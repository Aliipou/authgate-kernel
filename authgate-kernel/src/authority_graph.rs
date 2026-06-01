//! Authority Graph Engine — delegation chain analysis and DAG validation.
//!
//! This module is NOT part of the TCB. It provides structural analysis of the
//! authority graph: cycle detection, depth analysis, reachability, and trust
//! domain boundary crossing detection.
//!
//! The kernel (`engine.rs`) enforces per-action invariants. This module
//! provides graph-level invariants over the full delegation structure.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::wire::OwnershipRegistryWire;

// ── Graph representation ───────────────────────────────────────────────────

/// A node in the authority graph: an agent identified by name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorityNode {
    pub name: String,
    pub is_machine: bool,
    pub trust_domain: Option<String>,
}

/// A directed edge: `from` delegated authority to `to` on `resource`.
#[derive(Debug, Clone)]
pub struct DelegationEdge {
    pub from: String,
    pub to: String,
    pub resource_name: String,
    pub resource_type: String,
    pub depth: u8,
}

/// The full authority delegation graph for a registry snapshot.
#[derive(Debug, Default)]
pub struct AuthorityGraph {
    pub nodes: HashMap<String, AuthorityNode>,
    pub edges: Vec<DelegationEdge>,
    /// machine → human owner (A4 invariant)
    pub ownership: HashMap<String, String>,
}

// ── Construction ───────────────────────────────────────────────────────────

impl AuthorityGraph {
    pub fn from_registry(registry: &OwnershipRegistryWire) -> Self {
        let mut graph = AuthorityGraph::default();

        // Register ownership edges
        for mo in &registry.machine_owners {
            graph.ownership.insert(
                mo.machine.name.clone(),
                mo.owner.name.clone(),
            );
            graph.nodes.insert(mo.machine.name.clone(), AuthorityNode {
                name: mo.machine.name.clone(),
                is_machine: true,
                trust_domain: None,
            });
            graph.nodes.insert(mo.owner.name.clone(), AuthorityNode {
                name: mo.owner.name.clone(),
                is_machine: false,
                trust_domain: None,
            });
        }

        // Register delegation edges from claims
        for claim in &registry.claims {
            graph.nodes.entry(claim.holder.name.clone()).or_insert_with(|| AuthorityNode {
                name: claim.holder.name.clone(),
                is_machine: matches!(claim.holder.kind, crate::wire::EntityKind::Machine),
                trust_domain: claim.trust_domain.clone(),
            });
            graph.edges.push(DelegationEdge {
                from: claim.holder.name.clone(),
                to: claim.resource.name.clone(),
                resource_name: claim.resource.name.clone(),
                resource_type: claim.resource.rtype.clone(),
                depth: claim.delegation_depth,
            });
        }

        graph
    }
}

// ── Analysis functions ─────────────────────────────────────────────────────

/// Check for cycles in the delegation graph using DFS.
/// Returns the cycle path if one is found.
pub fn detect_cycles(graph: &AuthorityGraph) -> Option<Vec<String>> {
    // Build adjacency list: who delegates to whom (agent → agent edges via shared resources)
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for mo in &graph.ownership {
        adj.entry(mo.1.clone()).or_default().push(mo.0.clone());
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut rec_stack: HashSet<String> = HashSet::new();
    let mut path: Vec<String> = Vec::new();

    fn dfs(
        node: &str,
        adj: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> bool {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = adj.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    if dfs(neighbor, adj, visited, rec_stack, path) {
                        return true;
                    }
                } else if rec_stack.contains(neighbor) {
                    path.push(neighbor.to_string());
                    return true;
                }
            }
        }
        rec_stack.remove(node);
        path.pop();
        false
    }

    for node in graph.nodes.keys() {
        if !visited.contains(node) {
            if dfs(node, &adj, &mut visited, &mut rec_stack, &mut path) {
                return Some(path);
            }
        }
    }
    None
}

/// Compute the maximum delegation depth from any root principal.
pub fn max_depth(graph: &AuthorityGraph) -> u8 {
    graph.edges.iter().map(|e| e.depth).max().unwrap_or(0)
}

/// Find all agents reachable from `start` via delegation chains (BFS).
pub fn reachable_from(graph: &AuthorityGraph, start: &str) -> HashSet<String> {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for (machine, owner) in &graph.ownership {
        adj.entry(owner.as_str()).or_default().push(machine.as_str());
    }

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(start);

    while let Some(node) = queue.pop_front() {
        if visited.insert(node.to_string()) {
            if let Some(neighbors) = adj.get(node) {
                for &neighbor in neighbors {
                    if !visited.contains(neighbor) {
                        queue.push_back(neighbor);
                    }
                }
            }
        }
    }
    visited
}

/// Validate that all machines in the registry have a registered human owner (A4).
/// Returns names of ownerless machines.
pub fn ownerless_machines(registry: &OwnershipRegistryWire) -> Vec<String> {
    let owned: HashSet<&str> = registry.machine_owners.iter()
        .map(|mo| mo.machine.name.as_str())
        .collect();

    let mut result = Vec::new();
    for claim in &registry.claims {
        if matches!(claim.holder.kind, crate::wire::EntityKind::Machine) {
            if !owned.contains(claim.holder.name.as_str()) {
                if !result.contains(&claim.holder.name) {
                    result.push(claim.holder.name.clone());
                }
            }
        }
    }
    result
}

/// Cross-domain delegation analysis.
/// Returns pairs (agent, resource) where the agent's trust domain differs from
/// the resource's trust domain without a corresponding cross-domain grant.
pub fn cross_domain_violations(registry: &OwnershipRegistryWire) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    for claim in &registry.claims {
        let actor_domain = &claim.trust_domain;
        let res_domain = &claim.resource.trust_domain;
        if let (Some(ad), Some(rd)) = (actor_domain, res_domain) {
            if ad != rd {
                // Check if a cross-domain grant exists
                let granted = registry.trust_domains.iter().any(|td| {
                    td.cross_domain_grants.iter().any(|g| {
                        &g.from_domain == ad && &g.to_domain == rd
                    })
                });
                if !granted {
                    violations.push((claim.holder.name.clone(), claim.resource.name.clone()));
                }
            }
        }
    }
    violations
}

/// Full graph validation report.
#[derive(Debug)]
pub struct GraphValidationReport {
    pub has_cycles: bool,
    pub cycle_path: Option<Vec<String>>,
    pub max_delegation_depth: u8,
    pub ownerless_machines: Vec<String>,
    pub cross_domain_violations: Vec<(String, String)>,
    pub total_nodes: usize,
    pub total_edges: usize,
}

impl GraphValidationReport {
    pub fn is_valid(&self) -> bool {
        !self.has_cycles
            && self.ownerless_machines.is_empty()
            && self.cross_domain_violations.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.is_valid() {
            format!(
                "VALID: {} nodes, {} edges, max_depth={}, no cycles, no violations",
                self.total_nodes, self.total_edges, self.max_delegation_depth
            )
        } else {
            let mut issues = Vec::new();
            if self.has_cycles {
                issues.push(format!("CYCLE: {:?}", self.cycle_path));
            }
            for m in &self.ownerless_machines {
                issues.push(format!("OWNERLESS: {}", m));
            }
            for (a, r) in &self.cross_domain_violations {
                issues.push(format!("CROSS_DOMAIN: {} -> {}", a, r));
            }
            format!("INVALID: {}", issues.join("; "))
        }
    }
}

pub fn validate(registry: &OwnershipRegistryWire) -> GraphValidationReport {
    let graph = AuthorityGraph::from_registry(registry);
    let cycle_path = detect_cycles(&graph);
    GraphValidationReport {
        has_cycles: cycle_path.is_some(),
        cycle_path,
        max_delegation_depth: max_depth(&graph),
        ownerless_machines: ownerless_machines(registry),
        cross_domain_violations: cross_domain_violations(registry),
        total_nodes: graph.nodes.len(),
        total_edges: graph.edges.len(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ClaimWire, EntityKind, EntityWire, MachineOwnerWire, OwnershipRegistryWire, ResourceWire};

    fn human(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Human }
    }
    fn machine(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Machine }
    }
    fn resource(name: &str) -> ResourceWire {
        ResourceWire {
            name: name.to_string(),
            rtype: "dataset".to_string(),
            scope: format!("/data/{}/", name),
            is_public: false,
            ifc_label: String::new(),
            trust_domain: None,
        }
    }
    fn claim(holder: EntityWire, res: ResourceWire) -> ClaimWire {
        ClaimWire {
            holder,
            resource: res,
            can_read: true,
            can_write: false,
            can_delegate: false,
            confidence: 1.0,
            expires_at: None,
            trust_domain: None,
            delegation_depth: 0,
        }
    }

    #[test]
    fn test_ownerless_detection() {
        let registry = OwnershipRegistryWire {
            claims: vec![claim(machine("orphan-bot"), resource("data"))],
            machine_owners: vec![],
            trust_domains: vec![],
        };
        let orphans = ownerless_machines(&registry);
        assert_eq!(orphans, vec!["orphan-bot"]);
    }

    #[test]
    fn test_valid_graph_no_orphans() {
        let registry = OwnershipRegistryWire {
            claims: vec![claim(machine("bot"), resource("data"))],
            machine_owners: vec![MachineOwnerWire {
                machine: machine("bot"),
                owner: human("alice"),
            }],
            trust_domains: vec![],
        };
        let report = validate(&registry);
        assert!(report.ownerless_machines.is_empty());
        assert!(!report.has_cycles);
        assert!(report.is_valid());
    }

    #[test]
    fn test_reachability() {
        let registry = OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![
                MachineOwnerWire { machine: machine("bot-a"), owner: human("alice") },
                MachineOwnerWire { machine: machine("bot-b"), owner: human("alice") },
            ],
            trust_domains: vec![],
        };
        let graph = AuthorityGraph::from_registry(&registry);
        let reachable = reachable_from(&graph, "alice");
        assert!(reachable.contains("bot-a"));
        assert!(reachable.contains("bot-b"));
    }
}
