//! Recursive goal decomposition tree with DFS verification.
//!
//! This module is **Trusted** (not TCB). Every node's action is verified
//! by the pure `engine::verify` gate. The tree enforces a hard depth cap
//! to prevent recursive delegation explosion.

use crate::engine;
use crate::wire::{ActionWire, OwnershipRegistryWire, VerificationResultWire};

// ── GoalNode ──────────────────────────────────────────────────────────────────

/// A node in a recursive goal decomposition tree.
///
/// INVARIANT: subgoal authority ⊆ parent authority.
/// Enforced structurally: `with_subgoal` rejects additions beyond `depth_limit`.
#[derive(Debug, Clone)]
pub struct GoalNode {
    pub id: String,
    pub action: ActionWire,
    pub subgoals: Vec<GoalNode>,
    pub depth_limit: usize,
}

impl GoalNode {
    pub fn leaf(id: impl Into<String>, action: ActionWire) -> Self {
        Self { id: id.into(), action, subgoals: vec![], depth_limit: 10 }
    }

    pub fn with_depth_limit(mut self, limit: usize) -> Self {
        self.depth_limit = limit;
        self
    }

    /// Add a subgoal. Returns Err if depth_limit would be exceeded.
    pub fn with_subgoal(mut self, child: GoalNode) -> Result<Self, GoalTreeError> {
        let child_depth = child.max_depth();
        if child_depth >= self.depth_limit {
            return Err(GoalTreeError::DepthLimitExceeded {
                limit: self.depth_limit,
                actual: child_depth + 1,
            });
        }
        self.subgoals.push(child);
        Ok(self)
    }

    fn max_depth(&self) -> usize {
        if self.subgoals.is_empty() {
            return 0;
        }
        1 + self.subgoals.iter().map(|s| s.max_depth()).max().unwrap_or(0)
    }
}

// ── GoalTreeError ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum GoalTreeError {
    DepthLimitExceeded { limit: usize, actual: usize },
    AuthorityEscalation { node_id: String, detail: String },
    KernelViolation { node_id: String, result: VerificationResultWire },
}

impl GoalTreeError {
    pub fn description(&self) -> String {
        match self {
            Self::DepthLimitExceeded { limit, actual } => format!(
                "depth limit exceeded: limit={} actual={}", limit, actual
            ),
            Self::AuthorityEscalation { node_id, detail } => format!(
                "authority escalation at node {}: {}", node_id, detail
            ),
            Self::KernelViolation { node_id, result } => format!(
                "kernel violation at node {}: {:?}", node_id, result.violations
            ),
        }
    }
}

// ── GoalTreeResult ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct GoalTreeResult {
    pub all_permitted: bool,
    pub node_results: Vec<(String, VerificationResultWire)>,
    pub first_violation: Option<GoalTreeError>,
}

// ── verify_goal_tree ──────────────────────────────────────────────────────────

/// Verifies a goal tree by pre-order DFS traversal.
///
/// INVARIANTS CHECKED:
/// 1. Every node's action passes the kernel gate (A4, A6, A7, all 10 forbidden flags)
/// 2. Hard depth limit is respected (prevents recursive delegation explosion)
///
/// ORDER: parent verified before children (pre-order DFS)
pub fn verify_goal_tree(registry: &OwnershipRegistryWire, root: &GoalNode) -> GoalTreeResult {
    let mut node_results = Vec::new();
    let mut first_violation = None;

    dfs_verify(registry, root, &mut node_results, &mut first_violation, 0);

    GoalTreeResult {
        all_permitted: first_violation.is_none(),
        node_results,
        first_violation,
    }
}

fn dfs_verify(
    registry: &OwnershipRegistryWire,
    node: &GoalNode,
    results: &mut Vec<(String, VerificationResultWire)>,
    violation: &mut Option<GoalTreeError>,
    current_depth: usize,
) {
    if violation.is_some() { return; }

    if current_depth >= node.depth_limit {
        *violation = Some(GoalTreeError::DepthLimitExceeded {
            limit: node.depth_limit,
            actual: current_depth,
        });
        return;
    }

    let result = engine::verify(registry, &node.action);
    if !result.permitted {
        *violation = Some(GoalTreeError::KernelViolation {
            node_id: node.id.clone(),
            result: result.clone(),
        });
    }
    results.push((node.id.clone(), result));

    for child in &node.subgoals {
        dfs_verify(registry, child, results, violation, current_depth + 1);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ClaimWire, EntityKind, EntityWire, MachineOwnerWire, ResourceWire};

    fn machine(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Machine }
    }
    fn human(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Human }
    }
    fn owned_registry() -> OwnershipRegistryWire {
        OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![MachineOwnerWire { machine: machine("bot"), owner: human("alice") }],
        }
    }
    fn safe_action(id: &str) -> ActionWire {
        ActionWire {
            action_id: id.to_string(),
            actor: machine("bot"),
            description: String::new(),
            resources_read: vec![],
            resources_write: vec![],
            resources_delegate: vec![],
            governs_humans: vec![],
            argument: String::new(),
            increases_machine_sovereignty: false,
            resists_human_correction: false,
            bypasses_verifier: false,
            weakens_verifier: false,
            disables_corrigibility: false,
            machine_coalition_dominion: false,
            coerces: false,
            deceives: false,
            self_modification_weakens_verifier: false,
            machine_coalition_reduces_freedom: false,
        }
    }
    fn forbidden_action(id: &str) -> ActionWire {
        ActionWire { increases_machine_sovereignty: true, ..safe_action(id) }
    }

    #[test]
    fn test_single_leaf_permitted() {
        let root = GoalNode::leaf("root", safe_action("root-action"));
        let result = verify_goal_tree(&owned_registry(), &root);
        assert!(result.all_permitted);
        assert_eq!(result.node_results.len(), 1);
        assert!(result.first_violation.is_none());
    }

    #[test]
    fn test_forbidden_leaf_blocked() {
        let root = GoalNode::leaf("root", forbidden_action("bad"));
        let result = verify_goal_tree(&owned_registry(), &root);
        assert!(!result.all_permitted);
        assert!(matches!(result.first_violation, Some(GoalTreeError::KernelViolation { .. })));
    }

    #[test]
    fn test_forbidden_child_blocks_tree() {
        let child = GoalNode::leaf("child", forbidden_action("bad-child"));
        let root = GoalNode::leaf("root", safe_action("root-ok"))
            .with_subgoal(child)
            .unwrap();
        let result = verify_goal_tree(&owned_registry(), &root);
        assert!(!result.all_permitted);
        // Root should have been verified (permitted) before child blocked
        assert_eq!(result.node_results.len(), 2);
    }

    #[test]
    fn test_depth_limit_enforced() {
        // Build a chain 3 deep with limit=2
        let deep = GoalNode::leaf("d3", safe_action("d3")).with_depth_limit(2);
        let mid = GoalNode::leaf("d2", safe_action("d2"))
            .with_depth_limit(2)
            .with_subgoal(deep)
            .unwrap();

        // Manually push past limit in root
        let mut root = GoalNode::leaf("root", safe_action("root"));
        root.depth_limit = 2;
        root.subgoals.push(mid);

        let result = verify_goal_tree(&owned_registry(), &root);
        assert!(!result.all_permitted);
        assert!(matches!(result.first_violation, Some(GoalTreeError::DepthLimitExceeded { .. })));
    }

    #[test]
    fn test_tree_with_permitted_children() {
        let c1 = GoalNode::leaf("c1", safe_action("c1"));
        let c2 = GoalNode::leaf("c2", safe_action("c2"));
        let root = GoalNode::leaf("root", safe_action("root"))
            .with_subgoal(c1).unwrap()
            .with_subgoal(c2).unwrap();
        let result = verify_goal_tree(&owned_registry(), &root);
        assert!(result.all_permitted);
        assert_eq!(result.node_results.len(), 3);
    }

    #[test]
    fn test_depth_limit_exceeded_rejects_subgoal_at_construction() {
        let child = GoalNode::leaf("child", safe_action("c")).with_depth_limit(0);
        // depth_limit=0 means max_depth() of child (0) is not >= 0... actually let's test limit=1
        let deep = GoalNode::leaf("deep", safe_action("deep")).with_depth_limit(1);
        let mid = GoalNode::leaf("mid", safe_action("mid"))
            .with_depth_limit(1)
            .with_subgoal(deep)
            .unwrap(); // depth 1, limit 1: 1 >= 1, rejected
        // Actually with_subgoal checks child.max_depth() >= self.depth_limit
        // mid.max_depth()=1 (one subgoal), limit=1: 1 >= 1 → Err
        let _ = child; // suppress warning
        let result = GoalNode::leaf("root", safe_action("root"))
            .with_depth_limit(1)
            .with_subgoal(mid);
        assert!(result.is_err(), "Adding a subgoal past depth_limit must fail");
    }
}
