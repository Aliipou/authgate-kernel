//! Freedom Kernel CLI
//!
//! Usage:
//!   echo '<json>' | fk verify
//!   fk verify-plan --registry reg.json --plan plan.json
//!   fk verify-goal-tree --registry reg.json --tree tree.json
//!
//! Exit codes:
//!   0 = permitted
//!   1 = blocked
//!   2 = input/parse error

use std::io::{self, Read};
use std::process;
use std::env;

mod types {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EntityWire {
        pub name: String,
        pub kind: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ResourceWire {
        pub name: String,
        pub rtype: String,
        #[serde(default)] pub scope: String,
        #[serde(default)] pub is_public: bool,
        #[serde(default)] pub ifc_label: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ClaimWire {
        pub holder: EntityWire,
        pub resource: ResourceWire,
        #[serde(default = "default_true")] pub can_read: bool,
        #[serde(default)] pub can_write: bool,
        #[serde(default)] pub can_delegate: bool,
        #[serde(default = "default_one")] pub confidence: f64,
        #[serde(default)] pub expires_at: Option<f64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MachineOwnerWire {
        pub machine: EntityWire,
        pub owner: EntityWire,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OwnershipRegistryWire {
        #[serde(default)] pub claims: Vec<ClaimWire>,
        #[serde(default)] pub machine_owners: Vec<MachineOwnerWire>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ActionWire {
        pub action_id: String,
        pub actor: EntityWire,
        #[serde(default)] pub resources_read: Vec<ResourceWire>,
        #[serde(default)] pub resources_write: Vec<ResourceWire>,
        #[serde(default)] pub resources_delegate: Vec<ResourceWire>,
        #[serde(default)] pub governs_humans: Vec<EntityWire>,
        #[serde(default)] pub argument: String,
        #[serde(default)] pub increases_machine_sovereignty: bool,
        #[serde(default)] pub resists_human_correction: bool,
        #[serde(default)] pub bypasses_verifier: bool,
        #[serde(default)] pub weakens_verifier: bool,
        #[serde(default)] pub disables_corrigibility: bool,
        #[serde(default)] pub machine_coalition_dominion: bool,
        #[serde(default)] pub coerces: bool,
        #[serde(default)] pub deceives: bool,
        #[serde(default)] pub self_modification_weakens_verifier: bool,
        #[serde(default)] pub machine_coalition_reduces_freedom: bool,
    }

    #[derive(Debug, Deserialize)]
    pub struct VerifyInput {
        pub registry: OwnershipRegistryWire,
        pub action: ActionWire,
    }

    #[derive(Debug, Deserialize)]
    pub struct VerifyPlanInput {
        pub registry: OwnershipRegistryWire,
        pub plan: Vec<ActionWire>,
    }

    fn default_true() -> bool { true }
    fn default_one() -> f64 { 1.0 }
}

mod verify {
    use super::types::*;

    const CONFIDENCE_WARN: f64 = 0.8;

    fn claim_valid(c: &ClaimWire) -> bool {
        c.confidence > 0.0 && c.expires_at.map_or(true, |t| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64()
                <= t
        })
    }

    fn can_act(registry: &OwnershipRegistryWire, actor: &str, resource: &ResourceWire, op: &str)
        -> (bool, f64, String)
    {
        if resource.is_public && op == "read" {
            return (true, 1.0, "public resource".into());
        }
        let candidates: Vec<&ClaimWire> = registry.claims.iter().filter(|c| {
            c.holder.name == actor
                && c.resource.name == resource.name
                && c.resource.rtype == resource.rtype
                && claim_valid(c)
                && match op {
                    "read"     => c.can_read,
                    "write"    => c.can_write,
                    "delegate" => c.can_delegate,
                    _          => false,
                }
        }).collect();

        if candidates.is_empty() {
            return (false, 0.0, format!(
                "{} holds no valid {} claim on {}:{}", actor, op, resource.rtype, resource.name
            ));
        }
        let best = candidates.iter().map(|c| c.confidence)
            .fold(f64::NEG_INFINITY, f64::max);
        (true, best, format!("claim confidence={:.2}", best))
    }

    pub struct VerifyOutput {
        pub permitted: bool,
        pub violations: Vec<String>,
        pub warnings: Vec<String>,
    }

    pub fn verify(registry: &OwnershipRegistryWire, action: &ActionWire) -> VerifyOutput {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        let flags: &[(bool, &str)] = &[
            (action.increases_machine_sovereignty, "increases machine sovereignty"),
            (action.resists_human_correction,      "resists human correction"),
            (action.bypasses_verifier,             "bypasses the Freedom Verifier"),
            (action.weakens_verifier,              "weakens the Freedom Verifier"),
            (action.disables_corrigibility,        "disables corrigibility"),
            (action.machine_coalition_dominion,    "machine coalition seeking dominion"),
            (action.coerces,                       "coerces another agent"),
            (action.deceives,                      "deceives another agent"),
            (action.self_modification_weakens_verifier, "self-modification weakens the verifier"),
            (action.machine_coalition_reduces_freedom,  "machine coalition reduces human freedom"),
        ];
        for (flag, label) in flags {
            if *flag { violations.push(format!("FORBIDDEN ({})", label)); }
        }

        let actor = &action.actor;
        if actor.kind == "MACHINE" {
            if !registry.machine_owners.iter().any(|mo| mo.machine.name == actor.name) {
                violations.push(format!("A4 violation: {} has no registered human owner", actor.name));
            }
            for h in &action.governs_humans {
                violations.push(format!("A6: {} cannot govern human {}", actor.name, h.name));
            }
        }

        for r in &action.resources_read {
            let (ok, conf, reason) = can_act(registry, &actor.name, r, "read");
            if !ok { violations.push(format!("READ DENIED on {}:{}: {}", r.rtype, r.name, reason)); }
            else if conf < CONFIDENCE_WARN {
                warnings.push(format!("READ on {}:{} contested (confidence={:.2})", r.rtype, r.name, conf));
            }
        }
        for r in &action.resources_write {
            let (ok, conf, reason) = can_act(registry, &actor.name, r, "write");
            if !ok { violations.push(format!("WRITE DENIED on {}:{}: {}", r.rtype, r.name, reason)); }
            else if conf < CONFIDENCE_WARN {
                warnings.push(format!("WRITE on {}:{} contested (confidence={:.2})", r.rtype, r.name, conf));
            }
        }
        for r in &action.resources_delegate {
            let (ok, _, reason) = can_act(registry, &actor.name, r, "delegate");
            if !ok { violations.push(format!("DELEGATION DENIED on {}:{}: {}", r.rtype, r.name, reason)); }
        }

        VerifyOutput { permitted: violations.is_empty(), violations, warnings }
    }
}

fn cmd_verify(json: &str) -> i32 {
    let input: types::VerifyInput = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => { eprintln!("parse error: {}", e); return 2; }
    };
    let out = verify::verify(&input.registry, &input.action);
    if out.permitted {
        println!("PERMITTED  {}", input.action.action_id);
    } else {
        println!("BLOCKED    {}", input.action.action_id);
        for v in &out.violations { println!("  VIOLATION: {}", v); }
    }
    for w in &out.warnings { println!("  WARNING: {}", w); }
    if out.permitted { 0 } else { 1 }
}

fn cmd_verify_plan(json: &str) -> i32 {
    let input: types::VerifyPlanInput = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => { eprintln!("parse error: {}", e); return 2; }
    };
    let mut all_ok = true;
    for (i, action) in input.plan.iter().enumerate() {
        let out = verify::verify(&input.registry, action);
        if !out.permitted {
            println!("BLOCKED    [{}] {}", i, action.action_id);
            for v in &out.violations { println!("  VIOLATION: {}", v); }
            all_ok = false;
            break;
        } else {
            println!("PERMITTED  [{}] {}", i, action.action_id);
        }
    }
    if all_ok { println!("PLAN: all {} actions permitted", input.plan.len()); 0 } else { 1 }
}

fn read_stdin() -> String {
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf).unwrap_or_default();
    buf
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    let code = match subcmd {
        "verify" => {
            let json = if args.len() > 2 {
                match read_file(&args[2]) { Ok(s) => s, Err(e) => { eprintln!("{}", e); process::exit(2); } }
            } else { read_stdin() };
            cmd_verify(&json)
        }
        "verify-plan" => {
            let json = if args.len() > 2 {
                match read_file(&args[2]) { Ok(s) => s, Err(e) => { eprintln!("{}", e); process::exit(2); } }
            } else { read_stdin() };
            cmd_verify_plan(&json)
        }
        _ => {
            println!("Freedom Kernel CLI");
            println!();
            println!("USAGE:");
            println!("  fk verify [file.json]          Verify a single action (stdin if omitted)");
            println!("  fk verify-plan [file.json]     Verify a plan (list of actions)");
            println!();
            println!("INPUT FORMAT for 'verify':     {{\"registry\":{{...}},\"action\":{{...}}}}");
            println!("INPUT FORMAT for 'verify-plan':{{\"registry\":{{...}},\"plan\":[...]}}");
            println!();
            println!("EXIT CODES:  0=permitted  1=blocked  2=error");
            0
        }
    };

    process::exit(code);
}
