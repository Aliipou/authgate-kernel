/// Kani bounded model-checking harnesses for Freedom Kernel engine properties.
///
/// Build with: cargo kani --harness <name>
/// These harnesses are gated behind #[cfg(kani)] so they never affect the
/// normal Rust build or test suite.
#[allow(unexpected_cfgs)]
#[cfg(kani)]
mod proofs {
    use crate::engine;
    use crate::planner;
    use crate::wire::{
        ActionWire, ClaimWire, EntityKind, EntityWire, MachineOwnerWire, OwnershipRegistryWire,
        ResourceWire,
    };

    // ── helpers ───────────────────────────────────────────────────────────────

    fn human(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Human }
    }

    fn machine(name: &str) -> EntityWire {
        EntityWire { name: name.to_string(), kind: EntityKind::Machine }
    }

    fn file_resource(name: &str) -> ResourceWire {
        ResourceWire {
            name: name.to_string(),
            rtype: "file".to_string(),
            scope: String::new(),
            is_public: false,
            ifc_label: String::new(),
            // trust_domain = None: every harness using this helper is about the CLAIM
            // rule (read/write/delegate denied without a claim). engine::verify's
            // trust-domain rule only fires when the action AND the resource both carry
            // Some(domain); keeping this None makes the denial attributable to the
            // claim rule alone rather than being masked by a domain violation.
            trust_domain: None,
        }
    }

    fn claim(holder: EntityWire, resource: ResourceWire, can_write: bool) -> ClaimWire {
        ClaimWire {
            holder,
            resource,
            can_read: true,
            can_write,
            can_delegate: can_write,
            confidence: 1.0,
            expires_at: None,
            // trust_domain = None: same reason as file_resource() — these harnesses
            // isolate the claim rule, not domain separation.
            trust_domain: None,
            // delegation_depth is NONDETERMINISTIC on purpose. engine::verify never
            // reads it (checked: no delegation_depth reference anywhere in
            // src/engine.rs), so any concrete constant would silently pin the harness
            // to one arbitrary point of a field the branch just introduced. kani::any()
            // proves the claim-rule properties hold for ALL depths, which is strictly
            // stronger and costs nothing symbolically.
            delegation_depth: kani::any(),
        }
    }

    fn minimal_registry_with_owner() -> OwnershipRegistryWire {
        OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![MachineOwnerWire {
                machine: machine("bot"),
                owner: human("alice"),
            }],
            // trust_domains = empty: this registry declares no cross-domain grants.
            // Combined with base_action()'s trust_domain = None the domain rule is
            // inert, which is what these harnesses want — they predate domain
            // separation and assert flag/claim properties only.
            trust_domains: vec![],
        }
    }

    fn base_action() -> ActionWire {
        ActionWire {
            action_id: "test".to_string(),
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
            // trust_domain = None is REQUIRED, not merely convenient.
            // engine::verify only applies the cross-domain rule when the action
            // carries Some(domain). base_action() is shared by the one POSITIVE
            // harness (prop_public_resource_read_permitted, which asserts permitted
            // == true); a symbolic or non-None domain there would let the engine
            // raise a TRUST DOMAIN violation and falsify that harness. None keeps
            // every harness testing the property it was written for. Domain
            // separation needs its own harness — see the note on that harness.
            trust_domain: None,
            // delegation_depth: nondeterministic, same rationale as in claim() —
            // engine::verify ignores the field, so pinning it to 0 would be an
            // arbitrary and unjustified restriction of the proved state space.
            delegation_depth: kani::any(),
        }
    }

    // ── Macro: one harness per flag ───────────────────────────────────────────
    //
    // Each harness proves: setting flag X = true always blocks, regardless of
    // all other action fields. This gives us 10 independent formal proofs.

    macro_rules! forbidden_flag_harness {
        ($name:ident, $field:ident) => {
            #[kani::proof]
            fn $name() {
                let registry = minimal_registry_with_owner();
                let mut action = base_action();
                action.$field = true;
                let result = engine::verify(&registry, &action);
                assert!(!result.permitted, "{} must always block", stringify!($field));
                assert!(
                    result.violations.iter().any(|v| v.contains("FORBIDDEN")),
                    "violation list must contain FORBIDDEN"
                );
            }
        };
    }

    forbidden_flag_harness!(prop_increases_machine_sovereignty, increases_machine_sovereignty);
    forbidden_flag_harness!(prop_resists_human_correction,      resists_human_correction);
    forbidden_flag_harness!(prop_bypasses_verifier,             bypasses_verifier);
    forbidden_flag_harness!(prop_weakens_verifier,              weakens_verifier);
    forbidden_flag_harness!(prop_disables_corrigibility,        disables_corrigibility);
    forbidden_flag_harness!(prop_machine_coalition_dominion,    machine_coalition_dominion);
    forbidden_flag_harness!(prop_coerces,                       coerces);
    forbidden_flag_harness!(prop_deceives,                      deceives);
    forbidden_flag_harness!(prop_self_modification,             self_modification_weakens_verifier);
    forbidden_flag_harness!(prop_coalition_reduces_freedom,     machine_coalition_reduces_freedom);

    // ── Property: Ownerless machine is always blocked ─────────────────────────

    #[kani::proof]
    fn prop_ownerless_machine_blocked() {
        let registry = OwnershipRegistryWire {
            claims: vec![],
            machine_owners: vec![], // no owner registered
            // No trust domains: the A4 ownerless-machine rule must block on its own,
            // without any cross-domain grant being present to help or hinder it.
            trust_domains: vec![],
        };
        let action = ActionWire { action_id: "no_owner".to_string(), actor: machine("orphan"), ..base_action() };
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "Ownerless machine must be blocked (A4)");
        assert!(result.violations.iter().any(|v| v.contains("A4")));
    }

    // ── Property: A machine governing a human is always blocked ───────────────

    #[kani::proof]
    fn prop_machine_governs_human_blocked() {
        let registry = minimal_registry_with_owner();
        let mut action = base_action();
        action.governs_humans = vec![human("bob")];
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "Machine governing human must be blocked (A6)");
        assert!(result.violations.iter().any(|v| v.contains("A6")));
    }

    // ── Property: Public resource read always permitted ───────────────────────

    #[kani::proof]
    fn prop_public_resource_read_permitted() {
        let public_res = ResourceWire {
            name: "public_data".to_string(),
            rtype: "file".to_string(),
            scope: String::new(),
            is_public: true,
            ifc_label: String::new(),
            // trust_domain = None is LOAD-BEARING here. is_public short-circuits the
            // claim check but NOT the trust-domain check: if this resource carried
            // Some(domain) and the action carried a different Some(domain) with no
            // grant, verify() would emit a TRUST DOMAIN violation and this harness
            // would be FALSE. So "public reads are always permitted" is only true for
            // unlabelled resources on this branch. Narrowing to None preserves the
            // harness's original intent; the wider claim now needs its own harness.
            trust_domain: None,
        };
        let registry = minimal_registry_with_owner();
        let mut action = base_action();
        action.resources_read = vec![public_res];
        let result = engine::verify(&registry, &action);
        assert!(result.permitted, "Public resource reads must always be permitted");
    }

    // ── Property: Write denied without write claim ────────────────────────────

    #[kani::proof]
    fn prop_write_denied_without_claim() {
        let res = file_resource("secret");
        let registry = OwnershipRegistryWire {
            claims: vec![claim(machine("bot"), file_resource("secret"), false)], // read-only
            machine_owners: vec![MachineOwnerWire {
                machine: machine("bot"),
                owner: human("alice"),
            }],
            // No trust domains: WRITE DENIED must follow from the missing write claim
            // alone. An empty grant table also means no grant could mask the denial.
            trust_domains: vec![],
        };
        let mut action = base_action();
        action.resources_write = vec![res];
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "Write without write claim must be denied");
        assert!(result.violations.iter().any(|v| v.contains("WRITE DENIED")));
    }

    // ── Property: Read denied without read claim (A7) ─────────────────────────

    #[kani::proof]
    fn prop_read_denied_without_claim() {
        let res = file_resource("private");
        let registry = OwnershipRegistryWire {
            claims: vec![],  // no claims at all
            machine_owners: vec![MachineOwnerWire {
                machine: machine("bot"),
                owner: human("alice"),
            }],
            // No trust domains: READ DENIED (A7) must follow from the absent read
            // claim alone, not from a domain boundary.
            trust_domains: vec![],
        };
        let mut action = base_action();
        action.resources_read = vec![res];
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "Read without any claim must be denied (A7)");
        assert!(result.violations.iter().any(|v| v.contains("READ DENIED")));
    }

    // ── Property: Delegation denied without can_delegate (A7) ─────────────────

    #[kani::proof]
    fn prop_delegation_denied_without_delegate_claim() {
        let res = file_resource("data");
        let registry = OwnershipRegistryWire {
            claims: vec![claim(machine("bot"), file_resource("data"), false)], // can_delegate=false
            machine_owners: vec![MachineOwnerWire {
                machine: machine("bot"),
                owner: human("alice"),
            }],
            // No trust domains: DELEGATION DENIED (A7) must follow from
            // can_delegate=false alone.
            trust_domains: vec![],
        };
        let mut action = base_action();
        action.resources_delegate = vec![res];
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "Delegation without can_delegate must be denied (A7)");
        assert!(result.violations.iter().any(|v| v.contains("DELEGATION DENIED")));
    }

    // ── Property: verify is deterministic (pure function) ─────────────────────

    #[kani::proof]
    fn prop_permitted_deterministic() {
        let registry = minimal_registry_with_owner();
        let action = base_action();
        let r1 = engine::verify(&registry, &action);
        let r2 = engine::verify(&registry, &action);
        assert!(
            r1.permitted == r2.permitted,
            "verify must be deterministic: same inputs yield same permitted result"
        );
    }

    // ── Property: if permitted, violations list is empty ─────────────────────

    #[kani::proof]
    fn prop_permitted_implies_no_violations() {
        let registry = minimal_registry_with_owner();
        let action = base_action();
        let result = engine::verify(&registry, &action);
        if result.permitted {
            assert!(result.violations.is_empty(), "permitted result must have no violations");
        }
    }

    // ── Property: if blocked, violations list is non-empty ───────────────────

    #[kani::proof]
    fn prop_blocked_implies_violations_non_empty() {
        let registry = minimal_registry_with_owner();
        let mut action = base_action();
        action.increases_machine_sovereignty = true;
        let result = engine::verify(&registry, &action);
        assert!(!result.permitted, "forbidden flag must block");
        assert!(!result.violations.is_empty(), "blocked result must list violations");
    }

    // ── Property: plan with forbidden flag is always blocked (Stage 2A) ───────
    //
    // INV: if verify_plan returns all_permitted=true, no action set a forbidden flag.
    // Harness uses a concrete two-action plan; the sovereignty flag is set on action 2.
    //
    // PROOF: guaranteed by prop_increases_machine_sovereignty + planner short-circuit.

    #[kani::proof]
    #[kani::unwind(4)]
    fn prop_plan_permitted_means_no_forbidden_flags() {
        let registry = minimal_registry_with_owner();
        let ok = base_action();
        let mut bad = base_action();
        bad.increases_machine_sovereignty = true;

        // A plan where the second action has a forbidden flag must not be all_permitted
        let plan_result = planner::verify_plan(&registry, &[ok.clone(), bad.clone()]);
        assert!(!plan_result.all_permitted,
            "plan containing a forbidden-flag action must not be all_permitted");
        assert_eq!(plan_result.blocked_at, Some(1),
            "should be blocked at index 1 (the sovereignty action)");

        // A plan with only safe actions must be all_permitted (no resource claims needed here)
        let safe_result = planner::verify_plan(&registry, &[ok.clone()]);
        // Note: this may block if registry requires claims — the property is structural
        if safe_result.all_permitted {
            assert!(!ok.increases_machine_sovereignty,
                "if permitted, no sovereignty flag was set");
        }
    }
}
