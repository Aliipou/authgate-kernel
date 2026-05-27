use criterion::{black_box, criterion_group, criterion_main, Criterion};
use freedom_kernel::engine;
use freedom_kernel::wire::*;

fn make_registry(n_claims: usize) -> OwnershipRegistryWire {
    let machine = EntityWire { name: "bot".to_string(), kind: EntityKind::Machine };
    let human = EntityWire { name: "alice".to_string(), kind: EntityKind::Human };

    let claims = (0..n_claims).map(|i| ClaimWire {
        holder: machine.clone(),
        resource: ResourceWire {
            name: format!("resource-{}", i),
            rtype: "dataset".to_string(),
            scope: format!("/data/{}/", i),
            is_public: false,
            ifc_label: String::new(),
            trust_domain: None,
            delegation_depth: 0,
        },
        can_read: true,
        can_write: false,
        can_delegate: false,
        confidence: 1.0,
        expires_at: None,
        trust_domain: None,
        delegation_depth: 0,
    }).collect();

    OwnershipRegistryWire {
        claims,
        machine_owners: vec![MachineOwnerWire {
            machine,
            owner: human,
        }],
        trust_domains: vec![],
    }
}

fn make_read_action(resource_name: &str) -> ActionWire {
    ActionWire {
        action_id: "bench-read".to_string(),
        actor: EntityWire { name: "bot".to_string(), kind: EntityKind::Machine },
        description: String::new(),
        resources_read: vec![ResourceWire {
            name: resource_name.to_string(),
            rtype: "dataset".to_string(),
            scope: "/data/0/".to_string(),
            is_public: false,
            ifc_label: String::new(),
            trust_domain: None,
            delegation_depth: 0,
        }],
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
        trust_domain: None,
        delegation_depth: 0,
    }
}

fn bench_verify_permit(c: &mut Criterion) {
    let registry = make_registry(1);
    let action = make_read_action("resource-0");
    c.bench_function("verify_permit_1_claim", |b| {
        b.iter(|| engine::verify(black_box(&registry), black_box(&action)))
    });
}

fn bench_verify_block_flag(c: &mut Criterion) {
    let registry = make_registry(1);
    let mut action = make_read_action("resource-0");
    action.increases_machine_sovereignty = true;
    c.bench_function("verify_block_sovereignty_flag", |b| {
        b.iter(|| engine::verify(black_box(&registry), black_box(&action)))
    });
}

fn bench_verify_scale_claims(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_scale");
    for n in [10, 100, 1_000, 10_000] {
        let registry = make_registry(n);
        let action = make_read_action("resource-0");
        group.bench_with_input(
            criterion::BenchmarkId::from_parameter(n),
            &(registry, action),
            |b, (reg, act)| b.iter(|| engine::verify(black_box(reg), black_box(act))),
        );
    }
    group.finish();
}

fn bench_verify_no_claim(c: &mut Criterion) {
    let registry = make_registry(0);
    let action = make_read_action("nonexistent");
    c.bench_function("verify_block_no_claim", |b| {
        b.iter(|| engine::verify(black_box(&registry), black_box(&action)))
    });
}

criterion_group!(
    benches,
    bench_verify_permit,
    bench_verify_block_flag,
    bench_verify_scale_claims,
    bench_verify_no_claim,
);
criterion_main!(benches);
