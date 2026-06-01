# SCOPE-AND-LIMITATIONS.md

> Paste the "Scope" block into the kernel README, above the architecture diagram. It buys more credibility with a skeptical security engineer than the entire theory does.

## Scope — what this is

AuthGate / freedom-kernel is a **capability-confinement and policy-decision substrate for agentic AI**. It answers exactly one question, deterministically and with mechanical proofs:

> **Does this actor hold valid, unrevoked, sufficiently-attenuated authority to perform this action on this resource right now?**

It enforces: explicit scoped authority, no ambient authority, cryptographic identity, signed/time-bounded/epoch-revocable capabilities, child ⊆ parent attenuation, no machine dominion over humans, a non-transferable human override, and tamper-evident audit. It bounds the **blast radius** of a misbehaving agent.

## NOT in scope — what this does **not** do

This is the honest boundary. Do not deploy as if these were covered:

1. **Inner alignment.** It does not make a model *want* the right thing, nor prevent deception, mesa-optimization, specification gaming, or reward hacking. It constrains what a misaligned agent can *reach*, not whether the agent is misaligned.
2. **Semantic judgment.** The kernel does not read natural language. It cannot decide whether an action is "coercive," "deceptive," or "ethical." Those are oracle inputs from outside the TCB; they may only deny or escalate, never grant.
3. **Manipulation / cognitive sovereignty.** A *permitted* action can still engineer a human's preferences (choice architecture, drip-framing, dependency). Consent predicates assume an un-manipulated chooser; against a superhuman persuader that assumption fails. **This is an open problem we declare, not solve** (route to human escalation).
4. **Compromised trust root.** If the root signing key is compromised, all guarantees collapse. Key management (HSM, multi-party signing) is a deployment concern, not a kernel feature.
5. **Diffuse / systemic / probabilistic harms.** Externalities, public goods, systemic risk, and harms with no identifiable victim-owner are not addressable by capability checks or ex-post "clarify ownership."
6. **Runtime/TCB compromise & side channels.** A compromised `engine.rs` process, or timing/cache/power side channels, are out of scope (deployment isolation + attestation required).
7. **Subprocess/sandbox escape (current gap).** The Python reference executor is bypassable via subprocess; only the Rust WASM/seccomp path closes this, and that path is incomplete on some platforms. See `formal/INCOMPLETENESS.md`.

## The line, in one sentence

> **Authorization is solved here. Alignment is not. Use this as the containment layer of a defense-in-depth stack — paired with interpretability, evaluations, control protocols, and human oversight — never as the whole answer.**

## How to pair it

| Layer | Concern | Tool |
|---|---|---|
| Containment / authority | who may do what | **this kernel** |
| Behavioral alignment | does the model want the right thing | RLHF / Constitutional AI / oversight |
| Transparency | what is the model doing | interpretability / evals |
| Manipulation defense | is the human's agency preserved | (open research) + human escalation |
| Key & runtime trust | is the substrate intact | HSM, attestation, isolation |
