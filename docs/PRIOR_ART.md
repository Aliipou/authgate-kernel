# Prior Art and Comparative Analysis: Capability Systems for Authority Control

**Version:** 1.0
**Scope:** Situates authgate-kernel within the academic and engineering lineage of
capability-based security systems. Identifies genuine intellectual debts,
documents differences precisely, and characterizes what is novel.
**Intended audience:** Security researchers, systems engineers, and academic
reviewers evaluating the project's theoretical grounding.

---

## 1. Historical Context

### The Confinement Problem (Lampson, 1974)

The foundational paper for this line of work is Butler Lampson's "A Note on
the Confinement Problem" (CACM 17(10), 1974). Lampson observed that even a
fully trusted service, when given a piece of data to process, might communicate
the content of that data to an unauthorized principal through covert channels —
timing variations, resource contention, storage patterns. He defined *confinement*
as the property that a service cannot leak information given to it in secret,
and showed that confinement is extremely difficult to achieve in practice against
a resourceful adversary exploiting storage and timing channels.

Lampson's framing is directly relevant to autonomous agents. An agent given
access to sensitive customer data in order to produce a report is in exactly
the position of Lampson's "service." The agent may have no formal instruction
to exfiltrate data; it may nonetheless encode that data in the byte count of
its API calls, the timing of its requests, or the structure of its outputs.
Freedom-kernel enforces authority boundaries on typed capability claims; it
explicitly documents that it does not address covert channels (see `THREAT_MODEL.md`,
Adversary D). This is not a gap unique to authgate-kernel — it is the same
limitation Lampson identified fifty years ago, and no deployed capability system
has fully solved it. Intellectual honesty requires acknowledging this boundary
clearly rather than claiming a strength that does not exist.

### Original Capability Concept (Dennis and Van Horn, 1966)

Jack Dennis and Earl Van Horn's "Programming Semantics for Multiprogrammed
Computations" (CACM 9(3), 1966) introduced the capability as a first-class
programming primitive: an unforgeable token that confers a specific right to
access a specific resource. The key insight was that the mere *possession* of
the token is sufficient for authorization — no ambient lookup table, no
subject-object matrix, no external reference monitor needed. Authority flows
with the token.

This paper established the two invariants that every subsequent capability
system has tried to uphold: *unforgeability* (capabilities cannot be fabricated
by unprivileged code) and *confinement-by-default* (an entity can only act on
resources for which it holds a capability). Freedom-kernel inherits both
invariants directly. The `RightsClaim` in authgate-kernel is a direct descendant
of Dennis and Van Horn's capability: a typed, scoped, unforgeable token whose
possession is necessary and sufficient for the holder to perform the claimed
operation.

### Why these problems are re-emerging with autonomous agents

The problems Lampson, Dennis, and Van Horn identified were largely solved —
or at least practically bounded — in the context of static, human-written
software running in well-understood operating systems. They are re-emerging
with autonomous agents for three reasons that were not present in 1974.

First, *agency*. A capability granted to a library subroutine is used when the
calling program calls it. A capability granted to an autonomous agent may be
used at any point in a long-running, multi-step plan, potentially in
combinations the grantor did not anticipate. The delegation chain is dynamic;
sub-agents may be spawned; capabilities may be passed between agents without
the original grantor's knowledge. This is a qualitatively different threat
model from static process isolation.

Second, *natural language as an attack surface*. The agent's "code" is, in part,
natural language in its context window. A prompt injection attack can cause
the agent to construct Action IR that requests capabilities the human operator
did not intend to grant. The capability system can only gate the *action*; it
cannot gate the *reasoning process* that produced the action.

Third, *opacity*. The internal state of a large language model is not inspectable
in the way that a process's memory is inspectable. The kernel cannot reason about
what the model "intends" — only about what it *does*. This reinforces the
correctness of the capability-based approach: the right place to enforce
constraints is at the action boundary, not in the model's internals.

---

## 2. Prior Systems

### 2.1 KeyKOS / EROS / Coyotos

KeyKOS (Bomberger et al., 1992), EROS (Shapiro et al., 1999), and its successor
Coyotos (Shapiro, 2005–2007) form the most direct line of object-capability
operating system design. In these systems, every object in the system — including
devices, memory regions, and process control blocks — is accessed exclusively
through capability tokens. There is no ambient authority: a process that does
not hold a capability to a resource cannot access it, period, regardless of
process credentials or security labels. Capabilities in EROS are unforgeable
kernel-managed values that cannot be constructed or guessed by userspace code.

The EROS "confinement" result is particularly relevant: a confined process
in EROS provably cannot exfiltrate information through object access patterns
because the kernel mediates every access and can audit the complete capability
usage graph. This is the structural property that authgate-kernel attempts to
approximate at the agent-action level rather than the OS syscall level.

Freedom-kernel differs from this lineage in three ways. First, it targets agent
runtimes rather than OS kernels. It makes no claims about process isolation,
memory protection, or device access — those are the OS's responsibility.
Freedom-kernel operates one layer up: on the *actions* that an agent submits,
not on the system calls those actions eventually generate. Second, delegation
in authgate-kernel is runtime-dynamic and claim-based. In EROS, capabilities
are passed between processes through explicit IPC; the capability graph is
determined by the program's execution. In authgate-kernel, the authority graph
is declared in an `OwnershipRegistry` and evaluated against submitted Action IR
at runtime. This makes authgate-kernel more tractable for declarative policy
configuration but less structurally complete than EROS's pure object-capability
model. Third, authgate-kernel is a Python/Rust polyglot. EROS is a kernel;
it runs in ring 0 and is written entirely in C. Freedom-kernel is designed for
adoption in the LLM application stack, where Python is the lingua franca and
Rust provides the verified TCB core.

What authgate-kernel takes from EROS: the unforgeable capability token as the
unit of authority; the confinement principle (an agent has only what's in its
registry); and the "no ambient authority" invariant encoded in axiom A4.

### 2.2 seL4

seL4 (Klein et al., 2009, SOSP; formal verification paper, CACM 53(6), 2010)
is a microkernel whose implementation has been formally verified to be correct
with respect to its formal specification, using the Isabelle/HOL proof assistant.
The verification covers functional correctness, memory safety, and (in subsequent
work) information flow security. The TCB of seL4 is approximately 10,000 lines
of C, mechanically proved correct against a ~600-line formal abstract
specification.

The similarities between seL4 and authgate-kernel are genuine but operate at
different levels. Both minimize their TCB: seL4's verified kernel is ~10K LOC
of C; authgate-kernel's TCB is ~200 LOC of pure Rust (`engine.rs`, `crypto.rs`,
`verifier.rs`, `wire.rs`, `capability.rs`). Both use capability-based IPC as
the authority model: in seL4, processes communicate through capability-bearing
endpoints; in authgate-kernel, agents submit Action IR through the verifier gate.
Both document incompleteness: seL4's proof covers the C implementation but not
the compiler, hardware, or assembly bootstrap; authgate-kernel documents its
incompleteness in `SEMANTICS.md`.

The differences are fundamental. seL4 is a general-purpose operating system
kernel; authgate-kernel is a policy runtime for agent actions. seL4 enforces
capability discipline at the system call boundary; authgate-kernel enforces it
at the Action IR boundary, which is above the OS. seL4's formal verification
achieves mechanical completeness — every execution path through the C code is
proved correct. Freedom-kernel's formal verification (19 Kani harnesses, 4
Lean4 theorems) covers the central invariants of `engine.rs` but is not
mechanically complete over the full implementation. Freedom-kernel documents
this gap explicitly rather than claiming seL4-grade verification. The Kani
harnesses prove the properties that matter most — attenuation monotonicity,
sovereignty flag unconditional blocking, no authority invention — without
claiming to cover every code path.

### 2.3 Capsicum (Watson et al., 2010)

Capsicum (Watson et al., "Capsicum: Practical Capabilities for UNIX,"
USENIX Security 2010) introduced capability-mode sandboxing for FreeBSD and
subsequently Linux. A process that enters capability mode loses access to the
global file descriptor namespace; it can only operate on file descriptors it
already holds or receives through capability-bearing IPC. Ambient authority —
the ability to open arbitrary files by name — is removed. Capsicum has been
merged into FreeBSD and has partial Linux support via libcap-ng.

The similarities are real and instructive. Both Capsicum and authgate-kernel
implement the "no ambient authority" principle: a Capsicum process cannot access
a resource it was not explicitly handed; a authgate-kernel agent cannot perform
an action on a resource it does not hold a claim for. Both are designed for
practical deployability alongside existing codebases, not as theoretical ideals.
Capsicum's design principle — that capability security should be adoptable with
minimal source changes — directly parallels authgate-kernel's design goal of
being adoptable in existing Python agent frameworks with a `verify()` call.

The differences operate at the system boundary. Capsicum operates at the
*syscall boundary*: it restricts what file descriptors and system calls a
process can use. Freedom-kernel operates at the *action-IR boundary*: it
restricts what structured operations an agent can submit. Capsicum is
process-level; authgate-kernel is agent-action-level. More substantively,
authgate-kernel adds concepts that have no Capsicum equivalent:
delegation chains (the path from human principal to agent to sub-agent,
with attenuation at each hop); machine/human distinction (axiom A6 — a machine
may not govern a human, which has no meaning at the syscall level);
and sovereignty flags (hard structural blocks that cannot be overridden
by any capability configuration). Capsicum has no notion of an ownership
graph rooted at a human principal; its trust root is the process that
enters capability mode, not an externally registered human owner.

### 2.4 E Language (Miller and Shapiro, 2003)

The E programming language (Miller, Morningstar, Frantz, 2003; Miller's
dissertation, 2006) was the first programming language designed from the ground
up around the object-capability model. In E, object references *are* capabilities;
passing a reference to an object is precisely the act of granting authority to
use that object. There is no way to obtain a reference except by receiving it
from someone who already has it. The language enforces the capability invariants
structurally: the type system prevents forgery, the scoping rules prevent ambient
authority, and the `defcap` construct enables explicit attenuation.

E's influence on authgate-kernel is deep and mostly acknowledged. The capability
algebra in `capability.rs` — a closed, finite enum with no open extension points
— reflects E's principle that the authority vocabulary must be statically
enumerable. E's attenuation model, in which a holder can grant a subset of their
authority to another party, is directly encoded in authgate-kernel's `delegate()`
constraint: `child_capability ⊆ parent_capability`, enforced atomically at
`add_claim()` time. E's key theorem, sometimes stated as "if you can't get it,
you can't harm it," expresses the confinement-by-capability property; freedom-
kernel enforces this structurally in `engine.rs` check [4] (capability claim
check).

Freedom-kernel extends E's model in directions that the language did not address
because E was designed for distributed object systems, not autonomous AI agents.
E has no concept of a human/machine ownership hierarchy; it treats all objects
symmetrically. E does not model delegation depth limits; authgate-kernel's 16-hop
depth cap prevents unbounded recursive delegation chains. E has no sovereignty
flags; authgate-kernel's 10 forbidden flags are hard structural blocks without
analogue in E's capability model. The polyglot Rust/Python implementation of
authgate-kernel also has no precedent in E, which is a standalone language.

### 2.5 WASM Component Model and WASI (Bytecode Alliance, 2019–present)

The WebAssembly Component Model and the WebAssembly System Interface (WASI,
Bytecode Alliance, 2019) implement capability-based module composition for
WebAssembly. A WASM component declares its required capabilities as explicit
imports; the host provides those capabilities at instantiation time. A component
cannot access file descriptors, network sockets, or other host resources unless
they were explicitly passed to it. This is a structural no-ambient-authority
property enforced by the WASM runtime.

The similarity to authgate-kernel is architectural: both treat capabilities as
explicit grants rather than ambient privileges. The "imports are capabilities"
design in WASI and the "claims are capabilities" design in authgate-kernel share
the same intellectual lineage (Dennis and Van Horn, 1966; E language).

The difference is temporal. WASM capabilities are *static import-time grants*:
they are fixed at the moment the component is instantiated and cannot change
during execution (WASI Preview 2 adds some runtime resource acquisition, but
the component's authority set remains bounded by what the host injected at
startup). Freedom-kernel capabilities are *dynamic runtime claims* with expiry
timestamps, revocability, and delegation chains that can be traversed and
re-evaluated on every action. Additionally, WASM has no model of human ownership,
no sovereignty flags, and no agent-specific capability kinds (SPAWN_AGENT,
SYSTEM_PROMPT_EDIT, MODEL_INVOKE, POLICY_MODIFY). WASM is a module execution
model; authgate-kernel is an authority governance runtime for autonomous agents.

### 2.6 SELinux and AppArmor

SELinux (Loscocco and Smalley, 2001; NSA, subsequently mainlined into Linux)
and AppArmor (Cowan et al., Immunix, 1998; subsequently in SUSE/Ubuntu/Debian)
are mandatory access control (MAC) systems that enforce security policy labels
on Linux processes. In SELinux, every object and subject has a label; the policy
defines which label transitions are permitted and which operations are allowed
between label pairs. AppArmor takes a path-based approach: policies are
specified per-executable as allowlists of file paths and network operations.

The differences from authgate-kernel are substantial. SELinux and AppArmor
operate at the process level: the unit of authority is the process (and its
label), not the individual action. Freedom-kernel operates at the agent-action
level: the unit of authority is a single structured operation submitted by an
identified actor. A process executing an agent framework has one SELinux label
for its entire lifetime; an agent using authgate-kernel has its capability claims
evaluated fresh on every action, including delegation chain reachability and
claim expiry checks.

More fundamentally, SELinux and AppArmor policies are static — they must be
written before deployment and loaded into the kernel. Freedom-kernel's
`OwnershipRegistry` can be updated (before `freeze()`) to reflect changing
delegation relationships, and individual claims carry expiry timestamps that
are re-evaluated at action time. SELinux has no concept of a delegation chain:
there is no mechanism to say "process A has delegated subset S of its authority
to process B, and S must be a subset of A's current authority." Freedom-kernel's
attenuation invariant is precisely this mechanism, evaluated at runtime against
the full ownership graph.

SELinux also captures nothing about the human-machine ownership relationship.
There is no SELinux type that expresses "this process is acting on behalf of
a specific human and must not exceed that human's resource scope." This is
axiom A5 in authgate-kernel's formal model, and it has no MAC equivalent.

### 2.7 Macaroons (Birgisson et al., 2014)

Macaroons ("Macaroons: Cookies with Contextual Caveats for Decentralized
Authorization in the Cloud," Birgisson et al., NDSS 2014) are bearer tokens
with an HMAC chained structure that supports attenuation: anyone holding a
macaroon can add caveats that restrict the token's authority, but cannot remove
existing caveats or expand authority. Macaroons support first-party caveats
(conditions checked by the target service) and third-party caveats (conditions
checked by a designated third-party service, with a proof-of-satisfaction
discharge token).

The similarity to authgate-kernel is the deepest of any system in this survey
after E. Macaroon caveats correspond to authgate-kernel attenuation: in both
systems, a holder can derive a narrower-authority token from a wider one, but
cannot derive a wider one from a narrower one. Both systems support delegation
chains: a macaroon can be attenuated and passed to a delegate; a authgate-kernel
claim can be delegated with `can_delegate: true` and the resulting child claim
is bounded by the parent. Both systems are designed for distributed, open
environments where the target service cannot be assumed to have prior knowledge
of the requesting principal.

Freedom-kernel adds several properties that macaroons do not address. First,
macaroons are anonymous bearer tokens: possession is authority, regardless of
who holds the token. Freedom-kernel claims are bound to named actor/resource
pairs and evaluated against a typed ownership graph. A stolen authgate-kernel
`RightsClaim` is usable only by the actor named in the claim, and only within
the delegation chain rooted at the registered human principal. Second, macaroons
have no notion of human-machine ownership. A macaroon can be held by a person
or a process; the token structure does not distinguish them. Freedom-kernel's
axiom A4 (every machine must have a registered human owner) and axiom A6 (no
machine may govern a human) have no macaroon equivalent. Third, macaroons do
not model information flow control or sovereignty flags. The 10 forbidden flags
in authgate-kernel's engine produce unconditional BLOCKED results regardless
of token possession; there is no macaroon mechanism that prevents a caveat-free
macaroon from being used for a catastrophic operation. Fourth, macaroon third-
party caveats support a form of distributed authorization that authgate-kernel
does not address — cross-runtime capability verification remains an open
problem (see Section 4).

---

## 3. What Is New in authgate-kernel

The preceding analysis identifies authgate-kernel's genuine intellectual debts
to prior work. This section characterizes what is new — not new in the sense
of being disconnected from prior art, but new in the sense of addressing a
problem space that prior systems were not designed for.

### 3.1 Human-machine ownership as a first-class invariant

No prior capability system models the human-machine ownership relationship as
a typed, formally enforceable property. In seL4, EROS, Capsicum, E, WASM, and
macaroons, the trust root is the executing process, the system administrator,
or the token issuer. The question "which specific human being owns this machine,
and does the machine's capability scope stay within that human's property scope?"
is not answered by any of these systems.

Freedom-kernel's axioms A4 (machine-human ownership), A5 (machine scope bounded
by owner's scope), and A6 (no machine governs human) encode this relationship
formally and enforce it at every capability evaluation. The practical motivation
is the autonomous agent deployment model: an AI agent is not a general-purpose
process — it is a specific machine acting on behalf of a specific human. The
accountability chain for the agent's actions must be traceable to a human
principal, not to a process label or a capability token. This is novel.

### 3.2 Sovereignty flags: hard structural blocks with no override path

Sovereignty flags are a discrete innovation with no direct prior art. In every
prior capability system, authority can flow through the system given the right
token or label. Even EROS, with its hard capability model, allows the root
authority to grant any capability to any process. Freedom-kernel's 10 forbidden
flags (GOVERNS_HUMAN, SELF_MODIFYING_POLICY, SPAWN_UNRESTRICTED, REGISTRY_MODIFY,
and others) produce unconditional BLOCKED results regardless of what claims an
agent holds. There is no token, no label, and no delegation chain that overrides
them. They are structural vetos embedded in the engine's check [1], which runs
before capability evaluation, before ownership checks, and before any
policy logic.

The design rationale is that certain invariants must be inviolable for the
system to be trustworthy: an AI agent must never govern a human; an agent must
never modify the policy governing itself; unrestricted agent spawning must be
blocked by default. These invariants must hold even if a human operator
accidentally misconfigures the registry. Sovereignty flags are the mechanism
that enforces this.

### 3.3 Agentic AI-specific capability taxonomy

The `CapabilityKind` enum in authgate-kernel includes vocabulary that has no
precedent in prior systems: `ModelInvoke`, `SpawnAgent`, `SystemPromptEdit`,
`PolicyModify`, `ToolInvoke`. These reflect the specific threat model of
autonomous AI agents, not general-purpose processes.

`SpawnAgent` addresses the recursive delegation threat: an agent that can
spawn sub-agents without authority checks can potentially bootstrap capability
sets that neither the parent nor child holds individually (see split-action
attack in `THREAT_MODEL.md`, Section 5). `SystemPromptEdit` addresses prompt
injection escalation: an agent that can modify system prompts can rewrite its
own constraints. `PolicyModify` is a `CapabilityRisk::Catastrophic` capability
that machines cannot hold regardless of registry configuration. These concepts
do not exist in operating system capability systems because operating systems
do not model agents, prompts, or model invocations.

### 3.4 Python/Rust polyglot design for ecosystem adoption

Freedom-kernel's TCB is implemented in pure, formally-checked Rust
(`engine.rs`, `crypto.rs`, `wire.rs`, `capability.rs`, `verifier.rs`) and
exposed to the Python ecosystem via PyO3 bindings. The Python layer mirrors
the Rust semantics and is used when the Rust extension is not compiled.

This design choice is not a formal novelty but is a practical requirement for
adoption. The AI agent ecosystem is primarily Python. A capability system that
requires developers to rewrite their agents in a capability-secure language
(as E would require) will not be adopted. Freedom-kernel is designed to be
integrated with a `verify()` call in an existing Python agent loop. The Rust
TCB ensures that the critical invariants cannot be violated by bugs in the
Python layer, because the Python layer calls into verified Rust code for all
authority decisions.

Prior systems chose between correctness (seL4, EROS — in C/assembler, no Python
path) and adoptability (macaroons — in Go, no formal verification). Freedom-kernel
attempts both by partitioning the implementation: Python for the API surface,
Rust for the authority logic.

### 3.5 Existing systems do not model the open-environment agent problem

Synthesizing the above: no prior capability system was designed to answer the
question "can this autonomous agent, acting in an open environment on behalf
of a specific human, perform this action on this resource at this moment given
this delegation chain and these expiry constraints, without exceeding that
human's property scope or violating any structural sovereignty constraint?"

EROS answers a version of this for OS objects, but not for human ownership,
not for dynamic delegation chains, not for agent-specific capability kinds,
and not for sovereignty flags. Capsicum answers it at the syscall boundary,
not the action IR boundary. Macaroons answer it for bearer tokens, not for
named actors with ownership graphs. SELinux answers it with static labels,
not dynamic claims with expiry. None of them model human principals as the
trust root in the way that authgate-kernel's axiom A4 requires.

This is the gap that authgate-kernel addresses: the specific enforcement problem
that arises when an LLM-backed autonomous agent acts in an open environment
on a human's behalf, and the human needs structural — not behavioral —
guarantees about what the agent can do.

---

## 4. Open Problems

This section characterizes research problems that authgate-kernel's architecture
surfaces but does not solve. These are not deficiencies specific to this project;
they are open problems in the field that any serious capability system for
autonomous agents must eventually address.

### 4.1 Semantic escape

Freedom-kernel verifies *structural* authority: does the actor hold a valid
claim for this capability on this resource? It does not verify *semantic*
intent: is this formally-valid action sequence part of a plan with harmful
emergent effect?

An agent that reads a file, transforms it, and writes the result to a permitted
output bucket may be performing legitimate analytics or exfiltrating a reformatted
copy of sensitive data. Both action sequences are structurally identical from
the kernel's perspective. The capability check passes for both; the kernel
cannot distinguish them.

This is related to Lampson's covert channel problem but at a higher level of
abstraction. The open question is: can a formal system specify and verify
properties about *sequences* of capability-correct actions that collectively
constitute a policy violation, without requiring semantic interpretation of
the action content? Information flow control (IFC) provides partial answers —
tags can track information provenance through the action sequence — but IFC
over LLM-generated action sequences with structured outputs is an unsolved
research problem.

### 4.2 Cross-runtime attestation

Freedom-kernel verifies capability claims within a single runtime instance.
When an agent delegates authority to a sub-agent running in a different process,
container, or even a different cloud provider's infrastructure, the question
arises: how does the receiving runtime verify that the delegation chain is
authentic and that the delegating runtime's authority state has not been
tampered with?

Macaroon third-party caveats provide a partial mechanism, but they rely on
the third-party service being available and trusted. Trusted Execution
Environments (Intel TDX, AMD SEV-SNP, ARM TrustZone) provide hardware-level
attestation that a specific code image is running in a known state, which could
anchor the trust root for cross-runtime delegation. But composing authgate-kernel's
authority graph semantics with hardware attestation in a way that provides
end-to-end verifiable delegation chains across heterogeneous runtimes is an open
engineering and research problem.

### 4.3 Byzantine delegation

Freedom-kernel's authority graph assumes that all nodes (registered principals
and machines) behave honestly with respect to the protocol — they may try to
exceed their authority, but they do not actively forge attestations from other
nodes or corrupt the registry state. The adversary model in `THREAT_MODEL.md`
does not cover Byzantine nodes: principals that actively impersonate other
principals, generate fraudulent delegation proofs, or collude to construct
capability laundering chains that individually appear valid.

In a distributed multi-agent system where different agents run on infrastructure
controlled by different parties, Byzantine behavior is a realistic threat.
Byzantine fault-tolerant consensus over the authority graph (e.g., a BFT-replicated
OwnershipRegistry) would address this, but introduces significant complexity and
latency. The interaction between BFT consensus, capability expiry semantics, and
real-time action verification has not been formally analyzed.

### 4.4 Temporal logic of capability sequences

Freedom-kernel evaluates each action independently: does the actor hold a valid
claim at this moment? It does not evaluate properties of action sequences:
does holding this sequence of actions imply an invariant violation that no
individual action violates?

Temporal logic specifications (e.g., LTL, CTL) can express properties like
"an agent that reads a high-confidentiality resource must not subsequently
write to a low-confidentiality resource" — a classic non-interference property.
Verifying such properties over authgate-kernel's action stream would require
a monitor that maintains state across actions and evaluates temporal predicates,
which is fundamentally different from the stateless, per-action evaluation in
`engine.rs`.

Integrating temporal capability logic with the stateless TCB design — without
moving the temporal state machine into the TCB (which would violate the TCB
minimality constraint) and without losing soundness guarantees — is an open
design problem. A promising direction is to treat the temporal monitor as an
out-of-TCB policy layer that can advise on sequences but whose failure cannot
produce a false `PERMITTED` verdict from the TCB.

---

## References

Dennis, J. B., and Van Horn, E. C. (1966). Programming semantics for multiprogrammed
computations. *Communications of the ACM*, 9(3), 143–155.

Lampson, B. W. (1974). A note on the confinement problem. *Communications of the
ACM*, 17(10), 613–615.

Bomberger, A. C., Frantz, W. S., Hardy, N., Landau, C. R., Shapiro, J. S., and
Landau, S. (1992). The KeyKOS nanokernel architecture. *Proceedings of the
USENIX Workshop on Micro-kernels and Other Kernel Architectures*.

Shapiro, J. S., Smith, J. M., and Farber, D. J. (1999). EROS: A fast capability
system. *Proceedings of the 17th ACM Symposium on Operating Systems Principles
(SOSP)*, 170–185.

Klein, G., Elphinstone, K., Heiser, G., Andronick, J., Cock, D., Derrin, P.,
Elkaduwe, D., Engelhardt, K., Kolanski, R., Norrish, M., Sewell, T., Tuch, H.,
and Winwood, S. (2009). seL4: Formal verification of an OS kernel. *Proceedings
of the 22nd ACM Symposium on Operating Systems Principles (SOSP)*, 207–220.

Watson, R. N. M., Anderson, J., Laurie, B., and Kennaway, K. (2010). Capsicum:
Practical capabilities for UNIX. *Proceedings of the 19th USENIX Security
Symposium*, 29–46.

Miller, M. S., Morningstar, C., and Frantz, B. (2003). Capability-based
financial instruments. In *Proceedings of the 4th International Conference
on Financial Cryptography (FC)*. (Note: the E language design is fully
described in Miller's 2006 Johns Hopkins dissertation, "Robust Composition:
Towards a Unified Approach to Access Control and Concurrency Control.")

Miller, M. S. (2006). *Robust Composition: Towards a Unified Approach to
Access Control and Concurrency Control*. Ph.D. dissertation, Johns Hopkins
University.

Birgisson, A., Politz, J. G., Erlingsson, Ú., Taly, A., Vrable, M., and
Lentczner, M. (2014). Macaroons: Cookies with contextual caveats for
decentralized authorization in the cloud. *Proceedings of the 2014 Network
and Distributed System Security Symposium (NDSS)*.

Cowan, C., Pu, C., Maier, D., Hinton, H., Walpole, J., Bakke, P., Beattie, S.,
Grier, A., Wagle, P., and Zhang, Q. (1998). StackGuard: Automatic adaptive
detection and prevention of buffer-overflow attacks. *Proceedings of the 7th
USENIX Security Symposium*. (AppArmor is in Cowan's subsequent Immunix work;
the primary implementation reference is the AppArmor Linux kernel documentation
and the paper: Cowan et al., AppArmor: A simpler alternative to SELinux,
*Linux Journal*, 2000.)

Loscocco, P., and Smalley, S. (2001). Integrating flexible support for security
policies into the Linux operating system. *Proceedings of the USENIX Annual
Technical Conference (FREENIX Track)*, 29–42.

Bytecode Alliance. (2022). WASI Preview 2 and the Component Model. Technical
specification. https://github.com/WebAssembly/component-model
