---------------------------- MODULE FreedomKernel ----------------------------
(*
 * TLA+ specification of the Freedom Kernel core invariants.
 *
 * This spec models the ownership graph and verifier to mechanically check:
 *   1. Authority monotonicity  — authority never increases flowing downward
 *   2. Confinement             — no agent accesses resources outside its scope
 *   3. Non-bypass              — sovereignty flags always block, unconditionally
 *   4. Attenuation             — delegation cannot exceed delegator's authority
 *   5. Machine sovereignty     — no machine accumulates unconstrained authority
 *
 * Status: research-grade specification with stated invariants.
 *
 * Honest scope:
 *   DOES model: authority graph, delegation lattice, sovereignty flag gate
 *   DOES NOT model: emergent plan behavior, state mutation during execution,
 *                   information flow, concurrent registry modification,
 *                   ownership semantics for non-rival digital goods
 *
 * The THEOREM declarations below are stated targets, not mechanically
 * verified results. Next step: run TLC on a 3-entity/3-resource instance.
 *
 * Reference: نظریه آزادی by Mohammad Ali Jannat Khah Doust, pp. 791-816
 * Formal semantics: see SEMANTICS.md
 *)

EXTENDS Naturals, FiniteSets, Sequences, TLC

CONSTANTS
    Humans,       \* Set of human entity identifiers
    Machines,     \* Set of machine entity identifiers
    Resources,    \* Set of resource identifiers
    MaxDepth      \* Maximum delegation depth

ASSUME MaxDepth \in Nat /\ MaxDepth > 0

Entities == Humans \cup Machines

(* ── Types ─────────────────────────────────────────────────────────────────── *)

\* A rights claim: holder has some access to resource at some confidence
Claim == [
    holder     : Entities,
    resource   : Resources,
    can_read   : BOOLEAN,
    can_write  : BOOLEAN,
    can_delegate: BOOLEAN,
    confidence : 0..100   \* confidence * 100 for integer arithmetic
]

\* An action an agent wants to take
ActionIR == [
    actor              : Entities,
    resources_read     : SUBSET Resources,
    resources_write    : SUBSET Resources,
    \* Sovereignty flags (any true = unconditional block)
    incr_sovereignty   : BOOLEAN,
    resists_correction : BOOLEAN,
    bypasses_verifier  : BOOLEAN,
    weakens_verifier   : BOOLEAN,
    disables_corrig    : BOOLEAN,
    coerces            : BOOLEAN,
    deceives           : BOOLEAN
]

(* ── State ─────────────────────────────────────────────────────────────────── *)

VARIABLES
    claims,         \* Set of Claim records (the ownership graph)
    machine_owners, \* Function: Machines -> Humans (partial)
    audit_log       \* Sequence of [action, permitted] records

TypeInvariant ==
    /\ claims \subseteq Claim
    /\ machine_owners \in [DOMAIN machine_owners -> Humans]
    /\ DOMAIN machine_owners \subseteq Machines
    /\ IsSeq(audit_log)

(* ── Helper predicates ─────────────────────────────────────────────────────── *)

\* Best confidence for an operation by holder on resource
BestConfidence(holder, resource, op) ==
    LET matching == {c \in claims :
            /\ c.holder = holder
            /\ c.resource = resource
            /\ CASE op = "read"     -> c.can_read
                 [] op = "write"    -> c.can_write
                 [] op = "delegate" -> c.can_delegate
                 [] OTHER           -> FALSE}
    IN IF matching = {} THEN 0
       ELSE CHOOSE conf \in {c.confidence : c \in matching} :
                \A c2 \in matching : conf >= c2.confidence

\* Can an entity act on a resource with an operation?
CanAct(holder, resource, op) ==
    BestConfidence(holder, resource, op) > 0

\* Does a machine have a registered human owner?
HasOwner(machine) ==
    machine \in DOMAIN machine_owners

(* ── Core verification predicate ───────────────────────────────────────────── *)

SovereigntyFlags(a) ==
    \/ a.incr_sovereignty
    \/ a.resists_correction
    \/ a.bypasses_verifier
    \/ a.weakens_verifier
    \/ a.disables_corrig
    \/ a.coerces
    \/ a.deceives

\* The kernel gate: returns TRUE iff action is permitted
Permitted(a) ==
    \* 1. Hard sovereignty flags — unconditional block
    /\ ~SovereigntyFlags(a)
    \* 2. A4: machine must have owner
    /\ (a.actor \in Machines => HasOwner(a.actor))
    \* 3. Resource read access
    /\ \A r \in a.resources_read  : CanAct(a.actor, r, "read")
    \* 4. Resource write access
    /\ \A r \in a.resources_write : CanAct(a.actor, r, "write")

(* ── Safety invariants ─────────────────────────────────────────────────────── *)

\* INV1: No sovereignty flag ever permits an action
SovereigntyAlwaysBlocks ==
    \A a \in ActionIR :
        SovereigntyFlags(a) => ~Permitted(a)

\* INV2: Ownerless machines are always blocked
OwnerlessMachineBlocked ==
    \A a \in ActionIR :
        (a.actor \in Machines /\ ~HasOwner(a.actor)) => ~Permitted(a)

\* INV3: Attenuation — delegation cannot exceed delegator's confidence
AttenuationHolds ==
    \A delegated \in claims :
    \A delegator \in claims :
        (delegated.holder # delegator.holder
         /\ delegated.resource = delegator.resource
         /\ delegator.can_delegate)
        =>
        delegated.confidence <= delegator.confidence

\* INV4: A machine cannot access a resource its owner has no claim on
MachineWithinOwnerScope ==
    \A a \in ActionIR :
    \A r \in (a.resources_read \cup a.resources_write) :
        (a.actor \in Machines /\ HasOwner(a.actor) /\ CanAct(a.actor, r, "read"))
        =>
        CanAct(machine_owners[a.actor], r, "read")

(* ── State transitions ─────────────────────────────────────────────────────── *)

Init ==
    /\ claims = {}
    /\ machine_owners = [m \in {} |-> {}]  \* empty function
    /\ audit_log = <<>>

AddClaim(c) ==
    /\ c \in Claim
    /\ claims' = claims \cup {c}
    /\ UNCHANGED <<machine_owners, audit_log>>

RegisterMachine(m, h) ==
    /\ m \in Machines
    /\ h \in Humans
    /\ machine_owners' = machine_owners @@ (m :> h)
    /\ UNCHANGED <<claims, audit_log>>

ExecuteAction(a) ==
    /\ a \in ActionIR
    /\ audit_log' = Append(audit_log, [action |-> a, permitted |-> Permitted(a)])
    /\ UNCHANGED <<claims, machine_owners>>

Next ==
    \/ \E c \in Claim      : AddClaim(c)
    \/ \E m \in Machines, h \in Humans : RegisterMachine(m, h)
    \/ \E a \in ActionIR   : ExecuteAction(a)

Spec ==
    /\ Init
    /\ [][Next]_<<claims, machine_owners, audit_log>>
    /\ WF_<<claims, machine_owners, audit_log>>(Next)

(* ── Properties to check ───────────────────────────────────────────────────── *)

THEOREM Spec => []TypeInvariant
THEOREM Spec => []SovereigntyAlwaysBlocks
THEOREM Spec => []OwnerlessMachineBlocked
THEOREM Spec => []AttenuationHolds

=============================================================================
