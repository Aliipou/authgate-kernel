# Standardization path — MCP, not a new RFC

**Decision date:** 2026-08-20  
**Decision:** Standardize AuthGate’s external surface on **MCP** (Model Context
Protocol) tool mediation. Do **not** draft a new IETF/OIDF RFC for the core
authority profile until a second independent implementation exists and AuthZEN
engagement is active.

## Why MCP

1. **Already the agent–tool wire.** MCP is where tool calls happen; a PEP that
   does not sit on that path is invisible to the systems that need it.
2. **Avoid NIH on the envelope.** Identity/token plumbing is converging on OAuth
   2.1 resource servers, RFC 9728 metadata, RFC 8707 audience binding — MCP’s
   authorization track. Competing with that wastes credibility.
3. **Profile ≠ protocol.** AE-1…AE-10 is a *conformance profile for PEPs*. It can
   bind to MCP tool invocation without inventing a new transport.

## What we standardize where

| Concern | Surface |
|---|---|
| Tool call mediation (PEP) | MCP tool handler / gateway adapter (`plugin-mcp`, adapters) |
| Authority requirements | Authority Enforcement Profile (`contracts-spec/conformance`) |
| Cross-org authZ vocabulary | **AuthZEN** (OIDF) — participate; do not fork |
| Attenuation format | Prefer Macaroon/Biscuit *semantics*; lite HMAC caveats locally until a library is adopted wholesale |
| Normative liberty theory | Out of standardization path (FREEDOM_THEORY_POSITION.md) |

## Near-term engineering (B1)

1. MCP adapter that refuses tool dispatch without a signed, bound, unspent decision.
2. Quickstart: install → wrap one MCP tool → first DENY/ALLOW with audit line.
3. Map MCP tool annotations (`readOnly` / `destructive`) to obligations, not grants.

## Explicit non-goals

- A new “AuthGate Protocol” RFC.
- Replacing Cedar/OPA as the policy language inside enterprises.
- Claiming MCP standardization is complete because we have an adapter skeleton.

## Gate to revisit “maybe an RFC”

Only if: (a) two independent PEPs pass AE-1…AE-10, (b) AuthZEN WG signals appetite
for an agent-tool annex, and (c) ASSUMPTIONS.md no longer carries an unverified
signature axiom for the reference path.
