"""
authgate.integrations — adapters that connect AuthGate to upstream deciders.

Each integration is a thin, decoupled seam. The only one today is `fdk`: the
boundary to the Freedom Decision Kernel, which answers the *prior* question
("is this action legitimate?") before AuthGate answers "can this actor execute
it?". The two products share a JSON contract (the PolicyDecision schema), not
code — see `authgate.integrations.fdk`.
"""
