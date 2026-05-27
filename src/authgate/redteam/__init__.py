"""
Red-team framework for freedom-kernel.

Provides structured adversarial attack classes for testing kernel resilience.
Each class implements an attack() method that attempts to bypass the verifier
and asserts the attempt fails (or documents the residual risk if it cannot be
detected by the kernel).

Usage:
    from authgate.redteam.scenarios import (
        ForgedDelegationAttack,
        AuthorityLaunderingAttack,
        RecursiveToolAbuseAttack,
    )
    attack = ForgedDelegationAttack(registry, verifier, actor=malicious_bot)
    result = attack.run()
    assert result.blocked, result.explanation
"""
