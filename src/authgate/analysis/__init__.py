"""
authgate.analysis — observation layer, not enforcement.

These modules inspect registry state and return signals.
They are NOT gates. Nothing here blocks an action.
The gate is authgate.kernel.verifier.FreedomVerifier.verify().
"""
