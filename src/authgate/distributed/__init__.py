"""
authgate.distributed — network coordination layer.

Merkle state, threshold revocations, gossip, partition policy.
Operates outside the in-process kernel boundary.
The kernel (authgate.kernel) has no network I/O.
"""
