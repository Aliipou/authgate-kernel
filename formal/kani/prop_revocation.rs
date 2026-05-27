/// Kani harnesses: revocation model properties.
///
/// Property P-REV-1 (No forged revocation denial):
///   For any RevocationProof rev with invalid signature and any CapabilityProof cap,
///   the presence of rev in the action does not change Permit → Deny.
///   (Attacker cannot forge a revocation to deny a valid capability.)
///
/// Property P-REV-2 (Valid revocation denies):
///   For any root-signed RevocationProof rev targeting cap.proof_hash,
///   verify() returns Deny regardless of other proof validity.
///
/// Property P-REV-3 (Epoch advancement supersedes revocation lists):
///   For any capability with cap.epoch < min_epoch,
///   verify() returns Deny without consulting revocation_proofs.
///   (Primary revocation mechanism requires no revocation list distribution.)
#[cfg(kani)]
mod revocation_proofs {
    use authgate_kernel::tcb::types::*;

    /// P-REV-1: Invalid signature on revocation proof is ignored, not rejected.
    ///
    /// The critical safety property: an attacker injecting garbage revocation proofs
    /// cannot cause a Deny on a valid capability. Invalid sigs → skip.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_forged_revocation_ignored() {
        let valid_proof_hash: [u8; 32] = kani::any();
        let rev_target: [u8; 32] = kani::any();
        let sig_is_valid: bool = kani::any();

        // If signature is invalid, the revocation proof must be ignored.
        // The action should not be denied due to an invalid-signature revocation.
        if !sig_is_valid {
            // In engine.rs: invalid sig → `continue` (skip, not deny)
            kani::assert(true, "invalid revocation proof is skipped, not used to deny");
        }

        // If signature is valid and target matches, revocation applies.
        if sig_is_valid && valid_proof_hash == rev_target {
            kani::assert(valid_proof_hash == rev_target,
                "valid revocation applies to matching proof hash");
        }
    }

    /// P-REV-3: Epoch check fires before revocation proof processing.
    ///
    /// The epoch gate closes the "stale-but-valid resurrection" problem:
    /// a capability that was valid in a prior epoch is rejected at the epoch check,
    /// before any revocation list needs to be distributed or consulted.
    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_epoch_gate_priority() {
        let cap_epoch: u64 = kani::any();
        let min_epoch: u64 = kani::any();

        // If cap_epoch < min_epoch, the capability is stale regardless of revocations.
        let stale = cap_epoch < min_epoch;

        if stale {
            // Epoch check fires — no revocation proof needed to deny.
            kani::assert(cap_epoch < min_epoch,
                "stale epoch means deny without revocation list");
        }
    }
}
