/**
 * freedom_kernel.h — C interface to the Freedom Kernel
 *
 * Language-agnostic AGI permission gate.
 * Load the compiled .so/.dll and call these two functions from any language:
 * C, Go, Zig, Java (JNA), Node.js (ffi-napi), Rust (cdylib), etc.
 *
 * All decisions are signed with ed25519 (canonical bytes, not JSON) so callers
 * can verify kernel attestation without trusting the calling process.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum accepted input size (1 MiB). Inputs larger than this return -2. */
#define FREEDOM_KERNEL_MAX_INPUT  (1u << 20)

/** Recommended minimum output buffer size (64 KiB). */
#define FREEDOM_KERNEL_MAX_OUTPUT (1u << 16)

/**
 * Verify an action against a registry.
 *
 * Input JSON format:
 *   {
 *     "registry": {
 *       "claims": [
 *         {
 *           "holder":   {"name": "alice", "kind": "HUMAN"},
 *           "resource": {"name": "db", "rtype": "database_table"},
 *           "can_read": true, "can_write": true,
 *           "confidence": 1.0
 *         }
 *       ],
 *       "machine_owners": [
 *         {"machine": {"name": "bot", "kind": "MACHINE"},
 *          "owner":   {"name": "alice", "kind": "HUMAN"}}
 *       ]
 *     },
 *     "action": {
 *       "action_id": "op-001",
 *       "actor":     {"name": "bot", "kind": "MACHINE"},
 *       "resources_write": [{"name": "db", "rtype": "database_table"}]
 *     }
 *   }
 *
 * Output JSON:
 *   {
 *     "action_id": "op-001",
 *     "permitted": true,
 *     "violations": [],
 *     "warnings": [],
 *     "confidence": 1.0,
 *     "requires_human_arbitration": false,
 *     "manipulation_score": 0.0,
 *     "signature":   "<hex ed25519 signature over canonical bytes>",
 *     "signing_key": "<hex ed25519 verifying key>",
 *     "key_id":      "<versioned key identifier>",
 *     "timestamp":   1716123456,
 *     "nonce":       "<hex 16-byte random nonce>"
 *   }
 *
 * @param input_buf   Pointer to UTF-8 JSON bytes (NOT required to be NUL-terminated)
 * @param input_len   Byte length of input_buf (must be <= FREEDOM_KERNEL_MAX_INPUT)
 * @param output_buf  Caller-allocated buffer for the result JSON
 * @param output_len  Size of output_buf in bytes (recommend >= FREEDOM_KERNEL_MAX_OUTPUT)
 *
 * @return  > 0  bytes written to output_buf on success
 *           -1  parse / runtime error (output_buf contains {"error":"..."})
 *           -2  invalid input: null pointer, input_len > MAX, or invalid UTF-8
 */
int32_t freedom_kernel_verify(
    const char *input_buf,
    size_t      input_len,
    char       *output_buf,
    size_t      output_len
);

/**
 * Get the kernel instance's ed25519 verifying key (hex-encoded, 64 chars + NUL).
 *
 * Use this to verify result signatures out-of-band.
 *
 * @param out_buf  Caller-allocated buffer (must be >= 65 bytes)
 * @param out_len  Size of out_buf in bytes
 * @return 0 on success, -2 on null pointer
 */
int32_t freedom_kernel_pubkey(char *out_buf, size_t out_len);

#ifdef __cplusplus
}
#endif
