// Package freedomkernel provides a Go client for the Freedom Kernel C ABI.
//
// Usage (CGO — requires the compiled shared library):
//
//	result, err := Verify(registry, action)
//	planResult, err := VerifyPlan(registry, actions)
//
// The library is loaded via CGO; build with:
//
//	CGO_CFLAGS="-I/path/to/freedom-kernel/include"
//	CGO_LDFLAGS="-L/path/to/freedom-kernel/target/release -lfreedom_kernel"
package freedomkernel

/*
#cgo CFLAGS: -I../../freedom-kernel/include
#include "freedom_kernel.h"
#include <string.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

// Verify verifies a single action against a registry using the C ABI.
func Verify(registry OwnershipRegistryWire, action ActionWire) (*VerificationResult, error) {
	input := VerifyInput{Registry: registry, Action: action}
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	inputC := C.CString(string(inputJSON))
	defer C.free(unsafe.Pointer(inputC))

	var outBuf [C.FREEDOM_KERNEL_MAX_OUTPUT]C.char
	rc := C.freedom_kernel_verify(inputC, C.size_t(len(inputJSON)), &outBuf[0], C.size_t(len(outBuf)))
	if rc < 0 {
		return nil, fmt.Errorf("C ABI error: %d", int(rc))
	}

	var result VerificationResult
	if err := json.Unmarshal([]byte(C.GoString(&outBuf[0])), &result); err != nil {
		return nil, fmt.Errorf("unmarshal result: %w", err)
	}
	return &result, nil
}

// VerifyPlan verifies a sequence of actions as a plan.
// Stops at the first blocked action.
func VerifyPlan(registry OwnershipRegistryWire, plan []ActionWire) (*PlanResult, error) {
	results := make([]VerificationResult, 0, len(plan))
	for i, action := range plan {
		r, err := Verify(registry, action)
		if err != nil {
			return nil, fmt.Errorf("action %d: %w", i, err)
		}
		results = append(results, *r)
		if !r.Permitted {
			idx := i
			return &PlanResult{AllPermitted: false, Results: results, BlockedAt: &idx}, nil
		}
	}
	return &PlanResult{AllPermitted: true, Results: results}, nil
}
