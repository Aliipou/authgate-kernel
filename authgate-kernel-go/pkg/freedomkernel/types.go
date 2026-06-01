// Package freedomkernel provides Go types for the Freedom Kernel wire protocol.
package freedomkernel

// EntityWire mirrors wire.rs EntityWire
type EntityWire struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // "HUMAN" | "MACHINE"
}

// ResourceWire mirrors wire.rs ResourceWire
type ResourceWire struct {
	Name     string `json:"name"`
	Rtype    string `json:"rtype"`
	Scope    string `json:"scope,omitempty"`
	IsPublic bool   `json:"is_public,omitempty"`
	IfcLabel string `json:"ifc_label,omitempty"`
}

// ClaimWire mirrors wire.rs ClaimWire
type ClaimWire struct {
	Holder      EntityWire   `json:"holder"`
	Resource    ResourceWire `json:"resource"`
	CanRead     bool         `json:"can_read"`
	CanWrite    bool         `json:"can_write"`
	CanDelegate bool         `json:"can_delegate"`
	Confidence  float64      `json:"confidence"`
	ExpiresAt   *float64     `json:"expires_at,omitempty"`
}

// MachineOwnerWire mirrors wire.rs MachineOwnerWire
type MachineOwnerWire struct {
	Machine EntityWire `json:"machine"`
	Owner   EntityWire `json:"owner"`
}

// OwnershipRegistryWire mirrors wire.rs OwnershipRegistryWire
type OwnershipRegistryWire struct {
	Claims        []ClaimWire        `json:"claims"`
	MachineOwners []MachineOwnerWire `json:"machine_owners"`
}

// ActionWire mirrors wire.rs ActionWire
type ActionWire struct {
	ActionID                      string         `json:"action_id"`
	Actor                         EntityWire     `json:"actor"`
	Description                   string         `json:"description,omitempty"`
	ResourcesRead                 []ResourceWire `json:"resources_read,omitempty"`
	ResourcesWrite                []ResourceWire `json:"resources_write,omitempty"`
	ResourcesDelegate             []ResourceWire `json:"resources_delegate,omitempty"`
	GovernsHumans                 []EntityWire   `json:"governs_humans,omitempty"`
	Argument                      string         `json:"argument,omitempty"`
	IncreasesMachineSovereignty   bool           `json:"increases_machine_sovereignty,omitempty"`
	ResistsHumanCorrection        bool           `json:"resists_human_correction,omitempty"`
	BypassesVerifier              bool           `json:"bypasses_verifier,omitempty"`
	WeakensVerifier               bool           `json:"weakens_verifier,omitempty"`
	DisablesCorrigibility         bool           `json:"disables_corrigibility,omitempty"`
	MachineCoalitionDominion      bool           `json:"machine_coalition_dominion,omitempty"`
	Coerces                       bool           `json:"coerces,omitempty"`
	Deceives                      bool           `json:"deceives,omitempty"`
	SelfModificationWeakensVerifier bool         `json:"self_modification_weakens_verifier,omitempty"`
	MachineCoalitionReducesFreedom  bool         `json:"machine_coalition_reduces_freedom,omitempty"`
}

// VerificationResult mirrors wire.rs VerificationResultWire
type VerificationResult struct {
	ActionID                string   `json:"action_id"`
	Permitted               bool     `json:"permitted"`
	Violations              []string `json:"violations"`
	Warnings                []string `json:"warnings"`
	Confidence              float64  `json:"confidence"`
	RequiresHumanArbitration bool    `json:"requires_human_arbitration"`
	ManipulationScore       float64  `json:"manipulation_score"`
	Signature               *string  `json:"signature,omitempty"`
	SigningKey               *string  `json:"signing_key,omitempty"`
	KeyID                   *string  `json:"key_id,omitempty"`
	Timestamp               *uint64  `json:"timestamp,omitempty"`
	Nonce                   *string  `json:"nonce,omitempty"`
}

// VerifyInput is the input envelope for JSON-based verification
type VerifyInput struct {
	Registry OwnershipRegistryWire `json:"registry"`
	Action   ActionWire            `json:"action"`
}

// VerifyPlanInput is the input envelope for plan verification
type VerifyPlanInput struct {
	Registry OwnershipRegistryWire `json:"registry"`
	Plan     []ActionWire          `json:"plan"`
}

// PlanResult is the result of plan verification
type PlanResult struct {
	AllPermitted bool                 `json:"all_permitted"`
	Results      []VerificationResult `json:"results"`
	BlockedAt    *int                 `json:"blocked_at,omitempty"`
}
