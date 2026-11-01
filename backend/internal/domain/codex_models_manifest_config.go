package domain

// GroupCodexModelsManifestConfig controls which accounts fetch the Codex
// models manifest for an OpenAI group. When enabled, the group's Codex
// /models requests bypass the scheduler and only use the pinned accounts.
type GroupCodexModelsManifestConfig struct {
	Enabled bool `json:"enabled"`
	// AccountIDs is the ordered list of pinned account IDs. Order decides
	// merge precedence for duplicate model slugs.
	AccountIDs []int64 `json:"account_ids,omitempty"`
	// FallbackToScheduler controls the behavior when no pinned account is
	// usable or all upstream fetches fail: fall back to the scheduler loop
	// (true) or return the upstream error / 503 (false, default).
	FallbackToScheduler bool `json:"fallback_to_scheduler,omitempty"`
	// EmitLegacyBaseInstructions mirrors model_messages.instructions_template
	// into the legacy top-level base_instructions field for clients that still
	// read it (for example Magpie). It is independent of Enabled and defaults to
	// false so existing groups keep their byte-identical manifest.
	EmitLegacyBaseInstructions bool `json:"emit_legacy_base_instructions,omitempty"`
}
