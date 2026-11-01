package service

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// The compatibility switch is stored inside the existing
// groups.codex_models_manifest_config JSONB column. Persistence must survive the
// normalization rebuild, otherwise an admin save silently drops the toggle.
func TestNormalizeCodexModelsManifestConfigPreservesLegacyToggle(t *testing.T) {
	got := normalizeCodexModelsManifestConfig(PlatformOpenAI, GroupCodexModelsManifestConfig{
		Enabled:                    true,
		AccountIDs:                 []int64{5, 5, 0, 9},
		FallbackToScheduler:        true,
		EmitLegacyBaseInstructions: true,
	})

	require.True(t, got.Enabled)
	require.True(t, got.FallbackToScheduler)
	require.True(t, got.EmitLegacyBaseInstructions, "the toggle must survive normalization")
	require.Equal(t, []int64{5, 9}, got.AccountIDs)
}

func TestNormalizeCodexModelsManifestConfigDefaultsLegacyToggleOff(t *testing.T) {
	got := normalizeCodexModelsManifestConfig(PlatformOpenAI, GroupCodexModelsManifestConfig{})
	require.False(t, got.EmitLegacyBaseInstructions, "existing groups must keep the previous behaviour")
}

// Non-OpenAI platforms keep a zero config so the toggle can never leak into a
// platform that has no Codex manifest.
func TestNormalizeCodexModelsManifestConfigDropsLegacyToggleOffPlatform(t *testing.T) {
	got := normalizeCodexModelsManifestConfig(PlatformComposite, GroupCodexModelsManifestConfig{
		EmitLegacyBaseInstructions: true,
	})
	require.Equal(t, GroupCodexModelsManifestConfig{}, got)
}

// The toggle is independent of the pinned-account switch: enabling it must work
// even when pinned discovery stays off.
func TestNormalizeCodexModelsManifestConfigLegacyToggleIndependentOfEnabled(t *testing.T) {
	got := normalizeCodexModelsManifestConfig(PlatformOpenAI, GroupCodexModelsManifestConfig{
		EmitLegacyBaseInstructions: true,
	})
	require.False(t, got.Enabled)
	require.True(t, got.EmitLegacyBaseInstructions)
	require.Empty(t, got.AccountIDs)
}

// Persisted groups written before this change must still decode: the field is
// additive and omitted from older payloads.
func TestGroupCodexModelsManifestConfigDecodesLegacyPayload(t *testing.T) {
	var got GroupCodexModelsManifestConfig
	require.NoError(t, json.Unmarshal([]byte(`{"enabled":true,"account_ids":[1],"fallback_to_scheduler":false}`), &got))
	require.True(t, got.Enabled)
	require.False(t, got.EmitLegacyBaseInstructions)

	encoded, err := json.Marshal(GroupCodexModelsManifestConfig{Enabled: true, EmitLegacyBaseInstructions: true})
	require.NoError(t, err)
	require.JSONEq(t, `{"enabled":true,"emit_legacy_base_instructions":true}`, string(encoded))
}
