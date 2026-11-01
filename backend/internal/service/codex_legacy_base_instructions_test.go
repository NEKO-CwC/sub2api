package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// codexManifestWithTemplate builds a minimal Codex models manifest entry. The
// template text intentionally carries leading/trailing whitespace and a newline
// so byte-identical copying is observable.
func codexManifestWithTemplate(slug, template string) map[string]any {
	return map[string]any{
		"slug":         slug,
		"display_name": slug,
		"context_window": 272000,
		"model_messages": map[string]any{
			"instructions_template": template,
		},
	}
}

func encodeCodexManifest(t *testing.T, models ...map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"models": models})
	require.NoError(t, err)
	return body
}


func TestEmitLegacyBaseInstructionsCopiesTemplateVerbatim(t *testing.T) {
	template := "  You are Codex, an agent based on GPT-6.\n\tTrailing space kept \n"
	body := encodeCodexManifest(t, codexManifestWithTemplate("gpt-6.1-sol", template))

	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.True(t, changed)

	models := decodeCodexManifestModels(t, completed)
	require.Len(t, models, 1)
	got, ok := models[0]["base_instructions"].(string)
	require.True(t, ok, "base_instructions must be a string")
	require.Equal(t, template, got, "template bytes must be copied verbatim")

	messages, ok := models[0]["model_messages"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, template, messages["instructions_template"])

	// Unrelated metadata must survive untouched.
	require.Equal(t, "gpt-6.1-sol", models[0]["slug"])
	require.EqualValues(t, 272000, models[0]["context_window"])
}

func TestEmitLegacyBaseInstructionsLeavesExistingValue(t *testing.T) {
	// Upstream already owns base_instructions and advertises no template: the
	// value must survive untouched and no prompt may be synthesized.
	body := encodeCodexManifest(t, map[string]any{
		"slug":              "gpt-6.1-sol",
		"display_name":      "gpt-6.1-sol",
		"base_instructions": "upstream owned value",
	})

	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.False(t, changed, "an existing value must not be rewritten")

	models := decodeCodexManifestModels(t, completed)
	require.Equal(t, "upstream owned value", models[0]["base_instructions"])
}

func TestEmitLegacyBaseInstructionsIsNoopWhenAlreadyEqual(t *testing.T) {
	model := codexManifestWithTemplate("gpt-6.1-sol", "same text")
	model["base_instructions"] = "same text"
	body := encodeCodexManifest(t, model)

	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, body, completed, "body must be returned unchanged")
}

func TestEmitLegacyBaseInstructionsRejectsConflict(t *testing.T) {
	model := codexManifestWithTemplate("gpt-6.1-sol", "template text")
	model["base_instructions"] = "different text"
	body := encodeCodexManifest(t, model)

	_, _, err := emitLegacyBaseInstructions(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "conflicting base_instructions")
}

func TestEmitLegacyBaseInstructionsNeverSynthesizesPrompt(t *testing.T) {
	body := encodeCodexManifest(t, map[string]any{
		"slug":           "legacy-only",
		"display_name":   "legacy-only",
		"context_window": 1000,
	})

	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.False(t, changed)

	models := decodeCodexManifestModels(t, completed)
	_, hasBase := models[0]["base_instructions"]
	require.False(t, hasBase, "a missing template must not produce a fabricated prompt")
}

func TestEmitLegacyBaseInstructionsIgnoresBlankTemplate(t *testing.T) {
	body := encodeCodexManifest(t, codexManifestWithTemplate("blank", "   "))

	// A whitespace-only template is copied as-is: it is a real (if empty) value.
	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.True(t, changed)

	models := decodeCodexManifestModels(t, completed)
	require.Equal(t, "   ", models[0]["base_instructions"])
}

func TestEmitLegacyBaseInstructionsHandlesAllEntries(t *testing.T) {
	body := encodeCodexManifest(t,
		codexManifestWithTemplate("gpt-6.1-sol", "sol template"),
		map[string]any{"slug": "no-template", "display_name": "no-template"},
		codexManifestWithTemplate("gpt-6.1-luna", "luna template"),
	)

	completed, changed, err := emitLegacyBaseInstructions(body)
	require.NoError(t, err)
	require.True(t, changed)

	models := decodeCodexManifestModels(t, completed)
	require.Len(t, models, 3)
	require.Equal(t, "sol template", models[0]["base_instructions"])
	_, hasMiddle := models[1]["base_instructions"]
	require.False(t, hasMiddle)
	require.Equal(t, "luna template", models[2]["base_instructions"])
}

func TestEmitLegacyBaseInstructionsRejectsNonStringTemplate(t *testing.T) {
	model := map[string]any{
		"slug": "broken",
		"model_messages": map[string]any{
			"instructions_template": 42,
		},
	}
	body := encodeCodexManifest(t, model)

	_, _, err := emitLegacyBaseInstructions(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "instructions_template")
}

func TestEmitLegacyBaseInstructionsHandlesInvalidJSON(t *testing.T) {
	_, _, err := emitLegacyBaseInstructions([]byte("not-json"))
	require.Error(t, err)

	completed, changed, err := emitLegacyBaseInstructions(nil)
	require.NoError(t, err)
	require.False(t, changed)
	require.Empty(t, completed)
}

func TestApplyCodexModelsManifestCompatibilityRespectsGroupToggle(t *testing.T) {
	template := "native template " + strings.Repeat("x", 32)
	body := encodeCodexManifest(t, codexManifestWithTemplate("gpt-6.1-sol", template))
	original := codexModelsManifestBodyETag(body)

	off := &Group{CodexModelsManifestConfig: GroupCodexModelsManifestConfig{}}
	manifest := &OpenAIModelsResponse{Body: append([]byte(nil), body...), ETag: original}
	require.NoError(t, (&OpenAIGatewayService{}).applyCodexModelsManifestCompatibility(off, manifest))
	require.Equal(t, body, manifest.Body, "a disabled toggle must not change the body")
	require.Equal(t, original, manifest.ETag)

	on := &Group{CodexModelsManifestConfig: GroupCodexModelsManifestConfig{EmitLegacyBaseInstructions: true}}
	manifest = &OpenAIModelsResponse{Body: append([]byte(nil), body...), ETag: original}
	require.NoError(t, (&OpenAIGatewayService{}).applyCodexModelsManifestCompatibility(on, manifest))
	require.NotEqual(t, original, manifest.ETag, "a changed body must get a fresh ETag")
	require.Equal(t, codexModelsManifestBodyETag(manifest.Body), manifest.ETag)

	models := decodeCodexManifestModels(t, manifest.Body)
	require.Equal(t, template, models[0]["base_instructions"])
}

func TestApplyCodexModelsManifestCompatibilitySkipsNotModified(t *testing.T) {
	on := &Group{CodexModelsManifestConfig: GroupCodexModelsManifestConfig{EmitLegacyBaseInstructions: true}}
	manifest := &OpenAIModelsResponse{NotModified: true, ETag: `"abc"`}
	require.NoError(t, (&OpenAIGatewayService{}).applyCodexModelsManifestCompatibility(on, manifest))
	require.True(t, manifest.NotModified)
	require.Nil(t, manifest.Body)
}

// The compat pass must not disturb every other field, so a manifest that already
// satisfies the toggle stays byte-identical and therefore keeps its ETag.
func TestApplyCodexModelsManifestCompatibilityIsIdempotent(t *testing.T) {
	on := &Group{CodexModelsManifestConfig: GroupCodexModelsManifestConfig{EmitLegacyBaseInstructions: true}}
	body := encodeCodexManifest(t, codexManifestWithTemplate("gpt-6.1-sol", "template"))

	first := &OpenAIModelsResponse{Body: append([]byte(nil), body...), ETag: codexModelsManifestBodyETag(body)}
	require.NoError(t, (&OpenAIGatewayService{}).applyCodexModelsManifestCompatibility(on, first))

	second := &OpenAIModelsResponse{Body: append([]byte(nil), first.Body...), ETag: first.ETag}
	require.NoError(t, (&OpenAIGatewayService{}).applyCodexModelsManifestCompatibility(on, second))
	require.Equal(t, first.Body, second.Body)
	require.Equal(t, first.ETag, second.ETag)
}
