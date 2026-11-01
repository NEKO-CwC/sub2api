package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

// The upstream shapes below reproduce the relay behaviour that made third-party
// Codex clients reject native metadata: the entry carries
// model_messages.instructions_template but no legacy base_instructions.
const codexLegacyToggleTemplate = "You are Codex, an agent based on GPT-6.\n\nKeep trailing space "

func codexLegacyToggleManifestBody() string {
	return `{"models":[{"slug":"gpt-6.1-sol","display_name":"gpt-6.1-sol",` +
		`"context_window":272000,"max_context_window":872000,` +
		`"shell_type":"shell_command","tool_mode":"code_mode_only",` +
		`"use_responses_lite":true,` +
		`"model_messages":{"instructions_template":` + codexLegacyToggleEncode(codexLegacyToggleTemplate) + `}}]}`
}

func codexLegacyToggleEncode(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func newCodexLegacyToggleHandler() (*OpenAIGatewayHandler, *codexModelsPinnedHTTPUpstream) {
	accounts := []service.Account{newPinnedCodexAccount(1, service.StatusActive, true, false)}
	upstream := &codexModelsPinnedHTTPUpstream{bodies: map[int64]string{
		1: codexLegacyToggleManifestBody(),
	}}
	return newPinnedCodexTestHandler(accounts, upstream, 3), upstream
}

func codexLegacyToggleGroup(toggle bool) *service.Group {
	return &service.Group{
		ID:       78,
		Platform: service.PlatformOpenAI,
		CodexModelsManifestConfig: service.GroupCodexModelsManifestConfig{
			Enabled:                    true,
			AccountIDs:                 []int64{1},
			EmitLegacyBaseInstructions: toggle,
		},
	}
}

func decodeCodexToggleManifest(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var envelope struct {
		Models []map[string]any `json:"models"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	return envelope.Models
}

func TestCodexModelsLegacyBaseInstructionsDisabledKeepsBody(t *testing.T) {
	handler, _ := newCodexLegacyToggleHandler()

	recorder := performPinnedCodexModelsRequest(t, handler, codexLegacyToggleGroup(false), "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	models := decodeCodexToggleManifest(t, recorder.Body.Bytes())
	require.Len(t, models, 1)
	_, hasLegacy := models[0]["base_instructions"]
	require.False(t, hasLegacy, "a default-off group must keep the upstream body shape")
}

func TestCodexModelsLegacyBaseInstructionsEnabledCompletesField(t *testing.T) {
	handler, _ := newCodexLegacyToggleHandler()

	recorder := performPinnedCodexModelsRequest(t, handler, codexLegacyToggleGroup(true), "")
	require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())

	models := decodeCodexToggleManifest(t, recorder.Body.Bytes())
	require.Len(t, models, 1)
	require.Equal(t, codexLegacyToggleTemplate, models[0]["base_instructions"],
		"the legacy field must copy instructions_template byte-for-byte")

	// No other metadata may change.
	require.Equal(t, "gpt-6.1-sol", models[0]["slug"])
	require.EqualValues(t, 272000, models[0]["context_window"])
	require.EqualValues(t, 872000, models[0]["max_context_window"])
	require.Equal(t, "shell_command", models[0]["shell_type"])
	require.Equal(t, "code_mode_only", models[0]["tool_mode"])
	// sub2api deliberately disables Responses Lite for gpt-6.1-sol on API-key
	// accounts (apiKeyCodexModelsWithoutResponsesLite); this predates the toggle
	// and must stay independent of it.
	require.Equal(t, false, models[0]["use_responses_lite"])

	messages, ok := models[0]["model_messages"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, codexLegacyToggleTemplate, messages["instructions_template"])
}

func TestCodexModelsLegacyBaseInstructionsETagCoversCompletedBody(t *testing.T) {
	handler, _ := newCodexLegacyToggleHandler()
	group := codexLegacyToggleGroup(true)

	first := performPinnedCodexModelsRequest(t, handler, group, "")
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	etag := first.Header().Get("ETag")
	require.NotEmpty(t, etag)

	// The returned ETag must describe the completed body, so replaying it yields 304.
	second := performPinnedCodexModelsRequest(t, handler, group, etag)
	require.Equal(t, http.StatusNotModified, second.Code, second.Body.String())
	require.Empty(t, second.Body.String())
}

func TestCodexModelsLegacyBaseInstructionsDisabledCanNever304OnCompletedBody(t *testing.T) {
	handler, _ := newCodexLegacyToggleHandler()

	enabled := performPinnedCodexModelsRequest(t, handler, codexLegacyToggleGroup(true), "")
	require.Equal(t, http.StatusOK, enabled.Code)
	enabledETag := enabled.Header().Get("ETag")

	// The same upstream bytes without the toggle produce a different body, so the
	// enabled ETag must not validate the disabled response.
	disabled := performPinnedCodexModelsRequest(t, handler, codexLegacyToggleGroup(false), enabledETag)
	require.Equal(t, http.StatusOK, disabled.Code, disabled.Body.String())
	require.NotEqual(t, enabledETag, disabled.Header().Get("ETag"))
}
