package service

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutingObserverOpenAIFailoverMetadata(t *testing.T) {
	t.Run("fills legacy zero values at an authoritative account failover branch", func(t *testing.T) {
		err := typedOpenAIFailover(
			&UpstreamFailoverError{StatusCode: 524},
			GatewayFailureScopeAccount,
			openAIUpstreamResponseFailureReason,
		)

		require.Equal(t, GatewayFailureStageInference, err.Stage)
		require.Equal(t, GatewayFailureScopeAccount, err.Scope)
		require.Equal(t, openAIUpstreamResponseFailureReason, err.Reason)
		require.Equal(t, NextAccountRetry, err.NextAccountAction)
	})

	t.Run("preserves explicit typed decisions", func(t *testing.T) {
		explicitReason := GatewayFailureReason("explicit_reason")
		err := typedOpenAIFailover(
			&UpstreamFailoverError{
				Stage:             GatewayFailureStageAccountAuth,
				Scope:             GatewayFailureScopeProvider,
				Reason:            explicitReason,
				NextAccountAction: NextAccountStop,
			},
			GatewayFailureScopeAccount,
			openAIUpstreamResponseFailureReason,
		)

		require.Equal(t, GatewayFailureStageAccountAuth, err.Stage)
		require.Equal(t, GatewayFailureScopeProvider, err.Scope)
		require.Equal(t, explicitReason, err.Reason)
		require.Equal(t, NextAccountStop, err.NextAccountAction)
	})

	t.Run("common upstream response producer emits complete typed facts", func(t *testing.T) {
		headers := http.Header{"X-Request-Id": []string{"req-524"}}
		err := newOpenAIUpstreamFailoverError(524, headers, []byte(`{"error":{"type":"upstream_error"}}`), "", false)

		require.Equal(t, GatewayFailureStageInference, err.Stage)
		require.Equal(t, GatewayFailureScopeAccount, err.Scope)
		require.Equal(t, openAIUpstreamResponseFailureReason, err.Reason)
		require.Equal(t, NextAccountRetry, err.NextAccountAction)
		require.Equal(t, "req-524", err.ResponseHeaders.Get("X-Request-Id"))
	})

	t.Run("account-specific body limit keeps its narrower reason", func(t *testing.T) {
		err := newOpenAIUpstreamFailoverError(
			http.StatusRequestEntityTooLarge,
			nil,
			[]byte(`{"error":{"message":"request exceeds this account limit"}}`),
			"request exceeds this account limit",
			true,
		)

		require.Equal(t, GatewayFailureStageInference, err.Stage)
		require.Equal(t, GatewayFailureScopeAccount, err.Scope)
		require.Equal(t, openAIRequestBodyTooLargeReason, err.Reason)
		require.Equal(t, NextAccountRetry, err.NextAccountAction)
		require.False(t, err.RetryableOnSameAccount)
	})
}
