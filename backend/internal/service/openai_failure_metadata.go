package service

const (
	openAIUpstreamResponseFailureReason  GatewayFailureReason = "openai_upstream_response_failure"
	openAIUpstreamTransportFailureReason GatewayFailureReason = "openai_upstream_transport_failure"
	openAIFirstOutputTimeoutReason       GatewayFailureReason = "openai_first_output_timeout"
	openAIStreamFailureReason            GatewayFailureReason = "openai_stream_failure"
	openAIRequestScopedFailureReason     GatewayFailureReason = "openai_request_scoped_failure"
	openAIUsageIntegrityFailureReason    GatewayFailureReason = "openai_usage_integrity_failure"
	openAIWSRateLimitFailureReason       GatewayFailureReason = "openai_ws_rate_limit_failure"
	grokUpstreamResponseFailureReason    GatewayFailureReason = "grok_upstream_response_failure"
)

// typedOpenAIFailover is called only at service branches that have already
// made an authoritative failover-scope decision. It never reads status codes,
// response bodies, or messages to classify an error; those remain diagnostics.
func typedOpenAIFailover(err *UpstreamFailoverError, scope GatewayFailureScope, reason GatewayFailureReason) *UpstreamFailoverError {
	if err == nil {
		return nil
	}
	if err.Stage == "" {
		err.Stage = GatewayFailureStageInference
	}
	if err.Scope == "" {
		err.Scope = scope
	}
	if err.Reason == "" {
		err.Reason = reason
	}
	if err.NextAccountAction == NextAccountLegacyRetry {
		err.NextAccountAction = NextAccountRetry
	}
	return err
}
