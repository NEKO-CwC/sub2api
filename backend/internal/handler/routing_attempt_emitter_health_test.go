package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRoutingAttemptEmitterHealthOmitsSensitiveConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &OpenAIGatewayHandler{routingAttemptEmitter: &RoutingAttemptEmitter{
		cfg: config.GatewayRoutingAttemptEmitterConfig{
			Enabled: true, PanelURL: "https://panel.invalid/private", Secret: "must-not-leak",
		},
		queue: make(chan routingAttemptChain, 3),
	}}
	h.routingAttemptEmitter.stats.sent.Add(2)
	h.routingAttemptEmitter.stats.dropped.Add(1)
	h.routingAttemptEmitter.stats.failures.Add(3)
	h.routingAttemptEmitter.recordFailure(routingAttemptFailureHTTPStatus, http.StatusServiceUnavailable)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/routing-attempt-emitter/health", nil)
	h.GetRoutingAttemptEmitterHealth(c)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.NotContains(t, recorder.Body.String(), "panel.invalid")
	require.NotContains(t, recorder.Body.String(), "must-not-leak")
	var body struct {
		Data RoutingAttemptEmitterStats `json:"data"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	require.True(t, body.Data.Enabled)
	require.Equal(t, uint64(2), body.Data.Sent)
	require.Equal(t, uint64(1), body.Data.Dropped)
	require.Equal(t, uint64(4), body.Data.Failures)
	require.Equal(t, 3, body.Data.QueueCapacity)
	require.NotEmpty(t, body.Data.LastFailureAt)
	require.Equal(t, "http_status", body.Data.LastFailureKind)
	require.Equal(t, http.StatusServiceUnavailable, body.Data.LastFailureStatusCode)
}

func TestRoutingAttemptEmitterHealthReportsDisabledWithoutRuntimeAllocation(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/routing-attempt-emitter/health", nil)
	(&OpenAIGatewayHandler{}).GetRoutingAttemptEmitterHealth(c)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"enabled":false`)
	require.Contains(t, recorder.Body.String(), `"queue_capacity":0`)
}
