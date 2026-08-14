package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRoutingAttemptEmitterDisabledByDefault(t *testing.T) {
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{})
	require.Nil(t, e)
	e.Close()
	require.False(t, e.Submit(routingAttemptChain{Attempts: []routingAttemptRow{{AccountID: 1}}}))
	require.Equal(t, RoutingAttemptEmitterStats{}, e.Stats())
}

func TestRoutingAttemptEmitterDisabledPathAllocatesNothing(t *testing.T) {
	allocations := testing.AllocsPerRun(1000, func() {
		e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{})
		if e != nil || newRoutingAttemptRecorder(e, 5, "gpt-5", routingAttemptCorrelation{}) != nil || newRoutingAttemptWebSocketRecorder(e, 5, "gpt-5", routingAttemptCorrelation{}) != nil {
			panic("disabled emitter created runtime state")
		}
	})
	require.Zero(t, allocations)
}

func TestRoutingAttemptEmitterSendsBoundedSignedV2BatchForUntaggedRequests(t *testing.T) {
	type receivedRequest struct {
		payload map[string]any
		header  http.Header
	}
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- receivedRequest{payload: payload, header: r.Header.Clone()}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       2, BatchSize: 1, FlushIntervalMS: 10, RequestTimeoutMS: 500,
	})
	defer e.Close()
	recorder := newRoutingAttemptRecorder(e, 5, "gpt-\u2028-5", routingAttemptCorrelation{})
	recorder.record(10, nil, nil, time.Now())
	recorder.finish()
	select {
	case request := <-received:
		payload := request.payload
		var canonical bytes.Buffer
		encoder := json.NewEncoder(&canonical)
		encoder.SetEscapeHTML(false)
		require.NoError(t, encoder.Encode(payload))
		canonicalBytes := bytes.TrimSpace(canonical.Bytes())
		canonicalBytes = bytes.ReplaceAll(canonicalBytes, []byte(`\u2028`), []byte("\u2028"))
		canonicalBytes = bytes.ReplaceAll(canonicalBytes, []byte(`\u2029`), []byte("\u2029"))
		timestamp := request.header.Get("X-Dispatch-Timestamp")
		mac := hmac.New(sha256.New, []byte("test-secret"))
		mac.Write([]byte(timestamp + "."))
		mac.Write(canonicalBytes)
		require.Equal(t, "routing-dispatch-attempt-hook.v1", request.header.Get("X-Dispatch-Signature-Version"))
		require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), request.header.Get("X-Dispatch-Signature"))
		_, err := strconv.ParseInt(timestamp, 10, 64)
		require.NoError(t, err)
		observation, ok := payload["observation"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "routing-dispatch-attempt-observation.v2", observation["schema_version"])
		attempts, ok := observation["attempts"].([]any)
		require.True(t, ok)
		require.Len(t, attempts, 1)
		attempt, ok := attempts[0].(map[string]any)
		require.True(t, ok)
		require.NotContains(t, attempt, "api_key_id")
		require.NotContains(t, attempt, "correlation_sha256")
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for emitter batch")
	}
}

func TestRoutingAttemptEmitterSendsV3BatchForTaggedRequestWithoutRawNonce(t *testing.T) {
	nonce := strings.Repeat("A", routingCanaryNonceEncodedLength)
	received := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{routingCanaryGroupID},
		QueueSize:       2, BatchSize: 1, FlushIntervalMS: 10, RequestTimeoutMS: 500,
	})
	defer e.Close()
	recorder := newRoutingAttemptRecorder(e, routingCanaryGroupID, "gpt-5", routingAttemptCorrelation{
		APIKeyID:          routingCanaryAPIKeyID,
		CorrelationSHA256: "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95",
	})
	recorder.record(10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Unix(1, 0))
	recorder.record(11, &service.OpenAIForwardResult{FirstTokenMs: intPtr(100)}, nil, time.Unix(2, 0))
	recorder.finish()

	select {
	case body := <-received:
		require.NotContains(t, string(body), nonce)
		var payload struct {
			Observation struct {
				SchemaVersion string              `json:"schema_version"`
				Attempts      []routingAttemptRow `json:"attempts"`
			} `json:"observation"`
		}
		require.NoError(t, json.Unmarshal(body, &payload))
		require.Equal(t, routingAttemptObservationSchemaV3, payload.Observation.SchemaVersion)
		require.Len(t, payload.Observation.Attempts, 2)
		for _, attempt := range payload.Observation.Attempts {
			require.Equal(t, routingCanaryAPIKeyID, attempt.APIKeyID)
			require.NotNil(t, attempt.CorrelationSHA256)
			require.Equal(t, "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95", *attempt.CorrelationSHA256)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for tagged emitter batch")
	}
}

func TestRoutingAttemptEmitterSeparatesTaggedV3FromUntaggedV2Batches(t *testing.T) {
	var mu sync.Mutex
	schemas := make([]string, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Observation struct {
				SchemaVersion string `json:"schema_version"`
			} `json:"observation"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		schemas = append(schemas, payload.Observation.SchemaVersion)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{routingCanaryGroupID},
		QueueSize:       2, BatchSize: 2, FlushIntervalMS: 60_000, RequestTimeoutMS: 500,
	})
	defer e.Close()
	digest := "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95"
	e.sendGrouped([]routingAttemptChain{
		{
			GroupID: routingCanaryGroupID, Model: "gpt-5", ObservedAt: time.Unix(1, 0), IdempotencyKey: "untagged",
			Attempts: []routingAttemptRow{{LogicalRequestID: "untagged", Attempt: 1, AccountID: 10, Outcome: "success"}},
		},
		{
			GroupID: routingCanaryGroupID, Model: "gpt-5", ObservedAt: time.Unix(2, 0), IdempotencyKey: "tagged",
			Attempts: []routingAttemptRow{{APIKeyID: routingCanaryAPIKeyID, CorrelationSHA256: &digest, LogicalRequestID: "tagged", Attempt: 1, AccountID: 11, Outcome: "success"}},
		},
	})

	mu.Lock()
	require.ElementsMatch(t, []string{routingAttemptObservationSchemaV2, routingAttemptObservationSchemaV3}, schemas)
	mu.Unlock()
}

func TestRoutingAttemptEmitterDropsPartiallyTaggedChainFailClosed(t *testing.T) {
	e := newTestRoutingAttemptEmitterForGroup(routingCanaryGroupID)
	digest := "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95"
	e.sendGrouped([]routingAttemptChain{{
		GroupID: routingCanaryGroupID, Model: "gpt-5", ObservedAt: time.Unix(1, 0), IdempotencyKey: "mixed",
		Attempts: []routingAttemptRow{
			{LogicalRequestID: "mixed", Attempt: 1, AccountID: 10, Outcome: "failure"},
			{APIKeyID: routingCanaryAPIKeyID, CorrelationSHA256: &digest, LogicalRequestID: "mixed", Attempt: 2, AccountID: 11, Outcome: "success"},
		},
	}})
	require.Equal(t, uint64(1), e.Stats().Dropped)
	require.Empty(t, e.queue)
}

func TestConsumeRoutingAttemptCorrelationValidatesScopeAndHashesNonce(t *testing.T) {
	nonce := strings.Repeat("A", routingCanaryNonceEncodedLength)
	groupID := routingCanaryGroupID
	request := httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
	request.Header.Set(routingCanaryCorrelationHeader, nonce)

	correlation, status, err := consumeRoutingAttemptCorrelation(request, &service.APIKey{
		ID:      routingCanaryAPIKeyID,
		GroupID: &groupID,
	})

	require.NoError(t, err)
	require.Zero(t, status)
	require.Equal(t, routingCanaryAPIKeyID, correlation.APIKeyID)
	require.Equal(t, "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95", correlation.CorrelationSHA256)
	require.Empty(t, request.Header.Values(routingCanaryCorrelationHeader))
}

func TestConsumeRoutingAttemptCorrelationRejectsMalformedOrUnauthorizedValues(t *testing.T) {
	validNonce := strings.Repeat("A", routingCanaryNonceEncodedLength)
	validGroupID := routingCanaryGroupID
	wrongGroupID := int64(31)
	tests := []struct {
		name       string
		values     []string
		apiKey     *service.APIKey
		wantStatus int
	}{
		{name: "duplicate", values: []string{validNonce, validNonce}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "comma combined", values: []string{validNonce + "," + validNonce}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "short", values: []string{validNonce[:len(validNonce)-1]}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "long", values: []string{validNonce + "A"}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "invalid alphabet", values: []string{strings.Repeat("A", routingCanaryNonceEncodedLength-1) + "+"}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "leading whitespace", values: []string{" " + validNonce[:len(validNonce)-1]}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "control character", values: []string{validNonce[:len(validNonce)-1] + "\n"}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "non canonical trailing bits", values: []string{strings.Repeat("A", routingCanaryNonceEncodedLength-1) + "B"}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &validGroupID}, wantStatus: http.StatusBadRequest},
		{name: "wrong key", values: []string{validNonce}, apiKey: &service.APIKey{ID: 104, GroupID: &validGroupID}, wantStatus: http.StatusForbidden},
		{name: "wrong group", values: []string{validNonce}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID, GroupID: &wrongGroupID}, wantStatus: http.StatusForbidden},
		{name: "nil group", values: []string{validNonce}, apiKey: &service.APIKey{ID: routingCanaryAPIKeyID}, wantStatus: http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
			request.Header[routingCanaryCorrelationHeader] = append([]string(nil), test.values...)

			correlation, status, err := consumeRoutingAttemptCorrelation(request, test.apiKey)

			require.Error(t, err)
			require.Equal(t, test.wantStatus, status)
			require.Equal(t, routingAttemptCorrelation{}, correlation)
			require.Empty(t, request.Header.Values(routingCanaryCorrelationHeader))
			for _, value := range test.values {
				require.NotContains(t, err.Error(), value)
			}
		})
	}
}

func TestConsumeRoutingAttemptCorrelationLeavesUntaggedRequestCompatible(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/openai/v1/responses", nil)
	correlation, status, err := consumeRoutingAttemptCorrelation(request, nil)
	require.NoError(t, err)
	require.Zero(t, status)
	require.Equal(t, routingAttemptCorrelation{}, correlation)
}

func TestRoutingAttemptRecorderPropagatesCorrelationToEveryRetryWithoutRawNonce(t *testing.T) {
	nonce := strings.Repeat("A", routingCanaryNonceEncodedLength)
	correlation := routingAttemptCorrelation{
		APIKeyID:          routingCanaryAPIKeyID,
		CorrelationSHA256: "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95",
	}
	recorder := newRoutingAttemptRecorder(newTestRoutingAttemptEmitterForGroup(routingCanaryGroupID), routingCanaryGroupID, "gpt-5", correlation)
	recorder.record(10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Unix(1, 0))
	recorder.record(11, &service.OpenAIForwardResult{FirstTokenMs: intPtr(200)}, nil, time.Unix(2, 0))

	require.Len(t, recorder.attempts, 2)
	for _, attempt := range recorder.attempts {
		require.Equal(t, routingCanaryAPIKeyID, attempt.APIKeyID)
		require.NotNil(t, attempt.CorrelationSHA256)
		require.Equal(t, correlation.CorrelationSHA256, *attempt.CorrelationSHA256)
	}
	serialized, err := json.Marshal(recorder.attempts)
	require.NoError(t, err)
	require.NotContains(t, string(serialized), nonce)
}

func TestRoutingAttemptWebSocketRecorderPropagatesCorrelationAcrossTurns(t *testing.T) {
	emitter := newTestRoutingAttemptEmitterForGroup(routingCanaryGroupID)
	correlation := routingAttemptCorrelation{
		APIKeyID:          routingCanaryAPIKeyID,
		CorrelationSHA256: "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95",
	}
	recorder := newRoutingAttemptWebSocketRecorder(emitter, routingCanaryGroupID, "gpt-5", correlation)
	recorder.record(1, 10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Unix(1, 0))
	recorder.record(1, 11, &service.OpenAIForwardResult{OpenAIWSMode: true, UpstreamTerminalEvent: "response.completed"}, nil, time.Unix(2, 0))
	recorder.record(2, 12, &service.OpenAIForwardResult{OpenAIWSMode: true, UpstreamTerminalEvent: "response.completed"}, nil, time.Unix(3, 0))

	require.Len(t, emitter.queue, 2)
	for range 2 {
		chain := <-emitter.queue
		require.NotEmpty(t, chain.Attempts)
		for _, attempt := range chain.Attempts {
			require.Equal(t, routingCanaryAPIKeyID, attempt.APIKeyID)
			require.NotNil(t, attempt.CorrelationSHA256)
			require.Equal(t, correlation.CorrelationSHA256, *attempt.CorrelationSHA256)
		}
	}
}

func TestRoutingAttemptRecorderCapturesGatewayFactsAndFinalMarker(t *testing.T) {
	emitter := newTestRoutingAttemptEmitter()
	recorder := newRoutingAttemptRecorder(emitter, 5, "gpt-5", routingAttemptCorrelation{})
	status := http.StatusBadGateway
	recorder.record(10, nil, &service.UpstreamFailoverError{StatusCode: status, Reason: service.GatewayFailureReason("provider_unavailable")}, time.Unix(1, 0))
	recorder.record(11, &service.OpenAIForwardResult{FirstTokenMs: intPtr(1200)}, nil, time.Unix(2, 0))
	require.Len(t, recorder.attempts, 2)
	require.Equal(t, "failure", recorder.attempts[0].Outcome)
	require.Equal(t, "provider_unavailable", recorder.attempts[0].ErrorClass)
	require.Equal(t, status, *recorder.attempts[0].StatusCode)
	require.False(t, recorder.attempts[0].IsFinal)
	require.False(t, recorder.attempts[1].IsFinal)
	recorder.finish()
	require.True(t, recorder.attempts[1].IsFinal)
}

func TestRoutingAttemptRecorderUsesWebSocketTerminalOutcome(t *testing.T) {
	recorder := newRoutingAttemptRecorder(newTestRoutingAttemptEmitter(), 5, "gpt-5", routingAttemptCorrelation{})
	recorder.record(10, &service.OpenAIForwardResult{
		OpenAIWSMode:          true,
		UpstreamTerminalEvent: "response.failed",
		FirstTokenMs:          intPtr(900),
	}, nil, time.Unix(1, 0))
	recorder.record(11, &service.OpenAIForwardResult{
		OpenAIWSMode:          true,
		UpstreamTerminalEvent: "response.completed",
	}, nil, time.Unix(2, 0))

	require.Equal(t, "failure", recorder.attempts[0].Outcome)
	require.Equal(t, "upstream_terminal_response_failed", recorder.attempts[0].ErrorClass)
	require.Nil(t, recorder.attempts[0].StatusCode)
	require.Equal(t, 900, *recorder.attempts[0].TTFTMs)
	require.Equal(t, "success", recorder.attempts[1].Outcome)
	require.Empty(t, recorder.attempts[1].ErrorClass)
}

func TestRoutingAttemptRecorderDoesNotCollapseReusedClientRequestID(t *testing.T) {
	emitter := newTestRoutingAttemptEmitter()
	first := newRoutingAttemptRecorder(emitter, 5, "gpt-5", routingAttemptCorrelation{})
	second := newRoutingAttemptRecorder(emitter, 5, "gpt-5", routingAttemptCorrelation{})
	require.NotEqual(t, first.logicalRequestID, second.logicalRequestID)
	require.LessOrEqual(t, len(first.logicalRequestID), 128)
	require.LessOrEqual(t, len(second.logicalRequestID), 128)
	require.NotEqual(t, first.idempotencyKey, second.idempotencyKey)
}

func TestRecordRoutingAttemptDiscardsCanceledInboundChain(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	requestContext, cancel := context.WithCancel(context.Background())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(requestContext)
	recorder := newRoutingAttemptRecorder(newTestRoutingAttemptEmitter(), 5, "gpt-5", routingAttemptCorrelation{})
	recorder.record(10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Now())
	cancel()

	recordRoutingAttemptIfClientPresent(
		c,
		recorder,
		11,
		nil,
		&service.UpstreamFailoverError{StatusCode: http.StatusBadGateway},
		time.Now(),
	)

	require.True(t, recorder.discarded)
	require.Empty(t, recorder.attempts)
}

func TestRecordRoutingWebSocketAttemptDiscardsCanceledInboundTurn(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	requestContext, cancel := context.WithCancel(context.Background())
	c.Request = httptest.NewRequest(http.MethodGet, "/v1/responses", nil).WithContext(requestContext)
	emitter := newTestRoutingAttemptEmitter()
	recorder := newRoutingAttemptWebSocketRecorder(emitter, 5, "gpt-5", routingAttemptCorrelation{})
	recorder.record(1, 10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Now())
	cancel()

	recordRoutingWebSocketAttemptIfClientPresent(c, recorder, 1, 11, nil, nil, time.Now())
	recorder.finish()

	require.Empty(t, recorder.turns)
	require.Empty(t, emitter.queue)
}

func TestRoutingAttemptRecorderDoesNotSubmitUngroupedRequest(t *testing.T) {
	e := newTestRoutingAttemptEmitter()
	recorder := newRoutingAttemptRecorder(e, 0, "gpt-5", routingAttemptCorrelation{})
	require.Nil(t, recorder)
	require.Empty(t, e.queue)
}

func TestRoutingAttemptRecorderRejectsGroupsOutsideAllowlistBeforeAllocation(t *testing.T) {
	e := newTestRoutingAttemptEmitter()

	require.Nil(t, newRoutingAttemptRecorder(e, 4, "gpt-5", routingAttemptCorrelation{}))
	require.Nil(t, newRoutingAttemptWebSocketRecorder(e, 4, "gpt-5", routingAttemptCorrelation{}))
	require.NotNil(t, newRoutingAttemptRecorder(e, 5, "gpt-5", routingAttemptCorrelation{}))
	require.NotNil(t, newRoutingAttemptWebSocketRecorder(e, 5, "gpt-5", routingAttemptCorrelation{}))
	require.Empty(t, e.queue)
}

func TestRoutingAttemptRecordersRejectTaggedCorrelationOutsideExactCanaryScope(t *testing.T) {
	digest := "e1b1b2d579954c11301a081b74115b84635228d1323d392be4c49789dacb0a95"
	tagged := routingAttemptCorrelation{APIKeyID: routingCanaryAPIKeyID, CorrelationSHA256: digest}
	wrongGroupEmitter := newTestRoutingAttemptEmitterForGroup(5)
	require.Nil(t, newRoutingAttemptRecorder(wrongGroupEmitter, 5, "gpt-5", tagged))
	require.Nil(t, newRoutingAttemptWebSocketRecorder(wrongGroupEmitter, 5, "gpt-5", tagged))

	canaryEmitter := newTestRoutingAttemptEmitterForGroup(routingCanaryGroupID)
	partial := routingAttemptCorrelation{APIKeyID: routingCanaryAPIKeyID}
	require.Nil(t, newRoutingAttemptRecorder(canaryEmitter, routingCanaryGroupID, "gpt-5", partial))
	require.Nil(t, newRoutingAttemptWebSocketRecorder(canaryEmitter, routingCanaryGroupID, "gpt-5", partial))
}

func TestRoutingAttemptEmitterRejectsMissingOrInvalidAllowlist(t *testing.T) {
	base := config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: "https://panel.example.test", Secret: "test-secret",
		Sub2APIInstanceID: 7, QueueSize: 2, BatchSize: 1,
	}

	require.Nil(t, NewRoutingAttemptEmitter(base))
	base.AllowedGroupIDs = []int64{0}
	require.Nil(t, NewRoutingAttemptEmitter(base))
	base.AllowedGroupIDs = []int64{5, 5}
	require.Nil(t, NewRoutingAttemptEmitter(base))
	base.AllowedGroupIDs = []int64{5}
	require.NotNil(t, NewRoutingAttemptEmitter(base))
}

func TestRoutingAttemptEmitterCloseIsBoundedByShutdownTimeout(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		select {
		case <-r.Context().Done():
		case <-releaseRequest:
		}
	}))
	defer func() {
		close(releaseRequest)
		server.Close()
	}()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 5_000,
		ShutdownTimeoutMS: 25,
	})
	require.True(t, e.Submit(routingAttemptChain{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "bounded-close",
		Attempts: []routingAttemptRow{{LogicalRequestID: "bounded-close", Attempt: 1, IsFinal: true, AccountID: 10, Outcome: "success"}},
	}))
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for emitter request")
	}
	started := time.Now()
	e.Close()
	require.Less(t, time.Since(started), 250*time.Millisecond)
	require.Equal(t, uint64(1), e.Stats().Failures)
}

func TestRoutingAttemptEmitterCloseDrainsEveryAcceptedChain(t *testing.T) {
	firstRequest := make(chan struct{})
	releaseFirst := make(chan struct{})
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			close(firstRequest)
			<-releaseFirst
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       3, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	chain := func(id string) routingAttemptChain {
		return routingAttemptChain{
			GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: id,
			Attempts: []routingAttemptRow{{LogicalRequestID: id, Attempt: 1, IsFinal: true, AccountID: 10, Outcome: "success"}},
		}
	}
	require.True(t, e.Submit(chain("request-1")))
	select {
	case <-firstRequest:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the first request")
	}
	require.True(t, e.Submit(chain("request-2")))
	require.True(t, e.Submit(chain("request-3")))
	closed := make(chan struct{})
	go func() {
		e.Close()
		close(closed)
	}()
	close(releaseFirst)
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for emitter shutdown")
	}
	require.Equal(t, int64(3), requests.Load())
	require.Equal(t, uint64(3), e.Stats().Sent)
	require.False(t, e.Submit(chain("request-after-close")))
}

func TestRoutingAttemptEmitterRejectsChainAbovePanelRowLimit(t *testing.T) {
	e := &RoutingAttemptEmitter{queue: make(chan routingAttemptChain, 1)}
	chain := routingAttemptChain{Attempts: make([]routingAttemptRow, routingAttemptMaxRowsPerRequest+1)}

	require.False(t, e.Submit(chain))
	require.Empty(t, e.queue)
	require.Equal(t, uint64(1), e.Stats().Dropped)
}

func TestRoutingAttemptEmitterSplitsBatchesAtPanelRowLimit(t *testing.T) {
	var mu sync.Mutex
	rowCounts := make([]int, 0, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload struct {
			Observation struct {
				Attempts []routingAttemptRow `json:"attempts"`
			} `json:"observation"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		rowCounts = append(rowCounts, len(payload.Observation.Attempts))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       2, BatchSize: 2, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()
	chain := func(id string, rows int) routingAttemptChain {
		attempts := make([]routingAttemptRow, rows)
		for index := range attempts {
			attempts[index] = routingAttemptRow{
				LogicalRequestID: id, Attempt: index + 1, AccountID: 10,
				ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Outcome: "success",
			}
		}
		return routingAttemptChain{
			GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: id,
			Attempts: attempts,
		}
	}

	e.sendBounded([]routingAttemptChain{chain("request-1", 3000), chain("request-2", 2500)})
	mu.Lock()
	sort.Ints(rowCounts)
	require.Equal(t, []int{2500, 3000}, rowCounts)
	mu.Unlock()
	require.Equal(t, uint64(2), e.Stats().Sent)
}

func TestRoutingAttemptEmitterBoundedSendSkipsInvalidChain(t *testing.T) {
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload struct {
			Observation struct {
				Attempts []routingAttemptRow `json:"attempts"`
			} `json:"observation"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		require.Len(t, payload.Observation.Attempts, 1)
		received.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       2, BatchSize: 2, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()
	valid := routingAttemptChain{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "valid",
		Attempts: []routingAttemptRow{{LogicalRequestID: "valid", Attempt: 1, AccountID: 10, Outcome: "success"}},
	}
	invalid := routingAttemptChain{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "invalid",
		Attempts: make([]routingAttemptRow, routingAttemptMaxRowsPerRequest+1),
	}

	e.sendBounded([]routingAttemptChain{valid, invalid})
	require.Equal(t, int64(1), received.Load())
	require.Equal(t, uint64(1), e.Stats().Sent)
	require.Equal(t, uint64(1), e.Stats().Dropped)
}

func TestRoutingAttemptEmitterDrainsSmallResponseForConnectionReuse(t *testing.T) {
	var mu sync.Mutex
	remoteAddresses := make([]string, 0, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remoteAddresses = append(remoteAddresses, r.RemoteAddr)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
	}))
	server.EnableHTTP2 = false
	server.Start()
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       2, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()
	chain := func(id string) routingAttemptChain {
		return routingAttemptChain{
			GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: id,
			Attempts: []routingAttemptRow{{LogicalRequestID: id, Attempt: 1, AccountID: 10, Outcome: "success"}},
		}
	}

	e.send([]routingAttemptChain{chain("request-1")})
	e.send([]routingAttemptChain{chain("request-2")})
	mu.Lock()
	require.Len(t, remoteAddresses, 2)
	require.Equal(t, remoteAddresses[0], remoteAddresses[1])
	mu.Unlock()
}

func TestRoutingAttemptEmitterRetriesTransientPanelBusyWithSameIdentity(t *testing.T) {
	useFastRoutingAttemptRetries(t)
	var requests atomic.Int64
	var mu sync.Mutex
	operationIDs := make([]string, 0, routingAttemptSendMaxAttempts)
	idempotencyKeys := make([]string, 0, routingAttemptSendMaxAttempts)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload struct {
			OperationID string `json:"operation_id"`
			Observation struct {
				IdempotencyKey string `json:"idempotency_key"`
			} `json:"observation"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		operationIDs = append(operationIDs, payload.OperationID)
		idempotencyKeys = append(idempotencyKeys, payload.Observation.IdempotencyKey)
		mu.Unlock()
		if requests.Add(1) < routingAttemptSendMaxAttempts {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()
	chain := routingAttemptChain{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "panel-busy",
		Attempts: []routingAttemptRow{{LogicalRequestID: "panel-busy", Attempt: 1, AccountID: 10, Outcome: "success"}},
	}

	e.send([]routingAttemptChain{chain})

	require.Equal(t, int64(routingAttemptSendMaxAttempts), requests.Load())
	require.Equal(t, uint64(1), e.Stats().Sent)
	require.Zero(t, e.Stats().Failures)
	mu.Lock()
	require.Len(t, operationIDs, routingAttemptSendMaxAttempts)
	require.Len(t, idempotencyKeys, routingAttemptSendMaxAttempts)
	for index := 1; index < routingAttemptSendMaxAttempts; index++ {
		require.Equal(t, operationIDs[0], operationIDs[index])
		require.Equal(t, idempotencyKeys[0], idempotencyKeys[index])
	}
	mu.Unlock()
}

func TestRoutingAttemptEmitterDoesNotRetryPermanentPanelRejection(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()

	e.send([]routingAttemptChain{{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "permanent-reject",
		Attempts: []routingAttemptRow{{LogicalRequestID: "permanent-reject", Attempt: 1, AccountID: 10, Outcome: "success"}},
	}})

	require.Equal(t, int64(1), requests.Load())
	require.Zero(t, e.Stats().Sent)
	require.Equal(t, uint64(1), e.Stats().Failures)
}

func TestRoutingAttemptEmitterRetriesTransientTransportFailure(t *testing.T) {
	useFastRoutingAttemptRetries(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) < routingAttemptSendMaxAttempts {
			time.Sleep(10 * time.Millisecond)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 5,
	})
	defer e.Close()

	e.send([]routingAttemptChain{{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "transport-retry",
		Attempts: []routingAttemptRow{{LogicalRequestID: "transport-retry", Attempt: 1, AccountID: 10, Outcome: "success"}},
	}})

	require.Equal(t, int64(routingAttemptSendMaxAttempts), requests.Load())
	require.Equal(t, uint64(1), e.Stats().Sent)
	require.Zero(t, e.Stats().Failures)
}

func TestRoutingAttemptEmitterExhaustsTransientPanelRetriesAsOneFailure(t *testing.T) {
	useFastRoutingAttemptRetries(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	e := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: server.URL, Secret: "test-secret", Sub2APIInstanceID: 7,
		AllowedGroupIDs: []int64{5},
		QueueSize:       1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
	})
	defer e.Close()

	e.send([]routingAttemptChain{{
		GroupID: 5, Model: "gpt-5", ObservedAt: time.Now(), IdempotencyKey: "transient-exhausted",
		Attempts: []routingAttemptRow{{LogicalRequestID: "transient-exhausted", Attempt: 1, AccountID: 10, Outcome: "success"}},
	}})

	require.Equal(t, int64(routingAttemptSendMaxAttempts), requests.Load())
	require.Zero(t, e.Stats().Sent)
	require.Equal(t, uint64(1), e.Stats().Failures)
	require.Equal(t, "http_status", e.Stats().LastFailureKind)
	require.Equal(t, http.StatusServiceUnavailable, e.Stats().LastFailureStatusCode)
	require.NotEmpty(t, e.Stats().LastFailureAt)
}

func useFastRoutingAttemptRetries(t *testing.T) {
	t.Helper()
	original := routingAttemptRetryDelays
	for index := range routingAttemptRetryDelays {
		routingAttemptRetryDelays[index] = time.Millisecond
	}
	t.Cleanup(func() { routingAttemptRetryDelays = original })
}

func intPtr(value int) *int { return &value }

func newTestRoutingAttemptEmitter() *RoutingAttemptEmitter {
	return newTestRoutingAttemptEmitterForGroup(5)
}

func newTestRoutingAttemptEmitterForGroup(groupID int64) *RoutingAttemptEmitter {
	return &RoutingAttemptEmitter{
		cfg:           config.GatewayRoutingAttemptEmitterConfig{Enabled: true, AllowedGroupIDs: []int64{groupID}},
		allowedGroups: map[int64]struct{}{groupID: {}},
		queue:         make(chan routingAttemptChain, 8),
	}
}
