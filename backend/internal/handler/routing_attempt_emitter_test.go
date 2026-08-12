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
		if e != nil || newRoutingAttemptRecorder(e, 5, "gpt-5") != nil || newRoutingAttemptWebSocketRecorder(e, 5, "gpt-5") != nil {
			panic("disabled emitter created runtime state")
		}
	})
	require.Zero(t, allocations)
}

func TestRoutingAttemptEmitterSendsBoundedSignedV2Batch(t *testing.T) {
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
		QueueSize: 2, BatchSize: 1, FlushIntervalMS: 10, RequestTimeoutMS: 500,
	})
	defer e.Close()
	recorder := newRoutingAttemptRecorder(e, 5, "gpt-\u2028-5")
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
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for emitter batch")
	}
}

func TestRoutingAttemptRecorderCapturesGatewayFactsAndFinalMarker(t *testing.T) {
	emitter := newTestRoutingAttemptEmitter()
	recorder := newRoutingAttemptRecorder(emitter, 5, "gpt-5")
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
	recorder := newRoutingAttemptRecorder(newTestRoutingAttemptEmitter(), 5, "gpt-5")
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
	first := newRoutingAttemptRecorder(emitter, 5, "gpt-5")
	second := newRoutingAttemptRecorder(emitter, 5, "gpt-5")
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
	recorder := newRoutingAttemptRecorder(newTestRoutingAttemptEmitter(), 5, "gpt-5")
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
	recorder := newRoutingAttemptWebSocketRecorder(emitter, 5, "gpt-5")
	recorder.record(1, 10, nil, &service.UpstreamFailoverError{StatusCode: http.StatusBadGateway}, time.Now())
	cancel()

	recordRoutingWebSocketAttemptIfClientPresent(c, recorder, 1, 11, nil, nil, time.Now())
	recorder.finish()

	require.Empty(t, recorder.turns)
	require.Empty(t, emitter.queue)
}

func TestRoutingAttemptRecorderDoesNotSubmitUngroupedRequest(t *testing.T) {
	e := newTestRoutingAttemptEmitter()
	recorder := newRoutingAttemptRecorder(e, 0, "gpt-5")
	recorder.record(10, nil, nil, time.Now())
	recorder.finish()
	require.Empty(t, e.queue)
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
		QueueSize: 1, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 5_000,
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
		QueueSize: 3, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
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
		QueueSize: 2, BatchSize: 2, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
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
		QueueSize: 2, BatchSize: 2, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
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
		QueueSize: 2, BatchSize: 1, FlushIntervalMS: 60_000, RequestTimeoutMS: 2_000,
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

func intPtr(value int) *int { return &value }

func newTestRoutingAttemptEmitter() *RoutingAttemptEmitter {
	return &RoutingAttemptEmitter{
		cfg:   config.GatewayRoutingAttemptEmitterConfig{Enabled: true},
		queue: make(chan routingAttemptChain, 8),
	}
}
