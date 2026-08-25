package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// This harness is compiled only into a Go test binary. It exposes the real
// observer Admin handlers and the production request-local recorder over HTTP
// without adding an isolated-runtime bypass to the server binary.
func TestRoutingFailureLoopSourceProcess(t *testing.T) {
	if os.Getenv("NEKO_ROUTING_FAILURE_LOOP_SOURCE") != "1" {
		t.Skip("isolated functional-loop source process is disabled")
	}
	gin.SetMode(gin.ReleaseMode)
	settings := mustFailureLoopSourceSettings(t)
	clock := newFailureLoopClock(time.Now().UTC())
	observer := newRoutingObserverWithDependencies(config.GatewayRoutingObserverConfig{
		Enabled: true, PanelURL: settings.incidentURL, Secret: settings.secret,
		Sub2APIInstanceID: settings.instanceID, DataDir: settings.dataDir,
		QueueSize: 256, RequestTimeoutMS: 500, ShutdownTimeoutMS: 3000,
		MaxScopes: 8, MaxAccountsPerScope: 8, MaxRulesPerPolicy: 4,
		MaxAttemptsPerRequest: 8, MaxPendingOutbox: 8,
	}, clock, nil)
	if observer == nil {
		t.Fatal("routing observer did not start")
	}
	defer observer.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: settings.redisAddress})
	defer redisClient.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		t.Fatalf("routing failure loop Redis unavailable: %v", err)
	}
	concurrency := service.NewConcurrencyService(
		repository.NewConcurrencyCache(redisClient, 15, 900),
	)
	emitter := NewRoutingAttemptEmitter(config.GatewayRoutingAttemptEmitterConfig{
		Enabled: true, PanelURL: settings.panelURL, Secret: settings.secret,
		Sub2APIInstanceID: settings.instanceID, AllowedGroupIDs: []int64{settings.groupID},
		QueueSize: 32, BatchSize: 1, FlushIntervalMS: 10,
		RequestTimeoutMS: 1000, ShutdownTimeoutMS: 3000,
	})
	if emitter == nil {
		t.Fatal("routing attempt emitter did not start")
	}
	defer emitter.Close()

	harness := &failureLoopSourceHarness{
		observer: observer, emitter: emitter, concurrency: concurrency,
		clock: clock, settings: settings,
	}
	gateway := &OpenAIGatewayHandler{routingObserver: observer}
	router := gin.New()
	router.Use(gin.Recovery())
	router.GET("/api/v1/admin/ops/routing-observer/health", gateway.GetRoutingObserverHealth)
	router.GET("/api/v1/admin/ops/routing-observer/scopes/:group_id/:canonical_model", gateway.GetRoutingObserverScope)
	router.PUT("/api/v1/admin/ops/routing-observer/scopes/:group_id/:canonical_model", gateway.PutRoutingObserverScope)
	router.DELETE("/api/v1/admin/ops/routing-observer/scopes/:group_id/:canonical_model", gateway.DeleteRoutingObserverScope)
	router.POST("/v1/responses", harness.responses)
	router.GET("/__control/state", harness.state)
	router.POST("/__control/advance-clock", harness.advanceClock)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("source listener: %v", err)
	}
	server := &http.Server{Handler: router, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	address := "http://" + listener.Addr().String()
	if err := writeFailureLoopAddress(settings.addressFile, address); err != nil {
		_ = server.Close()
		t.Fatalf("source address file: %v", err)
	}

	shutdownFile := settings.shutdownFile
	deadline := time.Now().Add(settings.hardTimeout)
	for {
		if _, err := os.Stat(shutdownFile); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("source shutdown sentinel: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("source harness hard deadline expired")
		}
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Fatalf("source server: %v", err)
			}
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
	shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownContext); err != nil {
		t.Fatalf("source shutdown: %v", err)
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("source server exit: %v", err)
	}
}

type failureLoopSourceSettings struct {
	addressFile  string
	shutdownFile string
	dataDir      string
	incidentURL  string
	panelURL     string
	secret       string
	redisAddress string
	instanceID   int64
	groupID      int64
	model        string
	primaryID    int64
	fallbackID   int64
	candidateID  int64
	hardTimeout  time.Duration
}

func mustFailureLoopSourceSettings(t *testing.T) failureLoopSourceSettings {
	t.Helper()
	required := func(name string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("%s is required", name)
		}
		return value
	}
	positive := func(name string) int64 {
		value, err := strconv.ParseInt(required(name), 10, 64)
		if err != nil || value <= 0 {
			t.Fatalf("%s must be positive", name)
		}
		return value
	}
	seconds, err := strconv.Atoi(required("NEKO_ROUTING_FAILURE_LOOP_HARD_TIMEOUT_SECONDS"))
	if err != nil || seconds < 10 || seconds > 900 {
		t.Fatal("source hard timeout must be between 10 and 900 seconds")
	}
	secret := required("NEKO_ROUTING_FAILURE_LOOP_SECRET")
	if len(secret) < 16 {
		t.Fatal("source hook secret is too short")
	}
	return failureLoopSourceSettings{
		addressFile:  required("NEKO_ROUTING_FAILURE_LOOP_ADDRESS_FILE"),
		shutdownFile: required("NEKO_ROUTING_FAILURE_LOOP_SHUTDOWN_FILE"),
		dataDir:      required("NEKO_ROUTING_FAILURE_LOOP_DATA_DIR"),
		incidentURL:  required("NEKO_ROUTING_FAILURE_LOOP_INCIDENT_URL"),
		panelURL:     required("NEKO_ROUTING_FAILURE_LOOP_PANEL_URL"),
		secret:       secret, redisAddress: required("NEKO_ROUTING_FAILURE_LOOP_REDIS_ADDRESS"),
		instanceID:  positive("NEKO_ROUTING_FAILURE_LOOP_INSTANCE_ID"),
		groupID:     positive("NEKO_ROUTING_FAILURE_LOOP_GROUP_ID"),
		model:       required("NEKO_ROUTING_FAILURE_LOOP_MODEL"),
		primaryID:   positive("NEKO_ROUTING_FAILURE_LOOP_PRIMARY_ID"),
		fallbackID:  positive("NEKO_ROUTING_FAILURE_LOOP_FALLBACK_ID"),
		candidateID: positive("NEKO_ROUTING_FAILURE_LOOP_CANDIDATE_ID"),
		hardTimeout: time.Duration(seconds) * time.Second,
	}
}

type failureLoopSourceHarness struct {
	observer    *RoutingObserver
	emitter     *RoutingAttemptEmitter
	concurrency *service.ConcurrencyService
	clock       *failureLoopClock
	settings    failureLoopSourceSettings
	requests    atomic.Uint64
	ignored     atomic.Uint64
	eligible    atomic.Uint64
	chains      atomic.Uint64
	primary     atomic.Uint64
	fallback    atomic.Uint64
	candidate   atomic.Uint64
}

type failureLoopGatewayRequest struct {
	Profile    string `json:"profile"`
	FixtureID  string `json:"fixture_id,omitempty"`
	Category   string `json:"category,omitempty"`
	APIKeyID   int64  `json:"api_key_id"`
	Model      string `json:"model"`
	StatusCode int    `json:"status_code,omitempty"`
}

func (h *failureLoopSourceHarness) responses(c *gin.Context) {
	h.requests.Add(1)
	var request failureLoopGatewayRequest
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.APIKeyID <= 0 || strings.TrimSpace(request.Model) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "isolated_gateway_request_invalid"})
		return
	}
	switch request.Profile {
	case "failure-v1-fixture":
		h.fixture(c, request)
	case "failure-fallback":
		h.failureFallback(c, request)
	case "primary-success":
		h.success(c, request, h.settings.primaryID, false)
	case "candidate-success":
		h.success(c, request, h.settings.candidateID, true)
	default:
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "isolated_gateway_profile_unsupported"})
	}
}

func (h *failureLoopSourceHarness) fixture(c *gin.Context, request failureLoopGatewayRequest) {
	if request.Category == "pre_upstream" {
		h.ignored.Add(1)
		c.JSON(http.StatusOK, gin.H{"classification": "ignored"})
		return
	}
	recorder := newRoutingObserverRecorder(
		h.observer, h.settings.groupID, request.Model, request.APIKeyID,
		routingAttemptCorrelation{},
	)
	if recorder == nil {
		h.ignored.Add(1)
		c.JSON(http.StatusOK, gin.H{"classification": "ignored"})
		return
	}
	h.eligible.Add(1)
	recorder.record(h.settings.primaryID, nil, failureLoopUpstreamError(request.StatusCode), h.clock.Now())
	recorder.finish(true)
	c.JSON(http.StatusOK, gin.H{"classification": "eligible"})
}

func (h *failureLoopSourceHarness) failureFallback(c *gin.Context, request failureLoopGatewayRequest) {
	recorder := newRoutingObserverRecorder(
		h.observer, h.settings.groupID, request.Model, request.APIKeyID,
		routingAttemptCorrelation{},
	)
	if recorder == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "observer_scope_not_eligible"})
		return
	}
	primary, err := h.concurrency.AcquireAccountSlot(c.Request.Context(), h.settings.primaryID, 1)
	if err != nil || primary == nil || !primary.Acquired {
		recorder.discard()
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "primary_slot_unavailable"})
		return
	}
	failure := failureLoopUpstreamError(request.StatusCode)
	recorder.record(h.settings.primaryID, nil, failure, h.clock.Now())
	primary.ReleaseFunc()
	predecessor := recorder.prepareFailover(h.settings.primaryID, failure)
	tracker := service.NewAccountSlotHandoffTracker()
	if predecessor <= 0 || !tracker.SetPredecessor(predecessor) {
		recorder.discard()
		c.JSON(http.StatusConflict, gin.H{"error": "handoff_predecessor_unavailable"})
		return
	}
	requestContext := service.ContextWithAccountSlotHandoffTracker(c.Request.Context(), tracker)
	fallback, err := h.concurrency.AcquireAccountSlot(requestContext, h.settings.fallbackID, 1)
	if err != nil || fallback == nil || !fallback.Acquired {
		recorder.discard()
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "fallback_slot_unavailable"})
		return
	}
	recorder.captureHandoff(tracker, h.settings.fallbackID)
	ttft := 25
	result := &service.OpenAIForwardResult{FirstTokenMs: &ttft}
	recorder.record(h.settings.fallbackID, result, nil, h.clock.Now().Add(time.Millisecond))
	recorder.finish(true)
	fallback.ReleaseFunc()
	h.chains.Add(1)
	h.fallback.Add(1)
	c.JSON(http.StatusOK, gin.H{
		"terminal": "success", "serving_account_id": h.settings.fallbackID,
		"handoff": "primary_zero_fallback_nonzero",
	})
}

func (h *failureLoopSourceHarness) success(c *gin.Context, request failureLoopGatewayRequest, accountID int64, emitAttempt bool) {
	groupID := h.settings.groupID
	apiKey := &service.APIKey{ID: request.APIKeyID, GroupID: &groupID}
	correlation, status, err := consumeRoutingGatewayCorrelation(c.Request, apiKey, h.observer)
	if err != nil {
		c.JSON(status, gin.H{"error": "canary_correlation_rejected"})
		return
	}
	recorder := newRoutingObserverRecorder(
		h.observer, groupID, request.Model, request.APIKeyID, correlation,
	)
	if recorder == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "observer_scope_not_eligible"})
		return
	}
	ttft := 20
	result := &service.OpenAIForwardResult{FirstTokenMs: &ttft}
	recorder.record(accountID, result, nil, h.clock.Now())
	recorder.finish(true)
	if emitAttempt {
		legacy := newRoutingAttemptRecorder(h.emitter, groupID, request.Model, correlation)
		if legacy == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "canary_attempt_evidence_unavailable"})
			return
		}
		legacy.record(accountID, result, nil, time.Now().UTC())
		legacy.finish()
		h.candidate.Add(1)
	} else {
		h.primary.Add(1)
	}
	c.JSON(http.StatusOK, gin.H{
		"terminal": "success", "serving_account_id": accountID,
		"correlation_sha256": correlation.CorrelationSHA256,
	})
}

func (h *failureLoopSourceHarness) state(c *gin.Context) {
	outboxCount := 0
	entries, err := os.ReadDir(filepath.Join(h.settings.dataDir, "routing-observer-v1", "outbox"))
	if err == nil {
		outboxCount = len(entries)
	} else if !errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "outbox_read_failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"contract_version": "routing-failure-loop-source-state.v1",
		"observer":         h.observer.Health(), "attempt_emitter": h.emitter.Stats(),
		"durable_outbox_file_count": outboxCount,
		"gateway_request_count":     h.requests.Load(), "fixture_ignored_count": h.ignored.Load(),
		"fixture_eligible_count": h.eligible.Load(), "failure_fallback_chain_count": h.chains.Load(),
		"primary_serving_count": h.primary.Load(), "fallback_serving_count": h.fallback.Load(),
		"candidate_serving_count": h.candidate.Load(), "clock_periods_advanced": h.clock.Periods(),
	})
}

func (h *failureLoopSourceHarness) advanceClock(c *gin.Context) {
	var request struct {
		Seconds int `json:"seconds"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 256))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || request.Seconds < 1 || request.Seconds > 3600 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "clock_advance_invalid"})
		return
	}
	h.clock.Advance(time.Duration(request.Seconds) * time.Second)
	c.JSON(http.StatusOK, gin.H{"advanced": true, "periods": h.clock.Periods()})
}

func failureLoopUpstreamError(status int) *service.UpstreamFailoverError {
	if status < 400 || status > 599 {
		status = http.StatusServiceUnavailable
	}
	return &service.UpstreamFailoverError{
		StatusCode: status, Stage: service.GatewayFailureStageInference,
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("isolated_upstream_terminal_failure"),
		NextAccountAction: service.NextAccountRetry,
	}
}

type failureLoopClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []failureLoopClockWaiter
	periods atomic.Uint64
}

type failureLoopClockWaiter struct {
	deadline time.Time
	channel  chan time.Time
}

func newFailureLoopClock(now time.Time) *failureLoopClock {
	return &failureLoopClock{now: now.UTC()}
}

func (c *failureLoopClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *failureLoopClock) After(delay time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	channel := make(chan time.Time, 1)
	c.waiters = append(c.waiters, failureLoopClockWaiter{deadline: c.now.Add(delay), channel: channel})
	return channel
}

func (c *failureLoopClock) Advance(delta time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delta)
	remaining := c.waiters[:0]
	for _, waiter := range c.waiters {
		if waiter.deadline.After(c.now) {
			remaining = append(remaining, waiter)
			continue
		}
		waiter.channel <- c.now
		close(waiter.channel)
	}
	c.waiters = remaining
	c.mu.Unlock()
	c.periods.Add(1)
}

func (c *failureLoopClock) Periods() uint64 { return c.periods.Load() }

func writeFailureLoopAddress(path, address string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(address+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
