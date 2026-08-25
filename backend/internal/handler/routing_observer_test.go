package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestRoutingObserverScopeCASReadbackDisableAndDelete(t *testing.T) {
	transport := &routingObserverTestTransport{}
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
	observer := newRoutingObserverWithDependencies(cfg, nil, transport)
	t.Cleanup(observer.Close)

	request := routingObserverScopeRequest("scope-create", 0, "", true)
	created, err := observer.PutScope(31, "gpt-5.6-sol", request)
	require.NoError(t, err)
	require.Equal(t, int64(1), created.Revision)
	require.Equal(t, "ready", created.State)
	require.True(t, validRoutingSHA256(created.ScopeHash))
	require.True(t, validRoutingSHA256(created.PolicyHash))
	require.True(t, validRoutingSHA256(created.ReadbackHash))

	duplicate, err := observer.PutScope(31, "gpt-5.6-sol", request)
	require.NoError(t, err)
	require.True(t, duplicate.Duplicate)
	require.Equal(t, created.ScopeHash, duplicate.ScopeHash)
	require.Equal(t, created.ReadbackHash, duplicate.ReadbackHash)

	conflictingOperation := request
	conflictingOperation.Scope.RouteVersion++
	_, err = observer.PutScope(31, "gpt-5.6-sol", conflictingOperation)
	requireRoutingObserverOperationError(t, err, http.StatusConflict, "routing_scope_operation_conflict")

	wrongCAS := routingObserverScopeRequest("scope-update-wrong", created.Revision, strings.Repeat("sha256:a", 1), false)
	_, err = observer.PutScope(31, "gpt-5.6-sol", wrongCAS)
	requireRoutingObserverOperationError(t, err, http.StatusBadRequest, "routing_scope_cas_invalid")
	staleCAS := routingObserverScopeRequest("scope-update-stale", created.Revision, "sha256:"+strings.Repeat("b", 64), false)
	_, err = observer.PutScope(31, "gpt-5.6-sol", staleCAS)
	requireRoutingObserverOperationError(t, err, http.StatusConflict, "routing_scope_cas_conflict")

	disable := routingObserverScopeRequest("scope-disable", created.Revision, created.ScopeHash, false)
	disabled, err := observer.PutScope(31, "gpt-5.6-sol", disable)
	require.NoError(t, err)
	require.Equal(t, int64(2), disabled.Revision)
	require.Equal(t, "disabled", disabled.State)

	err = observer.DeleteScope(31, "gpt-5.6-sol", RoutingObserverScopeDeleteRequest{
		ContractVersion: RoutingObserverScopeDeleteContractV1,
		OperationID:     "scope-delete-wrong", ExpectedCurrentHash: created.ScopeHash,
	})
	requireRoutingObserverOperationError(t, err, http.StatusConflict, "routing_scope_cas_conflict")
	err = observer.DeleteScope(31, "gpt-5.6-sol", RoutingObserverScopeDeleteRequest{
		ContractVersion: RoutingObserverScopeDeleteContractV1,
		OperationID:     "scope-delete", ExpectedCurrentHash: disabled.ScopeHash,
	})
	require.NoError(t, err)
	_, err = observer.GetScope(31, "gpt-5.6-sol")
	requireRoutingObserverOperationError(t, err, http.StatusNotFound, "routing_scope_not_found")
	require.Zero(t, transport.calls.Load())
}

func TestRoutingObserverRouteRearmClearsOnlyTopologyScopedDegradation(t *testing.T) {
	observer := newRoutingObserverWithDependencies(
		routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid"),
		nil,
		&routingObserverTestTransport{},
	)
	t.Cleanup(observer.Close)

	created, err := observer.PutScope(
		31,
		"gpt-5.6-sol",
		routingObserverScopeRequest("scope-create", 0, "", true),
	)
	require.NoError(t, err)
	for _, reason := range []string{
		routingObserverReasonScopeDrift,
		routingObserverReasonAttributionGap,
		routingObserverReasonUntypedFailure,
		routingObserverReasonConcurrencyGap,
		routingObserverReasonDiskFailure,
	} {
		observer.markDegraded(reason)
	}

	update := routingObserverScopeRequest(
		"scope-route-rearm",
		created.Revision,
		created.ScopeHash,
		true,
	)
	update.Scope.RouteVersion++
	update.Scope.TopologyFingerprint = "sha256:" + strings.Repeat("b", 64)
	update.Scope.Roles = RoutingScopeRoles{
		PrimaryAccountIDs:   []int64{103},
		FallbackAccountIDs:  []int64{102},
		CandidateAccountIDs: []int64{104},
	}
	rearmed, err := observer.PutScope(31, "gpt-5.6-sol", update)
	require.NoError(t, err)
	require.Equal(t, "ready", rearmed.State)

	health := observer.Health()
	require.Contains(t, health.ReasonCodes, routingObserverReasonDiskFailure)
	for _, reason := range []string{
		routingObserverReasonScopeDrift,
		routingObserverReasonAttributionGap,
		routingObserverReasonUntypedFailure,
		routingObserverReasonConcurrencyGap,
	} {
		require.NotContains(t, health.ReasonCodes, reason)
	}
}

func TestRoutingObserverAdminGinStrictScopeLoopbackAndHealthRedaction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), "https://panel.internal.example")
	observer := newRoutingObserverWithDependencies(cfg, nil, &routingObserverTestTransport{})
	t.Cleanup(observer.Close)
	handler := &OpenAIGatewayHandler{routingObserver: observer}
	router := gin.New()
	router.GET("/api/v1/admin/ops/routing-observer/health", handler.GetRoutingObserverHealth)
	router.GET("/api/v1/admin/ops/routing-observer/scopes/:group_id/:canonical_model", handler.GetRoutingObserverScope)
	router.PUT("/api/v1/admin/ops/routing-observer/scopes/:group_id/:canonical_model", handler.PutRoutingObserverScope)

	invalid := []byte(`{"contract_version":"routing-observer-scope.v1","operation_id":"strict-test","expected_revision":0,"expected_current_hash":"","scope":{},"unknown":true}`)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/ops/routing-observer/scopes/31/gpt-5.6-sol", bytes.NewReader(invalid))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Contains(t, recorder.Body.String(), "routing_scope_request_invalid")
	require.Equal(t, 0, observer.Health().ScopeCount)

	payload, err := canonicalJSON(routingObserverScopeRequest("gin-scope-create", 0, "", true))
	require.NoError(t, err)
	request = httptest.NewRequest(http.MethodPut, "/api/v1/admin/ops/routing-observer/scopes/31/gpt-5.6-sol", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), RoutingObserverScopeReadbackContractV1)
	require.Contains(t, recorder.Body.String(), "gin-scope-create")

	request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/routing-observer/scopes/31/gpt-5.6-sol", nil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), "gpt-5.6-sol")

	request = httptest.NewRequest(http.MethodGet, "/api/v1/admin/ops/routing-observer/health", nil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.NotContains(t, recorder.Body.String(), cfg.PanelURL)
	require.NotContains(t, recorder.Body.String(), cfg.Secret)
	require.NotContains(t, recorder.Body.String(), "hmac-sha256:")
}

func TestRoutingObserverMatchedPersistsBeforeShortPostAndExactACK(t *testing.T) {
	dataDir := t.TempDir()
	secret := "0123456789abcdef"
	var calls atomic.Uint64
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		require.Equal(t, routingIncidentHookPath, request.URL.Path)
		require.Equal(t, RoutingIncidentHookSignatureV1, request.Header.Get("X-Dispatch-Signature-Version"))
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		capturedBody = append([]byte(nil), body...)
		verifyRoutingIncidentSignature(t, request, body, secret)
		entries, err := os.ReadDir(filepath.Join(dataDir, "routing-observer-v1", "outbox"))
		require.NoError(t, err)
		require.Len(t, entries, 1, "outbox must be durable before transport")
		var signal RoutingIncidentSignal
		require.NoError(t, decodeRoutingObserverJSON(body, &signal))
		digest := sha256.Sum256(body)
		writeRoutingIncidentACK(t, w, signal, "sha256:"+hex.EncodeToString(digest[:]))
	}))
	t.Cleanup(server.Close)

	cfg := routingObserverRuntimeTestConfig(dataDir, server.URL)
	observer := NewRoutingObserver(cfg)
	t.Cleanup(observer.Close)
	readback, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	require.Equal(t, readback.ScopeHash, scope.ScopeHash)

	result := observer.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.True(t, result.Accepted)
	require.Eventually(t, func() bool {
		health := observer.Health()
		return health.OutboxAckTotal == 1 && health.PendingOutboxCount == 0
	}, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), calls.Load())
	require.LessOrEqual(t, len(capturedBody), routingIncidentMaxBodyBytes)
	require.NotContains(t, string(capturedBody), "account_id")
	require.NotContains(t, string(capturedBody), "logical_request_id")
	require.NotContains(t, string(capturedBody), "status_message")
	require.NotContains(t, string(capturedBody), "email")
	var signal RoutingIncidentSignal
	require.NoError(t, decodeRoutingObserverJSON(capturedBody, &signal))
	require.Len(t, signal.Incident.Evidence.ChainDigests, 1)
	require.Equal(t, RoutingCriticalFailureRuleV1, signal.Incident.Winner.RuleID)

	observer.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.Eventually(t, func() bool { return observer.Health().DuplicateTotal == 1 }, time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), calls.Load(), "an admitted latch must suppress duplicate actions")
}

func TestRoutingObserverIgnoredFactsHaveNoTimerDrivenTransport(t *testing.T) {
	clock := newRoutingObserverManualClock(time.Unix(100, 0).UTC())
	transport := &routingObserverTestTransport{}
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
	observer := newRoutingObserverWithDependencies(cfg, clock, transport)
	t.Cleanup(observer.Close)
	_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	observer.mu.RLock()
	require.Len(t, observer.scopes[routingScopeKey(31, "gpt-5.6-sol")].buckets, 30)
	observer.mu.RUnlock()
	fact := routingObserverMatchedFact(scope, scope.ScopeHash)
	fact.TrafficOrigin = RoutingTrafficOriginMonitor
	require.True(t, observer.Submit(fact).Accepted)
	require.Eventually(t, func() bool { return observer.Health().QueueDepth == 0 }, time.Second, 10*time.Millisecond)
	clock.Advance(24 * time.Hour)
	clock.Advance(30 * 24 * time.Hour)
	require.Zero(t, transport.calls.Load())
	require.Zero(t, observer.Health().PendingOutboxCount)
}

func TestRoutingObserverHTTP2xxACKDriftKeepsDurableOutbox(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"item":{"contract_version":"routing-incident-ack.v1"}}`))
	}))
	t.Cleanup(server.Close)
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), server.URL)
	observer := NewRoutingObserver(cfg)
	t.Cleanup(observer.Close)
	_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	observer.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.Eventually(t, func() bool {
		health := observer.Health()
		return calls.Load() >= 1 && health.PendingOutboxCount == 1 && containsRoutingReason(health.ReasonCodes, routingObserverReasonAckMismatch)
	}, 2*time.Second, 10*time.Millisecond)
}

func TestRoutingObserverRestartRecoversAndDeliversFrozenOutbox(t *testing.T) {
	dataDir := t.TempDir()
	var firstCalls atomic.Uint64
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	cfg := routingObserverRuntimeTestConfig(dataDir, failing.URL)
	first := NewRoutingObserver(cfg)
	_, err := first.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := first.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	first.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.Eventually(t, func() bool { return firstCalls.Load() >= 1 && first.Health().PendingOutboxCount == 1 }, 2*time.Second, 10*time.Millisecond)
	first.Close()
	failing.Close()

	var recoveredCalls atomic.Uint64
	recovered := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		recoveredCalls.Add(1)
		var signal RoutingIncidentSignal
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		require.NoError(t, decodeRoutingObserverJSON(body, &signal))
		digest := sha256.Sum256(body)
		writeRoutingIncidentACK(t, w, signal, "sha256:"+hex.EncodeToString(digest[:]))
	}))
	t.Cleanup(recovered.Close)
	cfg.PanelURL = recovered.URL
	second := NewRoutingObserver(cfg)
	t.Cleanup(second.Close)
	require.True(t, second.Health().Accepting)
	require.Equal(t, 1, second.Health().PendingOutboxCount)
	require.Eventually(t, func() bool { return second.Health().OutboxAckTotal == 1 && second.Health().PendingOutboxCount == 0 }, 4*time.Second, 10*time.Millisecond)
	require.Equal(t, uint64(1), recoveredCalls.Load())
}

func TestRoutingObserverRestartRestoresAdmittedLatchAndLastACKWithoutResend(t *testing.T) {
	dataDir := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		require.NoError(t, err)
		var signal RoutingIncidentSignal
		require.NoError(t, decodeRoutingObserverJSON(body, &signal))
		digest := sha256.Sum256(body)
		writeRoutingIncidentACK(t, w, signal, "sha256:"+hex.EncodeToString(digest[:]))
	}))
	cfg := routingObserverRuntimeTestConfig(dataDir, server.URL)
	first := NewRoutingObserver(cfg)
	_, err := first.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := first.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	first.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.Eventually(t, func() bool { return first.Health().OutboxAckTotal == 1 }, 2*time.Second, 10*time.Millisecond)
	first.Close()
	server.Close()

	transport := &routingObserverTestTransport{}
	second := newRoutingObserverWithDependencies(cfg, nil, transport)
	t.Cleanup(second.Close)
	health := second.Health()
	require.True(t, health.Ready)
	require.Zero(t, health.PendingOutboxCount)
	require.NotNil(t, health.LastAcknowledgedAt)
	require.Zero(t, transport.calls.Load())
	second.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	require.Eventually(t, func() bool { return second.Health().DuplicateTotal == 1 }, time.Second, 10*time.Millisecond)
	require.Zero(t, transport.calls.Load())
}

func TestRoutingObserverCorruptStoreFailsClosedAndHealthRedactsConfiguration(t *testing.T) {
	dataDir := t.TempDir()
	store, err := newRoutingObserverFileStore(dataDir)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(store.scopesDir, "scope-corrupt.json"), []byte(`{"contract_version":`), 0o600))
	cfg := routingObserverRuntimeTestConfig(dataDir, "https://panel.secret.example")
	cfg.Secret = "very-secret-value"
	observer := NewRoutingObserver(cfg)
	t.Cleanup(observer.Close)
	health := observer.Health()
	require.False(t, health.Ready)
	require.False(t, health.Accepting)
	require.Contains(t, health.ReasonCodes, routingObserverReasonStoreCorrupt)
	payload, err := json.Marshal(health)
	require.NoError(t, err)
	require.NotContains(t, string(payload), cfg.PanelURL)
	require.NotContains(t, string(payload), cfg.Secret)
	require.NotContains(t, string(payload), "hmac-sha256:")
}

func TestRoutingObserverSubmitIsBoundedNonBlockingMemoryOnly(t *testing.T) {
	observer := &RoutingObserver{
		cfg:   config.GatewayRoutingObserverConfig{MaxAttemptsPerRequest: 1},
		queue: make(chan RoutingRequestFact, 1), degradedReasons: make(map[string]struct{}),
	}
	observer.accepting.Store(true)
	fact := RoutingRequestFact{Attempts: []RoutingAttemptFact{{AttemptIndex: 1}, {AttemptIndex: 2}}}
	started := time.Now()
	first := observer.Submit(fact)
	second := observer.Submit(fact)
	require.Less(t, time.Since(started), 50*time.Millisecond)
	require.True(t, first.Accepted)
	require.True(t, first.Gap)
	require.False(t, second.Accepted)
	require.True(t, second.Gap)
	require.Equal(t, uint64(1), observer.queueGapTotal.Load())
	queued := <-observer.queue
	require.Len(t, queued.Attempts, 1)
	require.True(t, queued.Gap)
}

func TestRoutingObserverOutboxCapacityAndDiskFailureNeverCreateUndurableSend(t *testing.T) {
	t.Run("capacity", func(t *testing.T) {
		transport := &routingObserverBlockingTransport{started: make(chan struct{}, 1)}
		cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
		cfg.MaxPendingOutbox = 1
		observer := newRoutingObserverWithDependencies(cfg, nil, transport)
		t.Cleanup(observer.Close)
		_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-one", 0, "", true))
		require.NoError(t, err)
		secondRequest := routingObserverScopeRequest("scope-two", 0, "", true)
		secondRequest.Scope.GroupID = 32
		secondRequest.Scope.CanonicalModel = "gpt-5.6-sol-secondary"
		secondRequest.Scope.ModelAliases = []string{"gpt-5.6-sol-secondary"}
		_, err = observer.PutScope(32, "gpt-5.6-sol-secondary", secondRequest)
		require.NoError(t, err)
		firstScope, ok := observer.LookupScope(31, "gpt-5.6-sol")
		require.True(t, ok)
		observer.Submit(routingObserverMatchedFact(firstScope, firstScope.ScopeHash))
		select {
		case <-transport.started:
		case <-time.After(2 * time.Second):
			t.Fatal("first incident was not delivered")
		}
		secondScope, ok := observer.LookupScope(32, "gpt-5.6-sol-secondary")
		require.True(t, ok)
		observer.Submit(routingObserverMatchedFact(secondScope, secondScope.ScopeHash))
		require.Eventually(t, func() bool {
			health := observer.Health()
			return health.PendingOutboxCount == 1 && containsRoutingReason(health.ReasonCodes, routingObserverReasonOutboxCapacity)
		}, time.Second, 10*time.Millisecond)
		require.Equal(t, uint64(1), transport.calls.Load())
	})

	t.Run("disk failure", func(t *testing.T) {
		transport := &routingObserverTestTransport{}
		cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
		observer := newRoutingObserverWithDependencies(cfg, nil, transport)
		t.Cleanup(observer.Close)
		_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
		require.NoError(t, err)
		store := observer.incidentStore.(*routingObserverFileStore)
		store.atomicWriteHook = func(stage string) error {
			if stage == "before_create" {
				return errors.New("injected outbox disk failure")
			}
			return nil
		}
		scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
		require.True(t, ok)
		observer.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
		require.Eventually(t, func() bool {
			health := observer.Health()
			return containsRoutingReason(health.ReasonCodes, routingObserverReasonDiskFailure)
		}, time.Second, 10*time.Millisecond)
		require.Zero(t, observer.Health().PendingOutboxCount)
		require.Zero(t, transport.calls.Load())
	})
}

func TestRoutingObserverShutdownDeadlineIsHardAndRecoverable(t *testing.T) {
	transport := &routingObserverTestTransport{}
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
	cfg.ShutdownTimeoutMS = 50
	observer := newRoutingObserverWithDependencies(cfg, nil, transport)
	_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	store := observer.incidentStore.(*routingObserverFileStore)
	started := make(chan struct{})
	release := make(chan struct{})
	var blocked atomic.Bool
	store.atomicWriteHook = func(stage string) error {
		if stage == "before_create" && blocked.CompareAndSwap(false, true) {
			close(started)
			<-release
		}
		return nil
	}
	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	observer.Submit(routingObserverMatchedFact(scope, scope.ScopeHash))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not reach the injected durable write")
	}
	startedAt := time.Now()
	observer.Close()
	require.Less(t, time.Since(startedAt), 500*time.Millisecond)
	close(release)
	require.True(t, waitRoutingObserverChannel(observer.workerDone, time.Second))
	require.Contains(t, observer.Health().ReasonCodes, routingObserverReasonShutdownTimeout)
}

func TestRoutingObserverAtomicStoreKeepsPreviousRecordBeforeRenameFaults(t *testing.T) {
	store, err := newRoutingObserverFileStore(t.TempDir())
	require.NoError(t, err)
	initial := routingObserverStoredScopeFixture(t, "initial", 1)
	require.NoError(t, store.PutScope(initial))

	for _, stage := range []string{"before_create", "before_file_sync", "before_rename"} {
		t.Run(stage, func(t *testing.T) {
			store.atomicWriteHook = func(current string) error {
				if current == stage {
					return errors.New("injected atomic write failure")
				}
				return nil
			}
			updated := routingObserverStoredScopeFixture(t, "updated-"+stage, 2)
			require.Error(t, store.PutScope(updated))
			store.atomicWriteHook = nil
			items, err := store.LoadScopes()
			require.NoError(t, err)
			require.Len(t, items, 1)
			require.Equal(t, initial.OperationID, items[0].OperationID)
			entries, err := os.ReadDir(store.scopesDir)
			require.NoError(t, err)
			for _, entry := range entries {
				require.False(t, strings.Contains(entry.Name(), ".tmp-"))
			}
		})
	}
}

func TestRoutingObserverSameIdentityDifferentPayloadConflictsAndStopsSend(t *testing.T) {
	transport := &routingObserverBlockingTransport{started: make(chan struct{}, 1)}
	cfg := routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid")
	observer := newRoutingObserverWithDependencies(cfg, nil, transport)
	t.Cleanup(observer.Close)
	_, err := observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("scope-create", 0, "", true))
	require.NoError(t, err)
	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	observer.mu.RLock()
	runtime := observer.scopes[routingScopeKey(31, "gpt-5.6-sol")]
	observer.mu.RUnlock()
	fact := routingObserverMatchedFact(scope, scope.ScopeHash)
	decision := runtime.registry.Evaluate(scope, fact)
	identity, err := RoutingIncidentIdentity([]byte(cfg.Secret), scope, decision.PolicyHash, decision.Winner.RuleID)
	require.NoError(t, err)
	signal, err := observer.buildIncidentSignal(runtime.stored, fact, decision, identity)
	require.NoError(t, err)
	resolution, err := observer.persistIncidentSignal(signal)
	require.NoError(t, err)
	require.Equal(t, RoutingIdentityNew, resolution)
	<-transport.started
	signal.Incident.Window.LastObservedAt = signal.Incident.Window.LastObservedAt.Add(time.Second)
	resolution, err = observer.persistIncidentSignal(signal)
	require.Error(t, err)
	require.Equal(t, RoutingIdentityConflict, resolution)
	health := observer.Health()
	require.Equal(t, uint64(1), health.ConflictCount)
	require.Equal(t, 1, health.PendingOutboxCount)
	require.Contains(t, health.ReasonCodes, routingObserverReasonIdentityConflict)
	observer.Close()

	recoveredTransport := &routingObserverTestTransport{}
	recovered := newRoutingObserverWithDependencies(cfg, nil, recoveredTransport)
	t.Cleanup(recovered.Close)
	recoveredHealth := recovered.Health()
	require.False(t, recoveredHealth.Ready)
	require.Equal(t, uint64(1), recoveredHealth.ConflictCount)
	require.Equal(t, 1, recoveredHealth.PendingOutboxCount)
	require.Contains(t, recoveredHealth.ReasonCodes, routingObserverReasonIdentityConflict)
	require.Zero(t, recoveredTransport.calls.Load())
}

func routingObserverRuntimeTestConfig(dataDir, panelURL string) config.GatewayRoutingObserverConfig {
	return config.GatewayRoutingObserverConfig{
		Enabled: true, PanelURL: panelURL, Secret: "0123456789abcdef", Sub2APIInstanceID: 1,
		DataDir: dataDir, QueueSize: 256, RequestTimeoutMS: 500, ShutdownTimeoutMS: 2000,
		MaxScopes: 64, MaxAccountsPerScope: 32, MaxRulesPerPolicy: 16,
		MaxAttemptsPerRequest: 64, MaxPendingOutbox: 64,
	}
}

func routingObserverScopeRequest(operationID string, expectedRevision int64, expectedHash string, enabled bool) RoutingObserverScopePutRequest {
	scope := routingObserverTestScope(DefaultRoutingFailurePolicy())
	return RoutingObserverScopePutRequest{
		ContractVersion: RoutingObserverScopeContractV1, OperationID: operationID,
		ExpectedRevision: expectedRevision, ExpectedCurrentHash: expectedHash,
		Scope: RoutingObserverScopeSnapshot{
			Enabled: enabled, Sub2APIInstanceID: scope.Sub2APIInstanceID, GroupID: scope.GroupID,
			CanonicalModel: scope.CanonicalModel, ModelAliases: append([]string(nil), scope.ModelAliases...),
			RouteVersion: scope.RouteVersion, TopologyFingerprint: scope.TopologyFingerprint,
			Roles: cloneRoutingRoles(scope.Roles), TrafficOrigin: cloneRoutingTrafficOrigin(scope.TrafficOrigin),
			Policy: cloneRoutingPolicy(scope.Policy),
		},
	}
}

func routingObserverStoredScopeFixture(t *testing.T, operationID string, revision int64) routingStoredScope {
	t.Helper()
	registry := NewDefaultRoutingPolicyRegistry()
	scope := routingObserverTestScope(DefaultRoutingFailurePolicy())
	scope.ScopeRevision = revision
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	validated, ok := registry.LastKnownGood()
	require.True(t, ok)
	scope.ScopeHash = scopeHash
	item := routingStoredScope{
		OperationID: operationID, Scope: scope, ScopeHash: scopeHash, PolicyHash: validated.Hash,
		StoredAt: time.Unix(revision, 0).UTC(),
	}
	item.ReadbackHash, err = routingScopeReadbackHash(item)
	require.NoError(t, err)
	return item
}

func requireRoutingObserverOperationError(t *testing.T, err error, status int, reason string) {
	t.Helper()
	var operationError *RoutingObserverOperationError
	require.ErrorAs(t, err, &operationError)
	require.Equal(t, status, operationError.StatusCode)
	require.Equal(t, reason, operationError.ReasonCode)
}

func verifyRoutingIncidentSignature(t *testing.T, request *http.Request, body []byte, secret string) {
	t.Helper()
	timestamp := request.Header.Get("X-Dispatch-Timestamp")
	_, err := strconv.ParseInt(timestamp, 10, 64)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "."))
	_, _ = mac.Write(body)
	require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)), request.Header.Get("X-Dispatch-Signature"))
}

func writeRoutingIncidentACK(t *testing.T, writer http.ResponseWriter, signal RoutingIncidentSignal, payloadHash string) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(writer).Encode(routingIncidentAckEnvelope{Item: RoutingIncidentAck{
		ContractVersion: RoutingIncidentAckContractV1, IncidentID: signal.Incident.IncidentID,
		IdempotencyKey: signal.Incident.IdempotencyKey, PayloadHash: payloadHash, AdmissionState: "admitted",
		RouteVersion: signal.Incident.Scope.RouteVersion, PolicyHash: signal.Incident.Policy.Hash,
		RouteIntentID: "intent-test", DispatchRunID: 1,
	}}))
}

func containsRoutingReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}

type routingObserverTestTransport struct {
	calls atomic.Uint64
}

func (t *routingObserverTestTransport) Deliver(context.Context, routingIncidentOutboxItem) (RoutingIncidentAck, string, error) {
	t.calls.Add(1)
	return RoutingIncidentAck{}, routingObserverReasonTransport, errors.New("test transport should not be called")
}

type routingObserverBlockingTransport struct {
	started chan struct{}
	calls   atomic.Uint64
}

func (t *routingObserverBlockingTransport) Deliver(ctx context.Context, _ routingIncidentOutboxItem) (RoutingIncidentAck, string, error) {
	t.calls.Add(1)
	select {
	case t.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return RoutingIncidentAck{}, routingObserverReasonTransport, ctx.Err()
}

type routingObserverManualClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []routingObserverManualWaiter
}

type routingObserverManualWaiter struct {
	at      time.Time
	channel chan time.Time
}

func newRoutingObserverManualClock(now time.Time) *routingObserverManualClock {
	return &routingObserverManualClock{now: now.UTC()}
}

func (c *routingObserverManualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *routingObserverManualClock) After(delay time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	channel := make(chan time.Time, 1)
	at := c.now.Add(delay)
	if delay <= 0 {
		channel <- c.now
		return channel
	}
	c.waiters = append(c.waiters, routingObserverManualWaiter{at: at, channel: channel})
	return channel
}

func (c *routingObserverManualClock) Advance(delay time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(delay)
	remaining := c.waiters[:0]
	for _, waiter := range c.waiters {
		if !waiter.at.After(c.now) {
			waiter.channel <- c.now
			continue
		}
		remaining = append(remaining, waiter)
	}
	c.waiters = remaining
	c.mu.Unlock()
}
