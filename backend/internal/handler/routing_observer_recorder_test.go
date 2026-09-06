package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type routingObserverRecorderTestBackend struct {
	mu               sync.Mutex
	scope            RoutingManagedScope
	accepted         bool
	current          bool
	beginCalls       int
	submitted        []RoutingRequestFact
	driftMarks       int
	attributionMarks int
	attemptGapMarks  int
}

func (b *routingObserverRecorderTestBackend) BeginScopedRequest(int64, string, int64, string) (RoutingManagedScope, RoutingTrafficOrigin, string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.beginCalls++
	if !b.accepted {
		return RoutingManagedScope{}, "", "ignored", false
	}
	return cloneRoutingManagedScope(b.scope), RoutingTrafficOriginUser, "eligible_user", true
}

func (b *routingObserverRecorderTestBackend) ScopeStillCurrent(RoutingManagedScope) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

func (b *routingObserverRecorderTestBackend) EvidenceDigest(domain, value string) (string, error) {
	return RoutingEvidenceDigest([]byte("0123456789abcdef"), domain, value)
}

func (b *routingObserverRecorderTestBackend) Submit(fact RoutingRequestFact) RoutingObserverSubmitResult {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.submitted = append(b.submitted, cloneRoutingObserverRequestFact(fact))
	return RoutingObserverSubmitResult{Accepted: true}
}

func (b *routingObserverRecorderTestBackend) MarkScopeDrift() {
	b.mu.Lock()
	b.driftMarks++
	b.mu.Unlock()
}

func (b *routingObserverRecorderTestBackend) MarkAttributionGap() {
	b.mu.Lock()
	b.attributionMarks++
	b.mu.Unlock()
}

func (b *routingObserverRecorderTestBackend) MarkAttemptGap() {
	b.mu.Lock()
	b.attemptGapMarks++
	b.mu.Unlock()
}

type routingObserverAtomicHandoffCache struct {
	*helperConcurrencyCacheStub
	result service.AccountSlotHandoffAcquireResult
}

type routingObserverPathHandoffCache struct {
	*helperConcurrencyCacheStub
	resultMu sync.Mutex
	results  []service.AccountSlotHandoffAcquireResult
}

func (c *routingObserverPathHandoffCache) AcquireAccountSlotWithHandoff(
	context.Context,
	int64,
	int64,
	int,
	string,
) (service.AccountSlotHandoffAcquireResult, error) {
	c.resultMu.Lock()
	defer c.resultMu.Unlock()
	if len(c.results) == 0 {
		return service.AccountSlotHandoffAcquireResult{}, errors.New("unexpected handoff acquire")
	}
	result := c.results[0]
	c.results = c.results[1:]
	return result, nil
}

func (c *routingObserverAtomicHandoffCache) AcquireAccountSlotWithHandoff(
	context.Context,
	int64,
	int64,
	int,
	string,
) (service.AccountSlotHandoffAcquireResult, error) {
	return c.result, nil
}

func TestNormalizeRoutingObserverAttemptUsesTypedFieldsOnly(t *testing.T) {
	tests := []struct {
		name     string
		result   *service.OpenAIForwardResult
		err      error
		complete bool
		stage    service.GatewayFailureStage
		scope    service.GatewayFailureScope
		next     service.NextAccountAction
		outcome  RoutingOutcome
	}{
		{name: "success", result: &service.OpenAIForwardResult{}, complete: true, outcome: RoutingOutcomeSuccess},
		{
			name: "documented legacy zero stage and action",
			err: &service.UpstreamFailoverError{
				Scope:  service.GatewayFailureScopeAccount,
				Reason: service.GatewayFailureReason("account_capacity"),
			},
			complete: true, stage: service.GatewayFailureStageInference,
			scope: service.GatewayFailureScopeAccount, next: service.NextAccountRetry,
			outcome: RoutingOutcomeFailure,
		},
		{
			name: "explicit credential stop",
			err: &service.UpstreamFailoverError{
				Stage:             service.GatewayFailureStageAccountAuth,
				Scope:             service.GatewayFailureScopeRequest,
				Reason:            service.GatewayFailureReason("request_credential"),
				NextAccountAction: service.NextAccountStop,
			},
			complete: true, stage: service.GatewayFailureStageAccountAuth,
			scope: service.GatewayFailureScopeRequest, next: service.NextAccountStop,
			outcome: RoutingOutcomeFailure,
		},
		{
			name:  "status and body cannot fill scope or reason",
			err:   &service.UpstreamFailoverError{StatusCode: http.StatusGatewayTimeout, ResponseBody: []byte(`{"error":"upstream"}`)},
			stage: service.GatewayFailureStageInference, next: service.NextAccountRetry,
			outcome: RoutingOutcomeFailure,
		},
		{name: "untyped error", err: errors.New("network failed"), outcome: RoutingOutcomeFailure},
		{
			name:    "terminal event without typed error",
			result:  &service.OpenAIForwardResult{OpenAIWSMode: true, UpstreamTerminalEvent: "response.failed"},
			outcome: RoutingOutcomeFailure,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := normalizeRoutingObserverAttempt(test.result, test.err)
			require.Equal(t, test.complete, got.complete)
			require.Equal(t, test.outcome, got.outcome)
			require.Equal(t, test.stage, got.stage)
			require.Equal(t, test.scope, got.scope)
			require.Equal(t, test.next, got.nextAccount)
		})
	}
}

func TestRoutingObserverRecorderBuildsCompleteTypedFailoverAndClearsRawIdentity(t *testing.T) {
	backend := newRoutingObserverRecorderTestBackend(t)
	recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
	require.NotNil(t, recorder)
	require.NotEmpty(t, recorder.logicalRequestID)

	failure := &service.UpstreamFailoverError{
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("account_capacity"),
		NextAccountAction: service.NextAccountRetry,
	}
	recorder.record(101, nil, failure, time.Unix(1, 0))
	predecessor := recorder.prepareFailover(101, failure)
	require.Equal(t, int64(101), predecessor)

	tracker := service.NewAccountSlotHandoffTracker()
	require.True(t, tracker.SetPredecessor(predecessor))
	cache := &routingObserverAtomicHandoffCache{
		helperConcurrencyCacheStub: &helperConcurrencyCacheStub{},
		result: service.AccountSlotHandoffAcquireResult{
			Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1,
			RedisUnix: 2,
		},
	}
	ctx := service.ContextWithAccountSlotHandoffTracker(context.Background(), tracker)
	acquire, err := service.NewConcurrencyService(cache).AcquireAccountSlot(ctx, 102, 1)
	require.NoError(t, err)
	require.True(t, acquire.Acquired)
	recorder.captureHandoff(tracker, 102)
	recorder.record(102, &service.OpenAIForwardResult{}, nil, time.Unix(3, 0))
	recorder.finish(true)
	acquire.ReleaseFunc()

	require.Empty(t, recorder.logicalRequestID)
	require.Len(t, backend.submitted, 1)
	fact := backend.submitted[0]
	require.Len(t, fact.Attempts, 2)
	require.False(t, fact.Attempts[0].Final)
	require.True(t, fact.Attempts[1].Final)
	require.NotNil(t, fact.Handoff)
	require.True(t, fact.Handoff.Complete)
	require.Equal(t, 0, fact.Handoff.PrimaryConcurrency)
	require.Equal(t, 1, fact.Handoff.FallbackConcurrency)
	require.NotContains(t, string(mustRoutingObserverJSON(t, fact)), "logical_request_id")

	decision := NewDefaultRoutingPolicyRegistry()
	validated, err := decision.ValidateAndLoad(backend.scope.Policy)
	require.NoError(t, err)
	require.NotEmpty(t, validated.Hash)
	result := decision.Evaluate(backend.scope, fact)
	require.NotNil(t, result.Winner)
	require.Equal(t, RoutingCriticalFailureRuleV1, result.Winner.RuleID)
}

func TestRoutingObserverRecorderBoundsCancelDriftAndAttribution(t *testing.T) {
	t.Run("64 and 65 attempts", func(t *testing.T) {
		backend := newRoutingObserverRecorderTestBackend(t)
		recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
		for index := 0; index < 65; index++ {
			recorder.record(101, &service.OpenAIForwardResult{}, nil, time.Unix(int64(index+1), 0))
		}
		recorder.finish(true)
		require.Len(t, backend.submitted, 1)
		require.Len(t, backend.submitted[0].Attempts, 64)
		require.True(t, backend.submitted[0].Gap)
		finals := 0
		for _, attempt := range backend.submitted[0].Attempts {
			if attempt.Final {
				finals++
			}
		}
		require.Equal(t, 1, finals)
		require.True(t, backend.submitted[0].Attempts[63].Final)
		require.Equal(t, 1, backend.attemptGapMarks)
	})

	t.Run("client cancel", func(t *testing.T) {
		backend := newRoutingObserverRecorderTestBackend(t)
		recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
		recorder.record(101, &service.OpenAIForwardResult{}, nil, time.Unix(1, 0))
		recorder.finish(false)
		require.Empty(t, backend.submitted)
		require.Empty(t, recorder.logicalRequestID)
	})

	t.Run("scope drift", func(t *testing.T) {
		backend := newRoutingObserverRecorderTestBackend(t)
		backend.current = false
		recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
		recorder.record(101, &service.OpenAIForwardResult{}, nil, time.Unix(1, 0))
		recorder.finish(true)
		require.Empty(t, backend.submitted)
		require.Equal(t, 1, backend.driftMarks)
	})

	t.Run("account attribution", func(t *testing.T) {
		backend := newRoutingObserverRecorderTestBackend(t)
		recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
		recorder.record(999, &service.OpenAIForwardResult{}, nil, time.Unix(1, 0))
		recorder.finish(true)
		require.Empty(t, backend.submitted)
		require.Equal(t, 1, backend.attributionMarks)
	})
}

func TestRoutingObserverWebSocketRecorderCarriesFirstTurnFailoverAndClosesLaterTurns(t *testing.T) {
	backend := newRoutingObserverRecorderTestBackend(t)
	recorder := newRoutingObserverWebSocketRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
	require.NotNil(t, recorder)
	failure := &service.UpstreamFailoverError{
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("websocket_account_failure"),
		NextAccountAction: service.NextAccountRetry,
	}
	recorder.record(1, 101, nil, failure, time.Unix(1, 0))
	predecessor := recorder.prepareFailover(101, failure)
	require.Equal(t, int64(101), predecessor)
	require.True(t, recorder.handoffTracker().SetPredecessor(predecessor))

	cache := &routingObserverAtomicHandoffCache{
		helperConcurrencyCacheStub: &helperConcurrencyCacheStub{},
		result: service.AccountSlotHandoffAcquireResult{
			Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1, RedisUnix: 2,
		},
	}
	ctx := service.ContextWithAccountSlotHandoffTracker(context.Background(), recorder.handoffTracker())
	acquire, err := service.NewConcurrencyService(cache).AcquireAccountSlot(ctx, 102, 1)
	require.NoError(t, err)
	require.True(t, acquire.Acquired)
	recorder.captureHandoff(102)
	recorder.record(1, 102, &service.OpenAIForwardResult{}, nil, time.Unix(3, 0))
	acquire.ReleaseFunc()

	require.Len(t, backend.submitted, 1)
	require.Len(t, backend.submitted[0].Attempts, 2)
	require.NotNil(t, backend.submitted[0].Handoff)
	require.True(t, backend.submitted[0].Handoff.Complete)

	// A later ordinary turn is a separate logical request and cannot inherit the
	// first turn's predecessor generation.
	recorder.record(2, 102, &service.OpenAIForwardResult{}, nil, time.Unix(4, 0))
	require.Len(t, backend.submitted, 2)
	require.Len(t, backend.submitted[1].Attempts, 1)
	require.Nil(t, backend.submitted[1].Handoff)
	require.True(t, backend.submitted[1].Attempts[0].Final)
}

func TestRoutingObserverWebSocketRecorderCreatesOneRecorderPerConcurrentTurn(t *testing.T) {
	backend := newRoutingObserverRecorderTestBackend(t)
	recorder := newRoutingObserverWebSocketRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
	require.NotNil(t, recorder)
	t.Cleanup(recorder.discard)

	const callers = 32
	recorders := make([]*routingObserverRecorder, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := range recorders {
		go func() {
			defer wait.Done()
			recorders[index] = recorder.recorderForTurn(2, "gpt-5.6-sol")
		}()
	}
	wait.Wait()

	for _, got := range recorders {
		require.Same(t, recorders[0], got)
	}
	backend.mu.Lock()
	beginCalls := backend.beginCalls
	backend.mu.Unlock()
	require.Equal(t, 2, beginCalls, "turn one and turn two must each consume the scope gate exactly once")
}

func TestRoutingObserverWebSocketRecorderCapturesCredentialFailoverWithoutAfterTurn(t *testing.T) {
	backend := newRoutingObserverRecorderTestBackend(t)
	recorder := newRoutingObserverWebSocketRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
	failure := &service.UpstreamFailoverError{
		Stage:             service.GatewayFailureStageAccountAuth,
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("credential_revoked"),
		NextAccountAction: service.NextAccountRetry,
	}
	predecessor := recorder.prepareFailover(101, failure)
	require.Equal(t, int64(101), predecessor)
	require.True(t, recorder.handoffTracker().SetPredecessor(predecessor))

	cache := &routingObserverAtomicHandoffCache{
		helperConcurrencyCacheStub: &helperConcurrencyCacheStub{},
		result: service.AccountSlotHandoffAcquireResult{
			Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1, RedisUnix: 2,
		},
	}
	ctx := service.ContextWithAccountSlotHandoffTracker(context.Background(), recorder.handoffTracker())
	acquire, err := service.NewConcurrencyService(cache).AcquireAccountSlot(ctx, 102, 1)
	require.NoError(t, err)
	require.True(t, acquire.Acquired)
	recorder.captureHandoff(102)
	recorder.record(1, 102, &service.OpenAIForwardResult{}, nil, time.Unix(3, 0))
	acquire.ReleaseFunc()

	require.Len(t, backend.submitted, 1)
	require.Equal(t, service.GatewayFailureStageAccountAuth, backend.submitted[0].Attempts[0].Stage)
	require.Equal(t, service.GatewayFailureReason("credential_revoked"), backend.submitted[0].Attempts[0].Reason)
}

func TestFailoverHandoffCoversPreAcquiredFastAndWaitAccountSlotPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	failure := &service.UpstreamFailoverError{
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("primary_failed"),
		NextAccountAction: service.NextAccountRetry,
	}
	tests := []struct {
		name       string
		preAcquire bool
		results    []service.AccountSlotHandoffAcquireResult
	}{
		{
			name:       "scheduler pre-acquired",
			preAcquire: true,
			results: []service.AccountSlotHandoffAcquireResult{{
				Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1, RedisUnix: 2,
			}},
		},
		{
			name: "handler fast acquire",
			results: []service.AccountSlotHandoffAcquireResult{{
				Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1, RedisUnix: 2,
			}},
		},
		{
			name: "handler wait acquire",
			results: []service.AccountSlotHandoffAcquireResult{
				{Acquired: false, PredecessorConcurrency: 0, FallbackConcurrency: 0, RedisUnix: 1},
				{Acquired: false, PredecessorConcurrency: 0, FallbackConcurrency: 0, RedisUnix: 1},
				{Acquired: true, PredecessorConcurrency: 0, FallbackConcurrency: 1, RedisUnix: 2},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			backend := newRoutingObserverRecorderTestBackend(t)
			recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
			recorder.record(101, nil, failure, time.Unix(1, 0))
			predecessor := recorder.prepareFailover(101, failure)
			tracker := service.NewAccountSlotHandoffTracker()
			require.True(t, tracker.SetPredecessor(predecessor))

			cache := &routingObserverPathHandoffCache{
				helperConcurrencyCacheStub: &helperConcurrencyCacheStub{},
				results:                    append([]service.AccountSlotHandoffAcquireResult(nil), test.results...),
			}
			concurrencyService := service.NewConcurrencyService(cache)
			handler := &OpenAIGatewayHandler{
				gatewayService:    &service.OpenAIGatewayService{},
				concurrencyHelper: NewConcurrencyHelper(concurrencyService, SSEPingFormatComment, 0),
			}
			requestContext := service.ContextWithAccountSlotHandoffTracker(context.Background(), tracker)
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(requestContext)
			account := &service.Account{ID: 102, Concurrency: 1}
			selection := &service.AccountSelectionResult{
				Account:  account,
				WaitPlan: &service.AccountWaitPlan{AccountID: 102, MaxConcurrency: 1, Timeout: time.Second, MaxWaiting: 1},
			}
			if test.preAcquire {
				acquire, err := concurrencyService.AcquireAccountSlot(requestContext, 102, 1)
				require.NoError(t, err)
				require.True(t, acquire.Acquired)
				selection.Acquired = true
				selection.ReleaseFunc = acquire.ReleaseFunc
			}
			streamStarted := false
			release, result := handler.acquireResponsesAccountSlot(c, nil, "", selection, false, &streamStarted, zap.NewNop())
			require.Equal(t, openAISlotAcquireOK, result)
			require.NotNil(t, release)
			recorder.captureHandoff(tracker, 102)
			recorder.record(102, &service.OpenAIForwardResult{}, nil, time.Unix(3, 0))
			recorder.finish(true)
			release()

			require.Len(t, backend.submitted, 1)
			require.NotNil(t, backend.submitted[0].Handoff)
			require.True(t, backend.submitted[0].Handoff.Complete)
			require.Equal(t, 0, backend.submitted[0].Handoff.PrimaryConcurrency)
			require.Equal(t, 1, backend.submitted[0].Handoff.FallbackConcurrency)
			require.Empty(t, cache.results)
		})
	}
}

func TestRoutingObserverScopeOriginGateAndDynamicCorrelationHeader(t *testing.T) {
	nonce := strings.Repeat("A", routingCanaryNonceEncodedLength)
	decodedRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	decodedRequest.Header.Set(routingCanaryCorrelationHeader, nonce)
	parsedNonce, present, status, err := consumeRoutingCorrelationNonce(decodedRequest)
	require.NoError(t, err)
	require.True(t, present)
	require.Zero(t, status)
	correlation := routingCorrelationFromNonce(401, parsedNonce)

	observer := newRoutingObserverWithDependencies(routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid"), nil, &routingObserverTestTransport{})
	t.Cleanup(observer.Close)
	request := routingObserverScopeRequest("scope-canary", 0, "", true)
	request.Scope.TrafficOrigin.CanaryAPIKeyIDs = []int64{401}
	request.Scope.TrafficOrigin.CanaryLoopIDHash = "sha256:" + correlation.CorrelationSHA256
	request.Scope.TrafficOrigin.CanaryMaxLogicalRequest = 2
	readback, err := observer.PutScope(31, "gpt-5.6-sol", request)
	require.NoError(t, err)

	require.True(t, observer.CanAuthorizeCanary(31, 401, correlation.CorrelationSHA256))
	require.False(t, observer.CanAuthorizeCanary(31, 401, strings.Repeat("b", 64)))
	_, _, reason, accepted := observer.BeginScopedRequest(31, "gpt-5.6-luna", 301, "")
	require.False(t, accepted)
	require.Equal(t, "unmanaged_scope", reason)
	_, _, reason, accepted = observer.BeginScopedRequest(31, "gpt-5.6-sol", 201, "")
	require.False(t, accepted)
	require.Equal(t, "monitor_traffic", reason)
	_, origin, _, accepted := observer.BeginScopedRequest(31, "gpt-5.6-sol", 301, "")
	require.True(t, accepted)
	require.Equal(t, RoutingTrafficOriginUser, origin)
	for index := 0; index < 2; index++ {
		_, origin, reason, accepted = observer.BeginScopedRequest(31, "gpt-5.6-sol", 401, correlation.CorrelationSHA256)
		require.True(t, accepted)
		require.Equal(t, RoutingTrafficOriginUserCanary, origin)
		require.Equal(t, "eligible_user_canary", reason)
	}
	_, _, reason, accepted = observer.BeginScopedRequest(31, "gpt-5.6-sol", 401, correlation.CorrelationSHA256)
	require.False(t, accepted)
	require.Equal(t, "canary_request_budget_exhausted", reason)

	groupID := int64(31)
	apiKey := &service.APIKey{ID: 401, GroupID: &groupID}
	gatewayRequest := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	gatewayRequest.Header.Set(routingCanaryCorrelationHeader, nonce)
	got, status, err := consumeRoutingGatewayCorrelation(gatewayRequest, apiKey, observer)
	require.NoError(t, err)
	require.Zero(t, status)
	require.Equal(t, correlation.CorrelationSHA256, got.CorrelationSHA256)
	require.Empty(t, gatewayRequest.Header.Values(routingCanaryCorrelationHeader))

	scope, ok := observer.LookupScope(31, "gpt-5.6-sol")
	require.True(t, ok)
	require.True(t, observer.ScopeStillCurrent(scope))
	update := routingObserverScopeRequest("scope-canary-route-update", readback.Revision, readback.ScopeHash, true)
	update.Scope.TrafficOrigin = cloneRoutingTrafficOrigin(request.Scope.TrafficOrigin)
	update.Scope.RouteVersion++
	_, err = observer.PutScope(31, "gpt-5.6-sol", update)
	require.NoError(t, err)
	require.False(t, observer.ScopeStillCurrent(scope))
}

func TestRoutingObserverRecorderCandidateServingAgainstStaleScopeFailsClosed(t *testing.T) {
	nonce := strings.Repeat("B", routingCanaryNonceEncodedLength)
	correlation := routingCorrelationFromNonce(401, nonce)
	observer := newRoutingObserverWithDependencies(
		routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid"),
		nil,
		&routingObserverTestTransport{},
	)
	t.Cleanup(observer.Close)

	request := routingObserverScopeRequest("scope-before-replacement", 0, "", true)
	request.Scope.Roles.CandidateAccountIDs = nil
	request.Scope.TrafficOrigin.CanaryAPIKeyIDs = []int64{401}
	request.Scope.TrafficOrigin.CanaryLoopIDHash = "sha256:" + correlation.CorrelationSHA256
	request.Scope.TrafficOrigin.CanaryMaxLogicalRequest = 1
	_, err := observer.PutScope(31, "gpt-5.6-sol", request)
	require.NoError(t, err)
	require.True(t, observer.Health().Ready)

	recorder := newRoutingObserverRecorder(observer, 31, "gpt-5.6-sol", 401, correlation)
	require.NotNil(t, recorder)
	recorder.record(103, &service.OpenAIForwardResult{}, nil, time.Unix(1, 0))
	recorder.finish(true)

	health := observer.Health()
	require.False(t, health.Ready)
	require.Contains(t, health.ReasonCodes, routingObserverReasonAttributionGap)
	require.Zero(t, health.PendingOutboxCount)
}

func TestRoutingObserverRecorderFixtureExactSeventeenIgnoredThreeEligible(t *testing.T) {
	payload, err := os.ReadFile("testdata/routing_observer/failure-v1.json")
	require.NoError(t, err)
	var fixture struct {
		Items []struct {
			FixtureID string `json:"fixture_id"`
			Category  string `json:"category"`
			APIKeyID  int64  `json:"api_key_id"`
			Model     string `json:"model"`
			Expected  string `json:"expected"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(payload, &fixture))
	transport := &routingObserverTestTransport{}
	observer := newRoutingObserverWithDependencies(routingObserverRuntimeTestConfig(t.TempDir(), "http://panel.invalid"), nil, transport)
	t.Cleanup(observer.Close)
	_, err = observer.PutScope(31, "gpt-5.6-sol", routingObserverScopeRequest("fixture-scope", 0, "", true))
	require.NoError(t, err)

	ignored, eligible := 0, 0
	for _, item := range fixture.Items {
		var recorder *routingObserverRecorder
		if item.Category != "pre_upstream" {
			recorder = newRoutingObserverRecorder(observer, 31, item.Model, item.APIKeyID, routingAttemptCorrelation{})
		}
		if item.Expected == "ignored" {
			ignored++
			require.Nil(t, recorder, item.FixtureID)
			continue
		}
		eligible++
		require.NotNil(t, recorder, item.FixtureID)
		recorder.record(101, nil, &service.UpstreamFailoverError{
			Scope:             service.GatewayFailureScopeAccount,
			Reason:            service.GatewayFailureReason("fixture_account_failure"),
			NextAccountAction: service.NextAccountRetry,
		}, time.Unix(int64(eligible), 0))
		recorder.finish(true)
	}
	require.Equal(t, 17, ignored)
	require.Equal(t, 3, eligible)
	require.Eventually(t, func() bool { return observer.Health().QueueDepth == 0 }, time.Second, 10*time.Millisecond)
	require.Zero(t, transport.calls.Load())
	require.Zero(t, observer.Health().PendingOutboxCount)
}

func newRoutingObserverRecorderTestBackend(t *testing.T) *routingObserverRecorderTestBackend {
	t.Helper()
	registry := NewDefaultRoutingPolicyRegistry()
	scope := routingObserverTestScope(DefaultRoutingFailurePolicy())
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	scope.ScopeHash = scopeHash
	return &routingObserverRecorderTestBackend{scope: scope, accepted: true, current: true}
}

func mustRoutingObserverJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	require.NoError(t, err)
	return payload
}
