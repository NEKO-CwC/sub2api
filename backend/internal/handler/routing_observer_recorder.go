package handler

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const routingObserverRecorderMaxAttempts = 64

type routingObserverRecorderBackend interface {
	BeginScopedRequest(groupID int64, model string, apiKeyID int64, correlationSHA256 string) (RoutingManagedScope, RoutingTrafficOrigin, string, bool)
	ScopeStillCurrent(RoutingManagedScope) bool
	EvidenceDigest(domain, value string) (string, error)
	Submit(RoutingRequestFact) RoutingObserverSubmitResult
	MarkScopeDrift()
	MarkAttributionGap()
	MarkAttemptGap()
}

// routingObserverRecorder is the v3 request-local fact assembler. It is
// deliberately separate from routingAttemptRecorder: the legacy emitter owns
// its compatibility payload/network path, while this recorder can only submit
// the bounded typed DTO consumed by RoutingObserver.
type routingObserverRecorder struct {
	backend            routingObserverRecorderBackend
	scope              RoutingManagedScope
	origin             RoutingTrafficOrigin
	logicalRequestID   string
	attempts           []RoutingAttemptFact
	handoff            *RoutingFailoverHandoffFact
	originalPrimaryID  int64
	gap                bool
	attemptLimitMarked bool
	discarded          bool
	finished           bool
	mu                 sync.Mutex
}

func newRoutingObserverRecorder(
	observer *RoutingObserver,
	groupID int64,
	model string,
	apiKeyID int64,
	correlation routingAttemptCorrelation,
) *routingObserverRecorder {
	if observer == nil {
		return nil
	}
	return newRoutingObserverRecorderWithBackend(observer, groupID, model, apiKeyID, correlation)
}

func newRoutingObserverRecorderWithBackend(
	backend routingObserverRecorderBackend,
	groupID int64,
	model string,
	apiKeyID int64,
	correlation routingAttemptCorrelation,
) *routingObserverRecorder {
	if backend == nil || groupID <= 0 || strings.TrimSpace(model) == "" || apiKeyID <= 0 {
		return nil
	}
	scope, origin, _, accepted := backend.BeginScopedRequest(groupID, strings.TrimSpace(model), apiKeyID, correlation.CorrelationSHA256)
	if !accepted {
		return nil
	}
	return &routingObserverRecorder{
		backend:          backend,
		scope:            scope,
		origin:           origin,
		logicalRequestID: uuid.NewString(),
		attempts:         make([]RoutingAttemptFact, 0, 4),
	}
}

type routingObserverNormalizedAttempt struct {
	outcome     RoutingOutcome
	stage       service.GatewayFailureStage
	scope       service.GatewayFailureScope
	reason      service.GatewayFailureReason
	nextAccount service.NextAccountAction
	complete    bool
}

func normalizeRoutingObserverAttempt(result *service.OpenAIForwardResult, err error) routingObserverNormalizedAttempt {
	if err == nil {
		if result != nil && result.SucceededForScheduling() {
			return routingObserverNormalizedAttempt{outcome: RoutingOutcomeSuccess, complete: true}
		}
		return routingObserverNormalizedAttempt{outcome: RoutingOutcomeFailure}
	}
	var failoverErr *service.UpstreamFailoverError
	if !errors.As(err, &failoverErr) || failoverErr == nil {
		return routingObserverNormalizedAttempt{outcome: RoutingOutcomeFailure}
	}
	stage := failoverErr.Stage
	if stage == "" {
		// GatewayFailureStage documents the legacy zero value as inference.
		stage = service.GatewayFailureStageInference
	}
	nextAccount := failoverErr.NextAccountAction
	if nextAccount == service.NextAccountLegacyRetry {
		// NextAccountAction documents the legacy zero value as retry.
		nextAccount = service.NextAccountRetry
	}
	normalized := routingObserverNormalizedAttempt{
		outcome: RoutingOutcomeFailure, stage: stage, scope: failoverErr.Scope,
		reason: failoverErr.Reason, nextAccount: nextAccount,
	}
	validStage := stage == service.GatewayFailureStageInference || stage == service.GatewayFailureStageAccountAuth
	validScope := failoverErr.Scope == service.GatewayFailureScopeAccount ||
		failoverErr.Scope == service.GatewayFailureScopeProvider ||
		failoverErr.Scope == service.GatewayFailureScopeRequest
	validAction := nextAccount == service.NextAccountRetry || nextAccount == service.NextAccountStop
	normalized.complete = validStage && validScope && strings.TrimSpace(string(failoverErr.Reason)) != "" && validAction
	return normalized
}

func (r *routingObserverRecorder) record(accountID int64, result *service.OpenAIForwardResult, err error, observedAt time.Time) {
	if r == nil || accountID <= 0 {
		return
	}
	r.mu.Lock()
	if r.discarded || r.finished {
		r.mu.Unlock()
		return
	}
	if len(r.attempts) >= routingObserverRecorderMaxAttempts {
		r.gap = true
		markGap := !r.attemptLimitMarked
		r.attemptLimitMarked = true
		r.mu.Unlock()
		if markGap {
			r.backend.MarkAttemptGap()
		}
		return
	}
	role, ok := r.scope.RoleForAccount(accountID)
	if !ok {
		r.discarded = true
		r.attempts = nil
		r.logicalRequestID = ""
		backend := r.backend
		r.mu.Unlock()
		backend.MarkAttributionGap()
		return
	}
	normalized := normalizeRoutingObserverAttempt(result, err)
	if !normalized.complete {
		r.gap = true
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
		r.gap = true
	} else {
		observedAt = observedAt.UTC()
	}
	index := len(r.attempts) + 1
	ttft := routingObserverTTFT(result)
	value := strings.Join([]string{
		r.logicalRequestID,
		strconv.Itoa(index),
		strconv.FormatInt(accountID, 10),
		string(role),
		string(normalized.outcome),
		string(normalized.stage),
		string(normalized.scope),
		string(normalized.reason),
		strconv.Itoa(int(normalized.nextAccount)),
		observedAt.Format(time.RFC3339Nano),
		routingObserverOptionalInt(ttft),
	}, "\x00")
	digest, digestErr := r.backend.EvidenceDigest("routing-request-attempt.v1", value)
	if digestErr != nil {
		r.discarded = true
		r.attempts = nil
		r.logicalRequestID = ""
		r.mu.Unlock()
		return
	}
	r.attempts = append(r.attempts, RoutingAttemptFact{
		AccountID: accountID, AccountRole: role, AttemptIndex: index,
		Outcome: normalized.outcome, Stage: normalized.stage, Scope: normalized.scope,
		Reason: normalized.reason, NextAccount: normalized.nextAccount,
		ObservedAt: observedAt, TTFTMillis: ttft, EvidenceDigest: digest,
	})
	r.mu.Unlock()
}

func routingObserverTTFT(result *service.OpenAIForwardResult) *int {
	if result == nil || result.FirstTokenMs == nil {
		return nil
	}
	value := *result.FirstTokenMs
	return &value
}

func routingObserverOptionalInt(value *int) string {
	if value == nil {
		return ""
	}
	return strconv.Itoa(*value)
}

// prepareFailover freezes the original primary only when the business path has
// committed to selecting another account. Same-account retries must not call
// this method.
func (r *routingObserverRecorder) prepareFailover(accountID int64, err error) int64 {
	if r == nil || accountID <= 0 {
		return 0
	}
	var failoverErr *service.UpstreamFailoverError
	if !errors.As(err, &failoverErr) || failoverErr == nil || !failoverErr.ShouldRetryNextAccount() {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.discarded || r.finished {
		return 0
	}
	role, ok := r.scope.RoleForAccount(accountID)
	if !ok {
		return 0
	}
	if r.originalPrimaryID == 0 && role == RoutingAccountRolePrimary {
		r.originalPrimaryID = accountID
	}
	return r.originalPrimaryID
}

func (r *routingObserverRecorder) captureHandoff(tracker *service.AccountSlotHandoffTracker, fallbackAccountID int64) {
	if r == nil || fallbackAccountID <= 0 {
		return
	}
	r.mu.Lock()
	if r.discarded || r.finished || r.originalPrimaryID <= 0 || fallbackAccountID == r.originalPrimaryID {
		r.mu.Unlock()
		return
	}
	originalPrimaryID := r.originalPrimaryID
	r.mu.Unlock()

	evidence, ok := tracker.Take(fallbackAccountID)
	if !ok {
		evidence = service.AccountSlotHandoffEvidence{
			PredecessorAccountID:   originalPrimaryID,
			FallbackAccountID:      fallbackAccountID,
			PredecessorConcurrency: -1,
			FallbackConcurrency:    -1,
			Complete:               false,
			ReasonCode:             "atomic_handoff_evidence_missing",
		}
	}
	complete := evidence.Complete &&
		evidence.PredecessorAccountID == originalPrimaryID &&
		evidence.FallbackAccountID == fallbackAccountID &&
		evidence.PredecessorConcurrency >= 0 && evidence.FallbackConcurrency >= 0 &&
		strings.TrimSpace(evidence.WindowIdentity) != "" && !evidence.ObservedAt.IsZero()
	r.mu.Lock()
	if !r.discarded && !r.finished {
		r.handoff = &RoutingFailoverHandoffFact{
			OriginalPrimaryAccountID: originalPrimaryID,
			FallbackAccountID:        fallbackAccountID,
			PrimaryConcurrency:       evidence.PredecessorConcurrency,
			FallbackConcurrency:      evidence.FallbackConcurrency,
			WindowIdentity:           evidence.WindowIdentity,
			ObservedAt:               evidence.ObservedAt.UTC(),
			Complete:                 complete,
		}
	}
	r.mu.Unlock()
}

func (r *routingObserverRecorder) finish(clientPresent bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.finished {
		r.mu.Unlock()
		return
	}
	r.finished = true
	if !clientPresent || r.discarded || len(r.attempts) == 0 {
		r.discarded = true
		r.attempts = nil
		r.logicalRequestID = ""
		r.mu.Unlock()
		return
	}
	for index := range r.attempts {
		r.attempts[index].Final = index == len(r.attempts)-1
	}
	observedAt := r.attempts[len(r.attempts)-1].ObservedAt
	fact := RoutingRequestFact{
		ObservedAt:          observedAt,
		Sub2APIInstanceID:   r.scope.Sub2APIInstanceID,
		ScopeRevision:       r.scope.ScopeRevision,
		ScopeHash:           r.scope.ScopeHash,
		RouteVersion:        r.scope.RouteVersion,
		TopologyFingerprint: r.scope.TopologyFingerprint,
		GroupID:             r.scope.GroupID,
		CanonicalModel:      r.scope.CanonicalModel,
		TrafficOrigin:       r.origin,
		Attempts:            append([]RoutingAttemptFact(nil), r.attempts...),
		Gap:                 r.gap,
	}
	if r.handoff != nil {
		handoff := *r.handoff
		fact.Handoff = &handoff
	}
	// Clear the only raw logical identifier before crossing the observer API.
	r.logicalRequestID = ""
	backend := r.backend
	scope := cloneRoutingManagedScope(r.scope)
	r.mu.Unlock()

	if !backend.ScopeStillCurrent(scope) {
		backend.MarkScopeDrift()
		return
	}
	backend.Submit(fact)
}

func (r *routingObserverRecorder) discard() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.discarded = true
	r.attempts = nil
	r.logicalRequestID = ""
	r.mu.Unlock()
}

func (r *routingObserverRecorder) hasLastFailure(accountID int64) bool {
	if r == nil || accountID <= 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.discarded || r.finished || len(r.attempts) == 0 {
		return false
	}
	last := r.attempts[len(r.attempts)-1]
	return last.AccountID == accountID && last.Outcome == RoutingOutcomeFailure
}

type routingObserverWebSocketRecorder struct {
	backend            routingObserverRecorderBackend
	groupID            int64
	initialModel       string
	apiKeyID           int64
	correlation        routingAttemptCorrelation
	tracker            *service.AccountSlotHandoffTracker
	mu                 sync.Mutex
	turns              map[int]*routingObserverRecorder
	activeFailoverTurn int
}

func newRoutingObserverWebSocketRecorder(
	observer *RoutingObserver,
	groupID int64,
	model string,
	apiKeyID int64,
	correlation routingAttemptCorrelation,
) *routingObserverWebSocketRecorder {
	if observer == nil {
		return nil
	}
	return newRoutingObserverWebSocketRecorderWithBackend(observer, groupID, model, apiKeyID, correlation)
}

func newRoutingObserverWebSocketRecorderWithBackend(
	backend routingObserverRecorderBackend,
	groupID int64,
	model string,
	apiKeyID int64,
	correlation routingAttemptCorrelation,
) *routingObserverWebSocketRecorder {
	first := newRoutingObserverRecorderWithBackend(backend, groupID, model, apiKeyID, correlation)
	if first == nil {
		return nil
	}
	return &routingObserverWebSocketRecorder{
		backend: backend, groupID: groupID, initialModel: strings.TrimSpace(model), apiKeyID: apiKeyID,
		correlation: correlation, tracker: service.NewAccountSlotHandoffTracker(),
		turns: map[int]*routingObserverRecorder{1: first},
	}
}

func (r *routingObserverWebSocketRecorder) handoffTracker() *service.AccountSlotHandoffTracker {
	if r == nil {
		return nil
	}
	return r.tracker
}

func (r *routingObserverWebSocketRecorder) recorderForTurn(turn int, model string) *routingObserverRecorder {
	if r == nil || turn <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if recorder := r.turns[turn]; recorder != nil {
		return recorder
	}
	if strings.TrimSpace(model) == "" {
		model = r.initialModel
	}
	recorder := newRoutingObserverRecorderWithBackend(r.backend, r.groupID, model, r.apiKeyID, r.correlation)
	if recorder == nil {
		return nil
	}
	r.turns[turn] = recorder
	return recorder
}

func (r *routingObserverWebSocketRecorder) record(
	turn int,
	accountID int64,
	result *service.OpenAIForwardResult,
	err error,
	observedAt time.Time,
) {
	if r == nil || turn <= 0 || accountID <= 0 {
		return
	}
	model := r.initialModel
	if result != nil && strings.TrimSpace(result.Model) != "" {
		model = strings.TrimSpace(result.Model)
	}
	recorder := r.recorderForTurn(turn, model)
	if recorder == nil {
		return
	}
	recorder.record(accountID, result, err, observedAt)
	if routingAttemptWillRetryAnotherAccount(err) {
		r.mu.Lock()
		r.activeFailoverTurn = turn
		r.mu.Unlock()
		return
	}
	recorder.finish(true)
	r.mu.Lock()
	delete(r.turns, turn)
	if r.activeFailoverTurn == turn {
		r.activeFailoverTurn = 0
	}
	r.mu.Unlock()
	r.tracker.ClearPredecessor()
}

func (r *routingObserverWebSocketRecorder) prepareFailover(accountID int64, err error) int64 {
	if r == nil || accountID <= 0 {
		return 0
	}
	r.mu.Lock()
	turn := r.activeFailoverTurn
	if turn <= 0 {
		turn = 1
	}
	r.mu.Unlock()
	recorder := r.recorderForTurn(turn, r.initialModel)
	if recorder == nil {
		return 0
	}
	if !recorder.hasLastFailure(accountID) {
		recorder.record(accountID, nil, err, time.Now().UTC())
	}
	r.mu.Lock()
	r.activeFailoverTurn = turn
	r.mu.Unlock()
	return recorder.prepareFailover(accountID, err)
}

func (r *routingObserverWebSocketRecorder) captureHandoff(fallbackAccountID int64) {
	if r == nil || fallbackAccountID <= 0 {
		return
	}
	r.mu.Lock()
	turn := r.activeFailoverTurn
	if turn <= 0 {
		turn = 1
	}
	recorder := r.turns[turn]
	r.mu.Unlock()
	if recorder != nil {
		recorder.captureHandoff(r.tracker, fallbackAccountID)
	}
}

func (r *routingObserverWebSocketRecorder) finish(clientPresent bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	recorders := make([]*routingObserverRecorder, 0, len(r.turns))
	for turn, recorder := range r.turns {
		recorders = append(recorders, recorder)
		delete(r.turns, turn)
	}
	r.activeFailoverTurn = 0
	r.mu.Unlock()
	for _, recorder := range recorders {
		recorder.finish(clientPresent)
	}
	r.tracker.ClearPredecessor()
}

func (r *routingObserverWebSocketRecorder) discard() {
	if r == nil {
		return
	}
	r.mu.Lock()
	recorders := make([]*routingObserverRecorder, 0, len(r.turns))
	for turn, recorder := range r.turns {
		recorders = append(recorders, recorder)
		delete(r.turns, turn)
	}
	r.activeFailoverTurn = 0
	r.mu.Unlock()
	for _, recorder := range recorders {
		recorder.discard()
	}
	r.tracker.ClearPredecessor()
}

func recordRoutingObserverAttemptIfClientPresent(
	c *gin.Context,
	recorder *routingObserverRecorder,
	accountID int64,
	result *service.OpenAIForwardResult,
	err error,
	observedAt time.Time,
) {
	if recorder == nil {
		return
	}
	if c == nil || c.Request == nil || c.Request.Context().Err() != nil {
		recorder.discard()
		return
	}
	recorder.record(accountID, result, err, observedAt)
}

func finishRoutingObserverRecorderIfClientPresent(c *gin.Context, recorder *routingObserverRecorder) {
	clientPresent := c != nil && c.Request != nil && c.Request.Context().Err() == nil
	recorder.finish(clientPresent)
}

func recordRoutingObserverWebSocketAttemptIfClientPresent(
	c *gin.Context,
	recorder *routingObserverWebSocketRecorder,
	turn int,
	accountID int64,
	result *service.OpenAIForwardResult,
	err error,
	observedAt time.Time,
) {
	if recorder == nil {
		return
	}
	if c == nil || c.Request == nil || c.Request.Context().Err() != nil {
		recorder.discard()
		return
	}
	recorder.record(turn, accountID, result, err, observedAt)
}

func finishRoutingObserverWebSocketRecorderIfClientPresent(c *gin.Context, recorder *routingObserverWebSocketRecorder) {
	clientPresent := c != nil && c.Request != nil && c.Request.Context().Err() == nil
	recorder.finish(clientPresent)
}
