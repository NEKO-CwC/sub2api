package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
)

const (
	RoutingIncidentSignalContractV1        = "routing-incident-signal.v1"
	RoutingIncidentAckContractV1           = "routing-incident-ack.v1"
	RoutingIncidentHookSignatureV1         = "routing-incident-hook.v1"
	RoutingObserverScopeReadbackContractV1 = "routing-observer-scope-readback.v1"
	RoutingObserverScopeDeleteContractV1   = "routing-observer-scope-delete.v1"
	routingIncidentHookPath                = "/api/account-ops/routing/dispatch/incident-hook"
	routingIncidentMaxBodyBytes            = 32 << 10
	routingIncidentMaxResponseBytes        = 64 << 10
	routingObserverAdminMaxBodyBytes       = 64 << 10
	routingObserverReasonQueueGap          = "request_queue_gap"
	routingObserverReasonAttemptGap        = "request_attempt_limit_gap"
	routingObserverReasonStoreUnavailable  = "file_store_unavailable"
	routingObserverReasonStoreCorrupt      = "file_store_corrupt"
	routingObserverReasonDiskFailure       = "disk_outbox_failure"
	routingObserverReasonOutboxCapacity    = "outbox_capacity_exceeded"
	routingObserverReasonScopeCapacity     = "scope_capacity_exceeded"
	routingObserverReasonIdentityConflict  = "identity_payload_conflict"
	routingObserverReasonAckMismatch       = "panel_ack_mismatch"
	routingObserverReasonTransport         = "panel_transport_failure"
	routingObserverReasonHTTPFailure       = "panel_http_failure"
	routingObserverReasonPendingDelivery   = "pending_incident_delivery"
	routingObserverReasonScopeDrift        = "scope_route_drift"
	routingObserverReasonAttributionGap    = "account_attribution_gap"
	routingObserverReasonUntypedFailure    = "untyped_failure_evidence"
	routingObserverReasonConcurrencyGap    = "concurrency_evidence_gap"
	routingObserverReasonShutdownTimeout   = "shutdown_timeout"
)

type RoutingIncidentSignal struct {
	ContractVersion   string                  `json:"contract_version"`
	Sub2APIInstanceID int64                   `json:"sub2api_instance_id"`
	OperationID       string                  `json:"operation_id"`
	Incident          RoutingIncidentSnapshot `json:"incident"`
}

type RoutingIncidentSnapshot struct {
	IncidentID     string                  `json:"incident_id"`
	IdempotencyKey string                  `json:"idempotency_key"`
	State          string                  `json:"state"`
	Scope          RoutingIncidentScope    `json:"scope"`
	Policy         RoutingIncidentPolicy   `json:"policy"`
	Winner         RoutingIncidentWinner   `json:"winner"`
	Window         RoutingIncidentWindow   `json:"window"`
	Evidence       RoutingIncidentEvidence `json:"evidence"`
}

type RoutingIncidentScope struct {
	ScopeRevision       int64                `json:"scope_revision"`
	ScopeHash           string               `json:"scope_hash"`
	GroupID             int64                `json:"group_id"`
	CanonicalModel      string               `json:"canonical_model"`
	TrafficOrigin       RoutingTrafficOrigin `json:"traffic_origin"`
	RouteVersion        int64                `json:"route_version"`
	TopologyFingerprint string               `json:"topology_fingerprint"`
}

type RoutingIncidentPolicy struct {
	PolicyID string `json:"policy_id"`
	Revision int64  `json:"revision"`
	Hash     string `json:"hash"`
}

type RoutingIncidentWinner struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Precedence int    `json:"precedence"`
	Action     string `json:"action"`
	ReasonCode string `json:"reason_code"`
}

type RoutingIncidentWindow struct {
	FirstObservedAt time.Time `json:"first_observed_at"`
	LastObservedAt  time.Time `json:"last_observed_at"`
}

type RoutingIncidentEvidence struct {
	CompleteChainCount          int      `json:"complete_chain_count"`
	OriginalPrimaryFailureCount int      `json:"original_primary_failure_count"`
	FallbackFinalSuccessCount   int      `json:"fallback_final_success_count"`
	PrimaryConcurrency          int      `json:"primary_concurrency"`
	FallbackConcurrency         int      `json:"fallback_concurrency"`
	ChainDigests                []string `json:"chain_digests"`
}

type RoutingIncidentAck struct {
	ContractVersion string `json:"contract_version"`
	IncidentID      string `json:"incident_id"`
	IdempotencyKey  string `json:"idempotency_key"`
	PayloadHash     string `json:"payload_hash"`
	AdmissionState  string `json:"admission_state"`
	Duplicate       bool   `json:"duplicate"`
	RouteVersion    int64  `json:"route_version"`
	PolicyHash      string `json:"policy_hash"`
	RouteIntentID   string `json:"route_intent_id"`
	DispatchRunID   int64  `json:"dispatch_run_id"`
}

type routingIncidentAckEnvelope struct {
	Item RoutingIncidentAck `json:"item"`
}

type RoutingObserverScopeSnapshot struct {
	Enabled             bool                      `json:"enabled"`
	Sub2APIInstanceID   int64                     `json:"sub2api_instance_id"`
	GroupID             int64                     `json:"group_id"`
	CanonicalModel      string                    `json:"canonical_model"`
	ModelAliases        []string                  `json:"model_aliases"`
	RouteVersion        int64                     `json:"route_version"`
	TopologyFingerprint string                    `json:"topology_fingerprint"`
	Roles               RoutingScopeRoles         `json:"roles"`
	TrafficOrigin       RoutingScopeTrafficOrigin `json:"traffic_origin"`
	Policy              RoutingPolicySet          `json:"policy"`
}

type RoutingObserverScopePutRequest struct {
	ContractVersion     string                       `json:"contract_version"`
	OperationID         string                       `json:"operation_id"`
	ExpectedRevision    int64                        `json:"expected_revision"`
	ExpectedCurrentHash string                       `json:"expected_current_hash"`
	Scope               RoutingObserverScopeSnapshot `json:"scope"`
}

type RoutingObserverScopeDeleteRequest struct {
	ContractVersion     string `json:"contract_version"`
	OperationID         string `json:"operation_id"`
	ExpectedCurrentHash string `json:"expected_current_hash"`
}

type RoutingObserverScopeReadback struct {
	ContractVersion       string    `json:"contract_version"`
	OperationID           string    `json:"operation_id"`
	Duplicate             bool      `json:"duplicate"`
	Revision              int64     `json:"revision"`
	ScopeHash             string    `json:"scope_hash"`
	PolicyHash            string    `json:"policy_hash"`
	ReadbackHash          string    `json:"readback_hash"`
	State                 string    `json:"state"`
	GroupID               int64     `json:"group_id"`
	CanonicalModel        string    `json:"canonical_model"`
	RouteVersion          int64     `json:"route_version"`
	TopologyFingerprint   string    `json:"topology_fingerprint"`
	PrimaryAccountCount   int       `json:"primary_account_count"`
	FallbackAccountCount  int       `json:"fallback_account_count"`
	CandidateAccountCount int       `json:"candidate_account_count"`
	MonitorKeyCount       int       `json:"monitor_key_count"`
	CanaryKeyCount        int       `json:"canary_key_count"`
	PendingIncidentCount  int       `json:"pending_incident_count"`
	ConflictCount         int       `json:"conflict_count"`
	StoredAt              time.Time `json:"stored_at"`
}

type RoutingObserverHealth struct {
	Enabled            bool       `json:"enabled"`
	Ready              bool       `json:"ready"`
	Accepting          bool       `json:"accepting"`
	ScopeCount         int        `json:"scope_count"`
	QueueDepth         int        `json:"queue_depth"`
	QueueCapacity      int        `json:"queue_capacity"`
	PendingOutboxCount int        `json:"pending_outbox_count"`
	ConflictCount      uint64     `json:"conflict_count"`
	QueueGapTotal      uint64     `json:"queue_gap_total"`
	AttemptGapTotal    uint64     `json:"attempt_gap_total"`
	MatchedTotal       uint64     `json:"matched_total"`
	DuplicateTotal     uint64     `json:"duplicate_total"`
	OutboxRetryTotal   uint64     `json:"outbox_retry_total"`
	OutboxAckTotal     uint64     `json:"outbox_ack_total"`
	ReasonCodes        []string   `json:"reason_codes"`
	LastAcknowledgedAt *time.Time `json:"last_acknowledged_at,omitempty"`
}

type RoutingObserverSubmitResult struct {
	Accepted bool   `json:"accepted"`
	Gap      bool   `json:"gap"`
	Reason   string `json:"reason,omitempty"`
}

type routingObserverClock interface {
	Now() time.Time
	After(time.Duration) <-chan time.Time
}

type routingObserverRealClock struct{}

func (routingObserverRealClock) Now() time.Time                             { return time.Now().UTC() }
func (routingObserverRealClock) After(delay time.Duration) <-chan time.Time { return time.After(delay) }

type RoutingIncidentTransport interface {
	Deliver(context.Context, routingIncidentOutboxItem) (RoutingIncidentAck, string, error)
}

type routingScopeRuntime struct {
	stored                routingStoredScope
	registry              *RoutingPolicyRegistry
	buckets               [30]routingObserverMinuteBucket
	canaryLogicalRequests int
}

type routingObserverMinuteBucket struct {
	minute       int64
	eligible     uint64
	matched      uint64
	notMatched   uint64
	insufficient uint64
}

type RoutingObserver struct {
	cfg           config.GatewayRoutingObserverConfig
	clock         routingObserverClock
	scopeStore    RoutingManagedScopeStore
	incidentStore RoutingIncidentStore
	transport     RoutingIncidentTransport

	queue         chan RoutingRequestFact
	workerStop    chan struct{}
	workerDone    chan struct{}
	senderWake    chan struct{}
	senderStop    chan struct{}
	senderDone    chan struct{}
	senderContext context.Context
	cancelSender  context.CancelFunc
	closeOnce     sync.Once
	accepting     atomic.Bool
	storeReady    atomic.Bool

	mu              sync.RWMutex
	scopes          map[string]*routingScopeRuntime
	scopeIndex      map[string]string
	latches         map[string]*routingIncidentLatch
	outbox          map[string]*routingIncidentOutboxItem
	degradedReasons map[string]struct{}
	lastAckAt       *time.Time

	queueGapTotal    atomic.Uint64
	attemptGapTotal  atomic.Uint64
	matchedTotal     atomic.Uint64
	duplicateTotal   atomic.Uint64
	retryTotal       atomic.Uint64
	ackTotal         atomic.Uint64
	conflictTotal    atomic.Uint64
	shutdownTimedOut atomic.Bool
}

func NewRoutingObserver(cfg config.GatewayRoutingObserverConfig) *RoutingObserver {
	return newRoutingObserverWithDependencies(cfg, nil, nil)
}

func newRoutingObserverWithDependencies(cfg config.GatewayRoutingObserverConfig, clock routingObserverClock, transport RoutingIncidentTransport) *RoutingObserver {
	if !cfg.Enabled {
		return nil
	}
	if clock == nil {
		clock = routingObserverRealClock{}
	}
	observer := &RoutingObserver{
		cfg:        cfg,
		clock:      clock,
		queue:      make(chan RoutingRequestFact, cfg.QueueSize),
		workerStop: make(chan struct{}), workerDone: make(chan struct{}),
		senderWake: make(chan struct{}, 1), senderStop: make(chan struct{}), senderDone: make(chan struct{}),
		scopes: make(map[string]*routingScopeRuntime), scopeIndex: make(map[string]string),
		latches: make(map[string]*routingIncidentLatch), outbox: make(map[string]*routingIncidentOutboxItem),
		degradedReasons: make(map[string]struct{}),
	}
	observer.senderContext, observer.cancelSender = context.WithCancel(context.Background())
	store, err := newRoutingObserverFileStore(cfg.DataDir)
	if err != nil {
		observer.markDegraded(routingObserverReasonStoreUnavailable)
		close(observer.workerDone)
		close(observer.senderDone)
		return observer
	}
	observer.scopeStore = store
	observer.incidentStore = store
	if transport == nil {
		transport = newRoutingIncidentHTTPTransport(cfg, observer.clock)
	}
	observer.transport = transport
	if err := observer.restore(); err != nil {
		observer.markDegraded(routingObserverReasonStoreCorrupt)
		close(observer.workerDone)
		close(observer.senderDone)
		return observer
	}
	observer.storeReady.Store(true)
	observer.accepting.Store(true)
	go observer.workerLoop()
	go observer.senderLoop()
	if len(observer.outbox) > 0 {
		observer.wakeSender()
	}
	return observer
}

func (o *RoutingObserver) markDegraded(reason string) {
	if o == nil || reason == "" {
		return
	}
	o.mu.Lock()
	o.degradedReasons[reason] = struct{}{}
	o.mu.Unlock()
}

func (o *RoutingObserver) Health() RoutingObserverHealth {
	if o == nil {
		return RoutingObserverHealth{}
	}
	o.mu.RLock()
	reasons := make([]string, 0, len(o.degradedReasons)+2)
	for reason := range o.degradedReasons {
		reasons = append(reasons, reason)
	}
	lastAck := o.lastAckAt
	if lastAck != nil {
		copyValue := *lastAck
		lastAck = &copyValue
	}
	scopeCount := len(o.scopes)
	pendingCount := len(o.outbox)
	o.mu.RUnlock()
	if o.queueGapTotal.Load() > 0 {
		reasons = append(reasons, routingObserverReasonQueueGap)
	}
	if o.attemptGapTotal.Load() > 0 {
		reasons = append(reasons, routingObserverReasonAttemptGap)
	}
	if pendingCount > 0 {
		reasons = append(reasons, routingObserverReasonPendingDelivery)
	}
	if o.shutdownTimedOut.Load() {
		reasons = append(reasons, routingObserverReasonShutdownTimeout)
	}
	sort.Strings(reasons)
	reasons = compactRoutingReasons(reasons)
	accepting := o.accepting.Load()
	return RoutingObserverHealth{
		Enabled: true, Ready: o.storeReady.Load() && accepting && pendingCount == 0 && len(reasons) == 0, Accepting: accepting,
		ScopeCount: scopeCount, QueueDepth: len(o.queue), QueueCapacity: cap(o.queue), PendingOutboxCount: pendingCount,
		ConflictCount: o.conflictTotal.Load(), QueueGapTotal: o.queueGapTotal.Load(), AttemptGapTotal: o.attemptGapTotal.Load(),
		MatchedTotal: o.matchedTotal.Load(), DuplicateTotal: o.duplicateTotal.Load(), OutboxRetryTotal: o.retryTotal.Load(),
		OutboxAckTotal: o.ackTotal.Load(), ReasonCodes: reasons, LastAcknowledgedAt: lastAck,
	}
}

func compactRoutingReasons(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}

func (o *RoutingObserver) Submit(fact RoutingRequestFact) RoutingObserverSubmitResult {
	if o == nil || !o.accepting.Load() {
		return RoutingObserverSubmitResult{Reason: "observer_disabled"}
	}
	copyFact := cloneRoutingObserverRequestFact(fact)
	result := RoutingObserverSubmitResult{Accepted: true}
	if len(copyFact.Attempts) > o.cfg.MaxAttemptsPerRequest {
		copyFact.Attempts = copyFact.Attempts[:o.cfg.MaxAttemptsPerRequest]
		copyFact.Gap = true
		o.attemptGapTotal.Add(1)
		result.Gap = true
		result.Reason = routingObserverReasonAttemptGap
	}
	select {
	case o.queue <- copyFact:
		return result
	default:
		o.queueGapTotal.Add(1)
		return RoutingObserverSubmitResult{Gap: true, Reason: routingObserverReasonQueueGap}
	}
}

func (o *RoutingObserver) LookupScope(groupID int64, model string) (RoutingManagedScope, bool) {
	if o == nil || !o.storeReady.Load() {
		return RoutingManagedScope{}, false
	}
	o.mu.RLock()
	key, ok := o.scopeIndex[routingScopeKey(groupID, model)]
	runtime := o.scopes[key]
	o.mu.RUnlock()
	if !ok || runtime == nil || !runtime.stored.Scope.Enabled {
		return RoutingManagedScope{}, false
	}
	return cloneRoutingManagedScope(runtime.stored.Scope), true
}

// BeginScopedRequest applies the production traffic-origin gate before any
// request-local recorder is allocated. The canary hash is the exact active-loop
// correlation digest (without the sha256: prefix); its request budget is
// consumed atomically under the scope generation lock.
func (o *RoutingObserver) BeginScopedRequest(
	groupID int64,
	model string,
	apiKeyID int64,
	correlationSHA256 string,
) (RoutingManagedScope, RoutingTrafficOrigin, string, bool) {
	if o == nil || !o.storeReady.Load() || groupID <= 0 || strings.TrimSpace(model) == "" || apiKeyID <= 0 {
		return RoutingManagedScope{}, "", "observer_or_request_unavailable", false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	key, ok := o.scopeIndex[routingScopeKey(groupID, model)]
	runtime := o.scopes[key]
	if !ok || runtime == nil || !runtime.stored.Scope.Enabled {
		return RoutingManagedScope{}, "", "unmanaged_scope", false
	}
	scope := runtime.stored.Scope
	for _, id := range scope.TrafficOrigin.MonitorAPIKeyIDs {
		if id == apiKeyID {
			return RoutingManagedScope{}, RoutingTrafficOriginMonitor, "monitor_traffic", false
		}
	}
	for _, id := range scope.TrafficOrigin.CanaryAPIKeyIDs {
		if id != apiKeyID {
			continue
		}
		expected := strings.TrimPrefix(scope.TrafficOrigin.CanaryLoopIDHash, "sha256:")
		if expected == "" || !validRoutingCorrelationDigest(correlationSHA256) || !hmac.Equal([]byte(expected), []byte(correlationSHA256)) {
			return RoutingManagedScope{}, RoutingTrafficOriginMonitor, "canary_correlation_invalid", false
		}
		if scope.TrafficOrigin.CanaryMaxLogicalRequest <= 0 || runtime.canaryLogicalRequests >= scope.TrafficOrigin.CanaryMaxLogicalRequest {
			return RoutingManagedScope{}, RoutingTrafficOriginMonitor, "canary_request_budget_exhausted", false
		}
		runtime.canaryLogicalRequests++
		return cloneRoutingManagedScope(scope), RoutingTrafficOriginUserCanary, "eligible_user_canary", true
	}
	if correlationSHA256 != "" {
		return RoutingManagedScope{}, "", "unexpected_canary_correlation", false
	}
	return cloneRoutingManagedScope(scope), RoutingTrafficOriginUser, "eligible_user", true
}

// CanAuthorizeCanary is used only while consuming the inbound correlation
// header, before the request model is available. Exact model/hash/budget checks
// still happen in BeginScopedRequest.
func (o *RoutingObserver) CanAuthorizeCanary(groupID, apiKeyID int64, correlationSHA256 string) bool {
	if o == nil || !o.storeReady.Load() || groupID <= 0 || apiKeyID <= 0 || !validRoutingCorrelationDigest(correlationSHA256) {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, runtime := range o.scopes {
		if runtime == nil || !runtime.stored.Scope.Enabled || runtime.stored.Scope.GroupID != groupID {
			continue
		}
		scope := runtime.stored.Scope
		expected := strings.TrimPrefix(scope.TrafficOrigin.CanaryLoopIDHash, "sha256:")
		if expected == "" || !hmac.Equal([]byte(expected), []byte(correlationSHA256)) || scope.TrafficOrigin.CanaryMaxLogicalRequest <= 0 {
			continue
		}
		for _, id := range scope.TrafficOrigin.CanaryAPIKeyIDs {
			if id == apiKeyID {
				return true
			}
		}
	}
	return false
}

func (o *RoutingObserver) ScopeStillCurrent(snapshot RoutingManagedScope) bool {
	if o == nil || !o.storeReady.Load() {
		return false
	}
	o.mu.RLock()
	runtime := o.scopes[routingScopeKey(snapshot.GroupID, snapshot.CanonicalModel)]
	current := RoutingManagedScope{}
	if runtime != nil {
		current = runtime.stored.Scope
	}
	o.mu.RUnlock()
	return runtime != nil && current.Enabled &&
		current.ScopeRevision == snapshot.ScopeRevision &&
		current.ScopeHash == snapshot.ScopeHash &&
		current.RouteVersion == snapshot.RouteVersion &&
		current.TopologyFingerprint == snapshot.TopologyFingerprint
}

func (o *RoutingObserver) MarkScopeDrift() {
	o.markDegraded(routingObserverReasonScopeDrift)
}

func (o *RoutingObserver) MarkAttributionGap() {
	o.markDegraded(routingObserverReasonAttributionGap)
}

func (o *RoutingObserver) MarkAttemptGap() {
	if o != nil {
		o.attemptGapTotal.Add(1)
	}
}

func (o *RoutingObserver) EvidenceDigest(domain, value string) (string, error) {
	if o == nil {
		return "", errors.New("routing observer is disabled")
	}
	return RoutingEvidenceDigest([]byte(o.cfg.Secret), domain, value)
}

func cloneRoutingObserverRequestFact(fact RoutingRequestFact) RoutingRequestFact {
	fact.Attempts = append([]RoutingAttemptFact(nil), fact.Attempts...)
	if fact.Handoff != nil {
		copyHandoff := *fact.Handoff
		fact.Handoff = &copyHandoff
	}
	return fact
}

func cloneRoutingManagedScope(scope RoutingManagedScope) RoutingManagedScope {
	scope.ModelAliases = append([]string(nil), scope.ModelAliases...)
	scope.Roles = cloneRoutingRoles(scope.Roles)
	scope.TrafficOrigin = cloneRoutingTrafficOrigin(scope.TrafficOrigin)
	scope.Policy = cloneRoutingPolicy(scope.Policy)
	return scope
}

type RoutingObserverOperationError struct {
	StatusCode int
	ReasonCode string
	Message    string
}

func (e *RoutingObserverOperationError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func routingObserverOperationError(status int, reason, message string) error {
	return &RoutingObserverOperationError{StatusCode: status, ReasonCode: reason, Message: message}
}

func (o *RoutingObserver) PutScope(groupID int64, canonicalModel string, request RoutingObserverScopePutRequest) (RoutingObserverScopeReadback, error) {
	if o == nil || !o.storeReady.Load() {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_store_unavailable", "routing observer store is unavailable")
	}
	if request.ContractVersion != RoutingObserverScopeContractV1 {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_contract_invalid", "routing scope contract_version is unsupported")
	}
	if !routingObserverIdentifierPattern.MatchString(request.OperationID) {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_operation_invalid", "routing scope operation_id is invalid")
	}
	if request.ExpectedRevision < 0 {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_revision_invalid", "routing scope expected_revision must be non-negative")
	}
	if request.ExpectedRevision == 0 && request.ExpectedCurrentHash != "" {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_cas_invalid", "routing scope creation must not include expected_current_hash")
	}
	if request.ExpectedRevision > 0 && !validRoutingSHA256(request.ExpectedCurrentHash) {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_cas_invalid", "routing scope expected_current_hash is invalid")
	}
	if groupID <= 0 || canonicalModel == "" || request.Scope.GroupID != groupID || request.Scope.CanonicalModel != canonicalModel {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_path_mismatch", "routing scope path and body do not match")
	}
	if request.Scope.Sub2APIInstanceID != o.cfg.Sub2APIInstanceID {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_instance_mismatch", "routing scope instance does not match this source")
	}
	if len(request.Scope.Roles.PrimaryAccountIDs)+len(request.Scope.Roles.FallbackAccountIDs)+len(request.Scope.Roles.CandidateAccountIDs) > o.cfg.MaxAccountsPerScope || len(request.Scope.Policy.Rules) > o.cfg.MaxRulesPerPolicy {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_capacity_invalid", "routing scope exceeds configured account or policy bounds")
	}
	scope := RoutingManagedScope{
		ContractVersion:     RoutingObserverScopeContractV1,
		Enabled:             request.Scope.Enabled,
		Sub2APIInstanceID:   request.Scope.Sub2APIInstanceID,
		GroupID:             request.Scope.GroupID,
		CanonicalModel:      request.Scope.CanonicalModel,
		ModelAliases:        append([]string(nil), request.Scope.ModelAliases...),
		RouteVersion:        request.Scope.RouteVersion,
		TopologyFingerprint: request.Scope.TopologyFingerprint,
		ScopeRevision:       request.ExpectedRevision + 1,
		Roles:               cloneRoutingRoles(request.Scope.Roles),
		TrafficOrigin:       cloneRoutingTrafficOrigin(request.Scope.TrafficOrigin),
		Policy:              cloneRoutingPolicy(request.Scope.Policy),
	}
	registry := NewRoutingPolicyRegistry(criticalFailureMetricAdapter{})
	scopeHash, err := scope.Validate(registry)
	if err != nil {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_snapshot_invalid", err.Error())
	}
	validatedPolicy, ok := registry.LastKnownGood()
	if !ok {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusBadRequest, "routing_scope_policy_invalid", "routing scope policy could not be loaded")
	}
	scope.ScopeHash = scopeHash
	storedAt := o.clock.Now().UTC()
	candidate := routingStoredScope{
		OperationID: request.OperationID, Scope: scope, ScopeHash: scopeHash,
		PolicyHash: validatedPolicy.Hash, StoredAt: storedAt,
	}
	candidate.ReadbackHash, err = routingScopeReadbackHash(candidate)
	if err != nil {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusInternalServerError, "routing_scope_hash_failed", "routing scope readback hash failed")
	}
	key := routingScopeKey(groupID, canonicalModel)
	o.mu.Lock()
	defer o.mu.Unlock()
	existing := o.scopes[key]
	if existing != nil && existing.stored.OperationID == request.OperationID {
		if existing.stored.ScopeHash == candidate.ScopeHash {
			return o.scopeReadbackLocked(existing.stored, true), nil
		}
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_operation_conflict", "routing scope operation_id was reused with a different snapshot")
	}
	if existing == nil {
		if request.ExpectedRevision != 0 || request.ExpectedCurrentHash != "" {
			return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_cas_conflict", "routing scope does not exist at the expected revision")
		}
		if len(o.scopes) >= o.cfg.MaxScopes {
			o.degradedReasons[routingObserverReasonScopeCapacity] = struct{}{}
			return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_capacity_exceeded", "routing observer scope capacity is exhausted")
		}
	} else {
		if existing.stored.Scope.ScopeRevision != request.ExpectedRevision || existing.stored.ScopeHash != request.ExpectedCurrentHash {
			return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_cas_conflict", "routing scope expected revision or hash does not match")
		}
		if (routingScopeRouteOrPrimaryChanged(existing.stored.Scope, candidate.Scope) || existing.stored.PolicyHash != candidate.PolicyHash) && o.pendingForScopeLocked(key) > 0 {
			return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_pending_incident", "routing scope route or policy cannot change while an incident is pending")
		}
	}
	for indexKey, owner := range o.scopeIndex {
		if owner != key && routingScopeIndexBelongsTo(candidate.Scope, indexKey) {
			return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusConflict, "routing_scope_model_overlap", "routing scope model or alias overlaps another scope")
		}
	}
	if err := o.scopeStore.PutScope(candidate); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusServiceUnavailable, "routing_scope_store_failed", "routing scope could not be persisted")
	}
	routeChanged := existing != nil && routingScopeRouteOrPrimaryChanged(existing.stored.Scope, candidate.Scope)
	runtime := &routingScopeRuntime{stored: candidate, registry: registry}
	if existing != nil &&
		existing.stored.Scope.TrafficOrigin.CanaryLoopIDHash == candidate.Scope.TrafficOrigin.CanaryLoopIDHash &&
		candidate.Scope.TrafficOrigin.CanaryLoopIDHash != "" {
		runtime.canaryLogicalRequests = existing.canaryLogicalRequests
	}
	o.scopes[key] = runtime
	o.rebuildScopeIndexLocked()
	if routeChanged {
		if err := o.rearmAdmittedLatchesLocked(key); err != nil {
			// The new scope is already durable and is now the in-memory LKG. A
			// cleanup failure must degrade readiness, but must not report the
			// committed CAS as if it were rolled back.
			o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		} else {
			delete(o.degradedReasons, routingObserverReasonScopeDrift)
			delete(o.degradedReasons, routingObserverReasonAttributionGap)
			delete(o.degradedReasons, routingObserverReasonUntypedFailure)
			delete(o.degradedReasons, routingObserverReasonConcurrencyGap)
		}
	}
	delete(o.degradedReasons, routingObserverReasonScopeCapacity)
	return o.scopeReadbackLocked(candidate, false), nil
}

func (o *RoutingObserver) GetScope(groupID int64, canonicalModel string) (RoutingObserverScopeReadback, error) {
	if o == nil || !o.storeReady.Load() {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_store_unavailable", "routing observer store is unavailable")
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	runtime := o.scopes[routingScopeKey(groupID, canonicalModel)]
	if runtime == nil {
		return RoutingObserverScopeReadback{}, routingObserverOperationError(http.StatusNotFound, "routing_scope_not_found", "routing scope was not found")
	}
	return o.scopeReadbackLocked(runtime.stored, false), nil
}

func (o *RoutingObserver) DeleteScope(groupID int64, canonicalModel string, request RoutingObserverScopeDeleteRequest) error {
	if o == nil || !o.storeReady.Load() {
		return routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_store_unavailable", "routing observer store is unavailable")
	}
	if request.ContractVersion != RoutingObserverScopeDeleteContractV1 || !routingObserverIdentifierPattern.MatchString(request.OperationID) || !validRoutingSHA256(request.ExpectedCurrentHash) {
		return routingObserverOperationError(http.StatusBadRequest, "routing_scope_delete_invalid", "routing scope delete request is invalid")
	}
	key := routingScopeKey(groupID, canonicalModel)
	o.mu.Lock()
	defer o.mu.Unlock()
	runtime := o.scopes[key]
	if runtime == nil {
		return routingObserverOperationError(http.StatusNotFound, "routing_scope_not_found", "routing scope was not found")
	}
	if runtime.stored.ScopeHash != request.ExpectedCurrentHash {
		return routingObserverOperationError(http.StatusConflict, "routing_scope_cas_conflict", "routing scope expected hash does not match")
	}
	if runtime.stored.Scope.Enabled {
		return routingObserverOperationError(http.StatusConflict, "routing_scope_not_disabled", "routing scope must be disabled before deletion")
	}
	if o.pendingForScopeLocked(key) > 0 || o.conflictsForScopeLocked(key) > 0 {
		return routingObserverOperationError(http.StatusConflict, "routing_scope_pending_incident", "routing scope has pending or conflicting incidents")
	}
	for incidentID, latch := range o.latches {
		if latch.ScopeKey != key {
			continue
		}
		if err := o.incidentStore.DeleteLatch(incidentID); err != nil {
			o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
			return routingObserverOperationError(http.StatusServiceUnavailable, "routing_scope_latch_delete_failed", "routing scope latch cleanup failed")
		}
	}
	if err := o.scopeStore.DeleteScope(key); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		return routingObserverOperationError(http.StatusServiceUnavailable, "routing_scope_delete_failed", "routing scope deletion failed")
	}
	for incidentID, latch := range o.latches {
		if latch.ScopeKey == key {
			delete(o.latches, incidentID)
		}
	}
	delete(o.scopes, key)
	o.rebuildScopeIndexLocked()
	return nil
}

func routingScopeReadbackHash(item routingStoredScope) (string, error) {
	return routingCanonicalHash(struct {
		OperationID         string `json:"operation_id"`
		Revision            int64  `json:"revision"`
		ScopeHash           string `json:"scope_hash"`
		PolicyHash          string `json:"policy_hash"`
		Enabled             bool   `json:"enabled"`
		RouteVersion        int64  `json:"route_version"`
		TopologyFingerprint string `json:"topology_fingerprint"`
	}{item.OperationID, item.Scope.ScopeRevision, item.ScopeHash, item.PolicyHash, item.Scope.Enabled, item.Scope.RouteVersion, item.Scope.TopologyFingerprint})
}

func (o *RoutingObserver) scopeReadbackLocked(item routingStoredScope, duplicate bool) RoutingObserverScopeReadback {
	state := "ready"
	if !item.Scope.Enabled {
		state = "disabled"
	}
	key := routingScopeKey(item.Scope.GroupID, item.Scope.CanonicalModel)
	return RoutingObserverScopeReadback{
		ContractVersion: RoutingObserverScopeReadbackContractV1, OperationID: item.OperationID, Duplicate: duplicate,
		Revision: item.Scope.ScopeRevision, ScopeHash: item.ScopeHash, PolicyHash: item.PolicyHash, ReadbackHash: item.ReadbackHash,
		State: state, GroupID: item.Scope.GroupID, CanonicalModel: item.Scope.CanonicalModel, RouteVersion: item.Scope.RouteVersion,
		TopologyFingerprint: item.Scope.TopologyFingerprint,
		PrimaryAccountCount: len(item.Scope.Roles.PrimaryAccountIDs), FallbackAccountCount: len(item.Scope.Roles.FallbackAccountIDs),
		CandidateAccountCount: len(item.Scope.Roles.CandidateAccountIDs), MonitorKeyCount: len(item.Scope.TrafficOrigin.MonitorAPIKeyIDs),
		CanaryKeyCount: len(item.Scope.TrafficOrigin.CanaryAPIKeyIDs), PendingIncidentCount: o.pendingForScopeLocked(key),
		ConflictCount: o.conflictsForScopeLocked(key), StoredAt: item.StoredAt,
	}
}

func routingScopeIndexBelongsTo(scope RoutingManagedScope, indexKey string) bool {
	if indexKey == routingScopeKey(scope.GroupID, scope.CanonicalModel) {
		return true
	}
	for _, alias := range scope.ModelAliases {
		if indexKey == routingScopeKey(scope.GroupID, alias) {
			return true
		}
	}
	return false
}

func routingScopeRouteOrPrimaryChanged(left, right RoutingManagedScope) bool {
	if left.RouteVersion != right.RouteVersion || left.TopologyFingerprint != right.TopologyFingerprint {
		return true
	}
	return !equalRoutingIDSet(left.Roles.PrimaryAccountIDs, right.Roles.PrimaryAccountIDs)
}

func equalRoutingIDSet(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy := append([]int64(nil), left...)
	rightCopy := append([]int64(nil), right...)
	sort.Slice(leftCopy, func(i, j int) bool { return leftCopy[i] < leftCopy[j] })
	sort.Slice(rightCopy, func(i, j int) bool { return rightCopy[i] < rightCopy[j] })
	for index := range leftCopy {
		if leftCopy[index] != rightCopy[index] {
			return false
		}
	}
	return true
}

func (o *RoutingObserver) pendingForScopeLocked(scopeKey string) int {
	count := 0
	for _, item := range o.outbox {
		if item.ScopeKey == scopeKey {
			count++
		}
	}
	return count
}

func (o *RoutingObserver) conflictsForScopeLocked(scopeKey string) int {
	count := 0
	for _, latch := range o.latches {
		if latch.ScopeKey == scopeKey && latch.State == routingIncidentLatchConflict {
			count++
		}
	}
	return count
}

func (o *RoutingObserver) rebuildScopeIndexLocked() {
	index := make(map[string]string)
	for key, runtime := range o.scopes {
		index[routingScopeKey(runtime.stored.Scope.GroupID, runtime.stored.Scope.CanonicalModel)] = key
		for _, alias := range runtime.stored.Scope.ModelAliases {
			index[routingScopeKey(runtime.stored.Scope.GroupID, alias)] = key
		}
	}
	o.scopeIndex = index
}

func (o *RoutingObserver) rearmAdmittedLatchesLocked(scopeKey string) error {
	for incidentID, latch := range o.latches {
		if latch.ScopeKey != scopeKey || latch.State != routingIncidentLatchAdmitted {
			continue
		}
		if _, pending := o.outbox[incidentID]; pending {
			return errors.New("admitted routing latch still has an outbox item")
		}
		if err := o.incidentStore.DeleteLatch(incidentID); err != nil {
			return err
		}
		delete(o.latches, incidentID)
	}
	return nil
}

func (o *RoutingObserver) restore() error {
	storedScopes, err := o.scopeStore.LoadScopes()
	if err != nil {
		return err
	}
	storedLatches, err := o.incidentStore.LoadLatches()
	if err != nil {
		return err
	}
	storedOutbox, err := o.incidentStore.LoadOutbox()
	if err != nil {
		return err
	}
	if len(storedScopes) > o.cfg.MaxScopes || len(storedOutbox) > o.cfg.MaxPendingOutbox {
		return errors.New("routing observer persisted state exceeds configured bounds")
	}
	recoveredReasons := make(map[string]struct{})
	var recoveredLastAck *time.Time
	var recoveredConflictCount uint64
	scopes := make(map[string]*routingScopeRuntime, len(storedScopes))
	index := make(map[string]string)
	for _, item := range storedScopes {
		if item.OperationID == "" || !routingObserverIdentifierPattern.MatchString(item.OperationID) || item.StoredAt.IsZero() {
			return errors.New("routing observer persisted scope metadata is invalid")
		}
		if item.Scope.Sub2APIInstanceID != o.cfg.Sub2APIInstanceID {
			return errors.New("routing observer persisted scope belongs to another instance")
		}
		registry := NewRoutingPolicyRegistry(criticalFailureMetricAdapter{})
		scopeHash, err := item.Scope.Validate(registry)
		if err != nil || scopeHash != item.ScopeHash {
			return errors.New("routing observer persisted scope hash is invalid")
		}
		validated, ok := registry.LastKnownGood()
		if !ok || validated.Hash != item.PolicyHash {
			return errors.New("routing observer persisted policy hash is invalid")
		}
		item.Scope.ScopeHash = item.ScopeHash
		readbackHash, err := routingScopeReadbackHash(item)
		if err != nil || readbackHash != item.ReadbackHash {
			return errors.New("routing observer persisted readback hash is invalid")
		}
		key := routingScopeKey(item.Scope.GroupID, item.Scope.CanonicalModel)
		if _, exists := scopes[key]; exists {
			return errors.New("routing observer persisted scopes contain a duplicate")
		}
		for _, model := range append([]string{item.Scope.CanonicalModel}, item.Scope.ModelAliases...) {
			indexKey := routingScopeKey(item.Scope.GroupID, model)
			if owner, exists := index[indexKey]; exists && owner != key {
				return errors.New("routing observer persisted scopes overlap")
			}
			index[indexKey] = key
		}
		scopes[key] = &routingScopeRuntime{stored: item, registry: registry}
	}
	latches := make(map[string]*routingIncidentLatch, len(storedLatches))
	for index := range storedLatches {
		item := storedLatches[index]
		if err := validateRoutingIncidentLatch(item); err != nil {
			return err
		}
		if _, exists := scopes[item.ScopeKey]; !exists {
			return errors.New("routing incident latch references an unknown scope")
		}
		if _, exists := latches[item.IncidentID]; exists {
			return errors.New("routing incident latch identity is duplicated")
		}
		copyItem := item
		latches[item.IncidentID] = &copyItem
		if item.State == routingIncidentLatchAdmitted && item.AcknowledgedAt != nil && (recoveredLastAck == nil || item.AcknowledgedAt.After(*recoveredLastAck)) {
			value := item.AcknowledgedAt.UTC()
			recoveredLastAck = &value
		}
		if item.State == routingIncidentLatchConflict {
			recoveredConflictCount += item.ConflictCount
			recoveredReasons[routingObserverReasonIdentityConflict] = struct{}{}
		}
	}
	outbox := make(map[string]*routingIncidentOutboxItem, len(storedOutbox))
	for index := range storedOutbox {
		item := storedOutbox[index]
		if err := validateRoutingIncidentOutbox(item); err != nil {
			return err
		}
		var persistedSignal RoutingIncidentSignal
		if err := decodeRoutingObserverJSON(item.Body, &persistedSignal); err != nil || persistedSignal.Sub2APIInstanceID != o.cfg.Sub2APIInstanceID {
			return errors.New("routing incident outbox belongs to another instance")
		}
		if item.LastFailureReason != "" {
			if !validRoutingObserverTransportFailureReason(item.LastFailureReason) {
				return errors.New("routing incident outbox failure reason is invalid")
			}
			recoveredReasons[item.LastFailureReason] = struct{}{}
		}
		if _, exists := scopes[item.ScopeKey]; !exists {
			return errors.New("routing incident outbox references an unknown scope")
		}
		if _, exists := outbox[item.IncidentID]; exists {
			return errors.New("routing incident outbox identity is duplicated")
		}
		latch := latches[item.IncidentID]
		if latch == nil {
			recovered := routingIncidentLatch{
				IncidentID: item.IncidentID, IdempotencyKey: item.IdempotencyKey, PayloadHash: item.PayloadHash,
				ScopeKey: item.ScopeKey, ScopeHash: item.ScopeHash, RouteVersion: item.RouteVersion,
				PolicyHash: item.PolicyHash, RuleID: item.RuleID, State: routingIncidentLatchOpened,
				OpenedAt: item.CreatedAt,
			}
			if err := o.incidentStore.PutLatch(recovered); err != nil {
				return fmt.Errorf("recover routing incident latch: %w", err)
			}
			latches[item.IncidentID] = &recovered
			latch = &recovered
		}
		if latch.PayloadHash != item.PayloadHash || latch.IdempotencyKey != item.IdempotencyKey || latch.ScopeKey != item.ScopeKey || latch.RouteVersion != item.RouteVersion || latch.PolicyHash != item.PolicyHash || latch.RuleID != item.RuleID {
			return errors.New("routing incident latch and outbox conflict")
		}
		if latch.State == routingIncidentLatchAdmitted {
			if err := o.incidentStore.DeleteOutbox(item.IncidentID); err != nil {
				return fmt.Errorf("clean acknowledged routing incident outbox: %w", err)
			}
			continue
		}
		copyItem := item
		copyItem.Body = append(json.RawMessage(nil), item.Body...)
		outbox[item.IncidentID] = &copyItem
	}
	for incidentID, latch := range latches {
		if latch.State == routingIncidentLatchOpened {
			if _, exists := outbox[incidentID]; !exists {
				return errors.New("opened routing incident latch has no durable outbox item")
			}
		}
	}
	o.mu.Lock()
	o.scopes = scopes
	o.scopeIndex = index
	o.latches = latches
	o.outbox = outbox
	o.lastAckAt = recoveredLastAck
	for reason := range recoveredReasons {
		o.degradedReasons[reason] = struct{}{}
	}
	o.mu.Unlock()
	o.conflictTotal.Store(recoveredConflictCount)
	return nil
}

func validRoutingObserverTransportFailureReason(reason string) bool {
	switch reason {
	case routingObserverReasonAckMismatch, routingObserverReasonTransport, routingObserverReasonHTTPFailure:
		return true
	default:
		return false
	}
}

func validateRoutingIncidentLatch(item routingIncidentLatch) error {
	if !routingObserverDigestPattern.MatchString(item.IncidentID) || item.IdempotencyKey != item.IncidentID || !validRoutingSHA256(item.PayloadHash) || !validRoutingSHA256(item.ScopeHash) || !validRoutingSHA256(item.PolicyHash) {
		return errors.New("routing incident latch identity is invalid")
	}
	if item.ScopeKey == "" || item.RouteVersion <= 0 || !routingObserverIdentifierPattern.MatchString(item.RuleID) || item.OpenedAt.IsZero() {
		return errors.New("routing incident latch metadata is invalid")
	}
	switch item.State {
	case routingIncidentLatchOpened:
		if item.AcknowledgedAt != nil {
			return errors.New("opened routing incident latch has an acknowledgement timestamp")
		}
	case routingIncidentLatchAdmitted:
		if item.AcknowledgedAt == nil || item.AcknowledgedAt.IsZero() {
			return errors.New("admitted routing incident latch is missing an acknowledgement timestamp")
		}
	case routingIncidentLatchConflict:
		if item.ConflictCount == 0 {
			return errors.New("conflicting routing incident latch is missing its conflict count")
		}
	default:
		return errors.New("routing incident latch state is invalid")
	}
	return nil
}

func validateRoutingIncidentOutbox(item routingIncidentOutboxItem) error {
	if !routingObserverDigestPattern.MatchString(item.IncidentID) || item.IdempotencyKey != item.IncidentID || !validRoutingSHA256(item.PayloadHash) || !validRoutingSHA256(item.ScopeHash) || !validRoutingSHA256(item.PolicyHash) {
		return errors.New("routing incident outbox identity is invalid")
	}
	if item.ScopeKey == "" || item.RouteVersion <= 0 || !routingObserverIdentifierPattern.MatchString(item.RuleID) || item.CreatedAt.IsZero() || item.NextAttemptAt.IsZero() || item.AttemptCount < 0 || len(item.Body) == 0 || len(item.Body) > routingIncidentMaxBodyBytes {
		return errors.New("routing incident outbox metadata is invalid")
	}
	digest := sha256.Sum256(item.Body)
	if "sha256:"+hex.EncodeToString(digest[:]) != item.PayloadHash {
		return errors.New("routing incident outbox payload hash is invalid")
	}
	var signal RoutingIncidentSignal
	if err := decodeRoutingObserverJSON(item.Body, &signal); err != nil {
		return errors.New("routing incident outbox payload schema is invalid")
	}
	if err := validateRoutingIncidentSignal(signal); err != nil {
		return err
	}
	if signal.ContractVersion != RoutingIncidentSignalContractV1 || signal.Incident.IncidentID != item.IncidentID || signal.Incident.IdempotencyKey != item.IdempotencyKey || signal.Incident.Scope.ScopeHash != item.ScopeHash || signal.Incident.Scope.RouteVersion != item.RouteVersion || routingScopeKey(signal.Incident.Scope.GroupID, signal.Incident.Scope.CanonicalModel) != item.ScopeKey || signal.Incident.Policy.Hash != item.PolicyHash || signal.Incident.Winner.RuleID != item.RuleID {
		return errors.New("routing incident outbox payload does not match its envelope")
	}
	return nil
}

func (o *RoutingObserver) workerLoop() {
	defer close(o.workerDone)
	for {
		select {
		case fact := <-o.queue:
			o.handleFact(fact)
		case <-o.workerStop:
			for {
				select {
				case fact := <-o.queue:
					o.handleFact(fact)
				default:
					return
				}
			}
		}
	}
}

func (o *RoutingObserver) handleFact(fact RoutingRequestFact) {
	o.mu.RLock()
	owner := o.scopeIndex[routingScopeKey(fact.GroupID, fact.CanonicalModel)]
	runtime := o.scopes[owner]
	o.mu.RUnlock()
	if runtime == nil {
		return
	}
	decision := runtime.registry.Evaluate(runtime.stored.Scope, fact)
	if decision.EligibilityState == RoutingEvaluationIgnored {
		if decision.EligibilityReason == "route_scope_mismatch" || decision.EligibilityReason == "scope_hash_mismatch" {
			o.markDegraded(routingObserverReasonScopeDrift)
		}
		return
	}
	runtime.recordDecision(fact.ObservedAt, decision)
	if decision.Winner == nil {
		o.recordInsufficientDecision(decision)
		return
	}
	identity, err := RoutingIncidentIdentity([]byte(o.cfg.Secret), runtime.stored.Scope, decision.PolicyHash, decision.Winner.RuleID)
	if err != nil {
		o.markDegraded(routingObserverReasonIdentityConflict)
		return
	}
	o.mu.RLock()
	existing := o.latches[identity]
	o.mu.RUnlock()
	if existing != nil {
		o.duplicateTotal.Add(1)
		return
	}
	signal, err := o.buildIncidentSignal(runtime.stored, fact, decision, identity)
	if err != nil {
		o.markDegraded(routingObserverReasonUntypedFailure)
		return
	}
	if _, err := o.persistIncidentSignal(signal); err != nil {
		return
	}
	o.matchedTotal.Add(1)
}

func (r *routingScopeRuntime) recordDecision(observedAt time.Time, decision RoutingPolicyDecision) {
	if r == nil {
		return
	}
	if observedAt.IsZero() {
		return
	}
	minute := observedAt.UTC().Unix() / 60
	index := int(minute % int64(len(r.buckets)))
	if index < 0 {
		index += len(r.buckets)
	}
	bucket := &r.buckets[index]
	if bucket.minute != minute {
		*bucket = routingObserverMinuteBucket{minute: minute}
	}
	bucket.eligible++
	if decision.Winner != nil {
		bucket.matched++
		return
	}
	for _, evaluation := range decision.Evaluations {
		if evaluation.State == RoutingEvaluationInsufficient {
			bucket.insufficient++
			return
		}
	}
	bucket.notMatched++
}

func (o *RoutingObserver) recordInsufficientDecision(decision RoutingPolicyDecision) {
	for _, evaluation := range decision.Evaluations {
		if evaluation.State != RoutingEvaluationInsufficient {
			continue
		}
		switch evaluation.ReasonCode {
		case "failure_stage_untyped", "failure_not_account_failover", "attempt_attribution_incomplete", "failure_chain_incomplete", "final_attempt_missing_or_not_terminal", "fallback_final_success_missing", "request_fact_gap":
			o.markDegraded(routingObserverReasonUntypedFailure)
		case "concurrency_handoff_missing", "concurrency_handoff_role_mismatch", "concurrency_handoff_invalid", "overlapping_timeline", "failover_handoff_not_proven":
			o.markDegraded(routingObserverReasonConcurrencyGap)
		}
	}
}

func (o *RoutingObserver) buildIncidentSignal(stored routingStoredScope, fact RoutingRequestFact, decision RoutingPolicyDecision, identity string) (RoutingIncidentSignal, error) {
	if decision.Winner == nil || fact.Handoff == nil || len(decision.Winner.Evidence) == 0 {
		return RoutingIncidentSignal{}, errors.New("routing incident evidence is incomplete")
	}
	firstObserved, lastObserved := routingIncidentObservationWindow(fact)
	if firstObserved.IsZero() || lastObserved.IsZero() {
		return RoutingIncidentSignal{}, errors.New("routing incident observation window is incomplete")
	}
	chainValue := strings.Join(decision.Winner.Evidence, "\x00") + "\x00" + fact.Handoff.WindowIdentity
	chainDigest, err := RoutingEvidenceDigest([]byte(o.cfg.Secret), "routing-incident-chain.v1", chainValue)
	if err != nil {
		return RoutingIncidentSignal{}, err
	}
	operationID := "routing-incident-" + strings.TrimPrefix(identity, "hmac-sha256:")
	if len(operationID) > 128 {
		return RoutingIncidentSignal{}, errors.New("routing incident operation identity is too long")
	}
	return RoutingIncidentSignal{
		ContractVersion:   RoutingIncidentSignalContractV1,
		Sub2APIInstanceID: stored.Scope.Sub2APIInstanceID,
		OperationID:       operationID,
		Incident: RoutingIncidentSnapshot{
			IncidentID: identity, IdempotencyKey: identity, State: "opened",
			Scope: RoutingIncidentScope{
				ScopeRevision: stored.Scope.ScopeRevision, ScopeHash: stored.ScopeHash,
				GroupID: stored.Scope.GroupID, CanonicalModel: stored.Scope.CanonicalModel,
				TrafficOrigin: fact.TrafficOrigin, RouteVersion: stored.Scope.RouteVersion,
				TopologyFingerprint: stored.Scope.TopologyFingerprint,
			},
			Policy: RoutingIncidentPolicy{PolicyID: stored.Scope.Policy.PolicyID, Revision: stored.Scope.Policy.Revision, Hash: stored.PolicyHash},
			Winner: RoutingIncidentWinner{
				RuleID: decision.Winner.RuleID, Severity: decision.Winner.Severity,
				Precedence: decision.Winner.Precedence, Action: decision.Winner.Action,
				ReasonCode: decision.Winner.ReasonCode,
			},
			Window: RoutingIncidentWindow{FirstObservedAt: firstObserved, LastObservedAt: lastObserved},
			Evidence: RoutingIncidentEvidence{
				CompleteChainCount: 1, OriginalPrimaryFailureCount: 1, FallbackFinalSuccessCount: 1,
				PrimaryConcurrency: fact.Handoff.PrimaryConcurrency, FallbackConcurrency: fact.Handoff.FallbackConcurrency,
				ChainDigests: []string{chainDigest},
			},
		},
	}, nil
}

func routingIncidentObservationWindow(fact RoutingRequestFact) (time.Time, time.Time) {
	var first, last time.Time
	consider := func(value time.Time) {
		if value.IsZero() {
			return
		}
		value = value.UTC()
		if first.IsZero() || value.Before(first) {
			first = value
		}
		if last.IsZero() || value.After(last) {
			last = value
		}
	}
	consider(fact.ObservedAt)
	for _, attempt := range fact.Attempts {
		consider(attempt.ObservedAt)
	}
	if fact.Handoff != nil {
		consider(fact.Handoff.ObservedAt)
	}
	return first, last
}

func (o *RoutingObserver) persistIncidentSignal(signal RoutingIncidentSignal) (RoutingIdentityResolution, error) {
	if err := validateRoutingIncidentSignal(signal); err != nil {
		return "", err
	}
	if signal.Sub2APIInstanceID != o.cfg.Sub2APIInstanceID {
		return "", errors.New("routing incident signal instance does not match this source")
	}
	body, err := canonicalJSON(signal)
	if err != nil || len(body) == 0 || len(body) > routingIncidentMaxBodyBytes {
		o.markDegraded(routingObserverReasonDiskFailure)
		return "", errors.New("routing incident payload serialization failed or exceeded 32 KiB")
	}
	digest := sha256.Sum256(body)
	payloadHash := "sha256:" + hex.EncodeToString(digest[:])
	incident := signal.Incident
	if !routingObserverDigestPattern.MatchString(incident.IncidentID) || incident.IdempotencyKey != incident.IncidentID || signal.ContractVersion != RoutingIncidentSignalContractV1 {
		return "", errors.New("routing incident signal identity is invalid")
	}
	item := routingIncidentOutboxItem{
		IncidentID: incident.IncidentID, IdempotencyKey: incident.IdempotencyKey, PayloadHash: payloadHash,
		ScopeKey: routingScopeKey(incident.Scope.GroupID, incident.Scope.CanonicalModel), ScopeHash: incident.Scope.ScopeHash,
		RouteVersion: incident.Scope.RouteVersion, PolicyHash: incident.Policy.Hash, RuleID: incident.Winner.RuleID,
		Body: append(json.RawMessage(nil), body...), CreatedAt: o.clock.Now().UTC(), NextAttemptAt: o.clock.Now().UTC(),
	}
	latch := routingIncidentLatch{
		IncidentID: item.IncidentID, IdempotencyKey: item.IdempotencyKey, PayloadHash: item.PayloadHash,
		ScopeKey: item.ScopeKey, ScopeHash: item.ScopeHash, RouteVersion: item.RouteVersion,
		PolicyHash: item.PolicyHash, RuleID: item.RuleID, State: routingIncidentLatchOpened, OpenedAt: item.CreatedAt,
	}
	o.mu.Lock()
	existing := o.latches[item.IncidentID]
	if existing != nil {
		resolution, resolutionErr := ResolveRoutingIdentity(existing.IncidentID, existing.PayloadHash, item.IncidentID, item.PayloadHash)
		if resolutionErr != nil {
			o.degradedReasons[routingObserverReasonIdentityConflict] = struct{}{}
			o.mu.Unlock()
			return "", resolutionErr
		}
		if resolution == RoutingIdentityDuplicate {
			existing.DuplicateCount++
			o.duplicateTotal.Add(1)
			o.mu.Unlock()
			return resolution, nil
		}
		existing.State = routingIncidentLatchConflict
		existing.ConflictCount++
		o.conflictTotal.Add(1)
		o.degradedReasons[routingObserverReasonIdentityConflict] = struct{}{}
		persistErr := o.incidentStore.PutLatch(*existing)
		o.mu.Unlock()
		if persistErr != nil {
			o.markDegraded(routingObserverReasonDiskFailure)
			return RoutingIdentityConflict, persistErr
		}
		return RoutingIdentityConflict, errors.New("routing incident identity maps to a different payload")
	}
	if len(o.outbox) >= o.cfg.MaxPendingOutbox {
		o.degradedReasons[routingObserverReasonOutboxCapacity] = struct{}{}
		o.mu.Unlock()
		return "", errors.New("routing incident outbox capacity is exhausted")
	}
	for existingID, pending := range o.outbox {
		if existingID != item.IncidentID && pending.ScopeKey == item.ScopeKey && pending.RouteVersion == item.RouteVersion && pending.RuleID == item.RuleID {
			o.degradedReasons[routingObserverReasonIdentityConflict] = struct{}{}
			o.conflictTotal.Add(1)
			o.mu.Unlock()
			return RoutingIdentityConflict, errors.New("routing incident scope, route, and rule already have a different pending identity")
		}
	}
	if _, exists := o.scopes[item.ScopeKey]; !exists {
		o.mu.Unlock()
		return "", errors.New("routing incident scope is not installed")
	}
	if err := o.incidentStore.PutOutbox(item); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		o.mu.Unlock()
		return "", err
	}
	if err := o.incidentStore.PutLatch(latch); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		// The outbox is already durable. Keep the in-memory latch and allow the
		// sender to deliver; startup recovery reconstructs this latch if needed.
	}
	o.outbox[item.IncidentID] = &item
	o.latches[item.IncidentID] = &latch
	delete(o.degradedReasons, routingObserverReasonOutboxCapacity)
	o.mu.Unlock()
	o.wakeSender()
	return RoutingIdentityNew, nil
}

func validateRoutingIncidentSignal(signal RoutingIncidentSignal) error {
	incident := signal.Incident
	if signal.ContractVersion != RoutingIncidentSignalContractV1 || signal.Sub2APIInstanceID <= 0 || !routingObserverIdentifierPattern.MatchString(signal.OperationID) {
		return errors.New("routing incident signal envelope is invalid")
	}
	if !routingObserverDigestPattern.MatchString(incident.IncidentID) || incident.IdempotencyKey != incident.IncidentID || incident.State != "opened" {
		return errors.New("routing incident signal identity is invalid")
	}
	scope := incident.Scope
	if scope.ScopeRevision <= 0 || scope.GroupID <= 0 || scope.RouteVersion <= 0 || strings.TrimSpace(scope.CanonicalModel) == "" || strings.TrimSpace(scope.CanonicalModel) != scope.CanonicalModel || !validRoutingSHA256(scope.ScopeHash) || !validRoutingSHA256(scope.TopologyFingerprint) {
		return errors.New("routing incident signal scope is invalid")
	}
	if scope.TrafficOrigin != RoutingTrafficOriginUser && scope.TrafficOrigin != RoutingTrafficOriginUserCanary {
		return errors.New("routing incident signal traffic origin is invalid")
	}
	policy := incident.Policy
	if !routingObserverIdentifierPattern.MatchString(policy.PolicyID) || policy.Revision <= 0 || !validRoutingSHA256(policy.Hash) {
		return errors.New("routing incident signal policy is invalid")
	}
	winner := incident.Winner
	if !routingObserverIdentifierPattern.MatchString(winner.RuleID) || routingSeverityRank(winner.Severity) >= 100 || winner.Precedence < 0 || winner.Action != RoutingActionHardFailover || !routingObserverIdentifierPattern.MatchString(winner.ReasonCode) {
		return errors.New("routing incident signal winner is invalid")
	}
	if incident.Window.FirstObservedAt.IsZero() || incident.Window.LastObservedAt.IsZero() || incident.Window.LastObservedAt.Before(incident.Window.FirstObservedAt) {
		return errors.New("routing incident signal window is invalid")
	}
	evidence := incident.Evidence
	if evidence.CompleteChainCount != 1 || evidence.OriginalPrimaryFailureCount != 1 || evidence.FallbackFinalSuccessCount != 1 || evidence.PrimaryConcurrency != 0 || evidence.FallbackConcurrency <= 0 || len(evidence.ChainDigests) == 0 || len(evidence.ChainDigests) > 8 {
		return errors.New("routing incident signal evidence counts are invalid")
	}
	for _, digest := range evidence.ChainDigests {
		if !routingObserverDigestPattern.MatchString(digest) {
			return errors.New("routing incident signal evidence digest is invalid")
		}
	}
	return nil
}

func (o *RoutingObserver) wakeSender() {
	if o == nil {
		return
	}
	select {
	case o.senderWake <- struct{}{}:
	default:
	}
}

func routingIncidentRetryDelay(attemptCount int) time.Duration {
	switch attemptCount {
	case 1:
		return time.Second
	case 2:
		return 2 * time.Second
	case 3:
		return 4 * time.Second
	case 4:
		return 8 * time.Second
	default:
		return 60 * time.Second
	}
}

func (o *RoutingObserver) senderLoop() {
	defer close(o.senderDone)
	for {
		item, wait := o.nextOutboxItem()
		if item != nil && wait <= 0 {
			o.deliverOutboxItem(*item)
			continue
		}
		if item == nil {
			select {
			case <-o.senderWake:
				continue
			case <-o.senderStop:
				return
			}
		}
		select {
		case <-o.clock.After(wait):
		case <-o.senderWake:
		case <-o.senderStop:
			return
		}
	}
}

func (o *RoutingObserver) nextOutboxItem() (*routingIncidentOutboxItem, time.Duration) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	var selected *routingIncidentOutboxItem
	for incidentID, item := range o.outbox {
		latch := o.latches[incidentID]
		if latch == nil || latch.State == routingIncidentLatchConflict {
			continue
		}
		if selected == nil || item.NextAttemptAt.Before(selected.NextAttemptAt) || (item.NextAttemptAt.Equal(selected.NextAttemptAt) && item.IncidentID < selected.IncidentID) {
			copyItem := *item
			copyItem.Body = append(json.RawMessage(nil), item.Body...)
			selected = &copyItem
		}
	}
	if selected == nil {
		return nil, 0
	}
	wait := selected.NextAttemptAt.Sub(o.clock.Now())
	return selected, wait
}

func (o *RoutingObserver) deliverOutboxItem(item routingIncidentOutboxItem) {
	o.mu.RLock()
	latch := o.latches[item.IncidentID]
	alreadyAdmitted := latch != nil && latch.State == routingIncidentLatchAdmitted
	o.mu.RUnlock()
	if alreadyAdmitted {
		o.cleanupAcknowledgedOutbox(item.IncidentID)
		return
	}
	requestContext, cancel := context.WithTimeout(o.senderContext, time.Duration(o.cfg.RequestTimeoutMS)*time.Millisecond)
	ack, reason, err := o.transport.Deliver(requestContext, item)
	cancel()
	if err != nil {
		o.scheduleOutboxRetry(item.IncidentID, reason)
		return
	}
	if !routingIncidentAckMatches(ack, item) {
		o.scheduleOutboxRetry(item.IncidentID, routingObserverReasonAckMismatch)
		return
	}
	o.acknowledgeOutbox(item.IncidentID)
}

func routingIncidentAckMatches(ack RoutingIncidentAck, item routingIncidentOutboxItem) bool {
	return ack.ContractVersion == RoutingIncidentAckContractV1 &&
		ack.IncidentID == item.IncidentID && ack.IdempotencyKey == item.IdempotencyKey &&
		ack.PayloadHash == item.PayloadHash && ack.AdmissionState == "admitted" &&
		ack.RouteVersion == item.RouteVersion && ack.PolicyHash == item.PolicyHash &&
		strings.TrimSpace(ack.RouteIntentID) != "" && ack.DispatchRunID > 0
}

func (o *RoutingObserver) scheduleOutboxRetry(incidentID, reason string) {
	if reason == "" {
		reason = routingObserverReasonTransport
	}
	o.mu.Lock()
	item := o.outbox[incidentID]
	if item == nil {
		o.mu.Unlock()
		return
	}
	if item.AttemptCount < 1_000_000 {
		item.AttemptCount++
	}
	item.LastFailureReason = reason
	item.NextAttemptAt = o.clock.Now().UTC().Add(routingIncidentRetryDelay(item.AttemptCount))
	persistErr := o.incidentStore.PutOutbox(*item)
	o.degradedReasons[reason] = struct{}{}
	if persistErr != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
	}
	o.mu.Unlock()
	o.retryTotal.Add(1)
}

func (o *RoutingObserver) acknowledgeOutbox(incidentID string) {
	o.mu.Lock()
	item := o.outbox[incidentID]
	latch := o.latches[incidentID]
	if item == nil || latch == nil || latch.State == routingIncidentLatchConflict {
		o.mu.Unlock()
		return
	}
	acknowledgedAt := o.clock.Now().UTC()
	latch.State = routingIncidentLatchAdmitted
	latch.AcknowledgedAt = &acknowledgedAt
	if err := o.incidentStore.PutLatch(*latch); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		o.mu.Unlock()
		return
	}
	if err := o.incidentStore.DeleteOutbox(incidentID); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		item.NextAttemptAt = acknowledgedAt.Add(60 * time.Second)
		o.mu.Unlock()
		return
	}
	delete(o.outbox, incidentID)
	o.lastAckAt = &acknowledgedAt
	delete(o.degradedReasons, routingObserverReasonAckMismatch)
	delete(o.degradedReasons, routingObserverReasonTransport)
	delete(o.degradedReasons, routingObserverReasonHTTPFailure)
	o.mu.Unlock()
	o.ackTotal.Add(1)
}

func (o *RoutingObserver) cleanupAcknowledgedOutbox(incidentID string) {
	o.mu.Lock()
	item := o.outbox[incidentID]
	latch := o.latches[incidentID]
	if item == nil {
		o.mu.Unlock()
		return
	}
	if err := o.incidentStore.DeleteOutbox(incidentID); err != nil {
		o.degradedReasons[routingObserverReasonDiskFailure] = struct{}{}
		item.NextAttemptAt = o.clock.Now().UTC().Add(60 * time.Second)
		o.mu.Unlock()
		return
	}
	delete(o.outbox, incidentID)
	if latch != nil && latch.AcknowledgedAt != nil {
		acknowledgedAt := latch.AcknowledgedAt.UTC()
		o.lastAckAt = &acknowledgedAt
		o.ackTotal.Add(1)
	}
	o.mu.Unlock()
}

type routingIncidentHTTPTransport struct {
	endpoint string
	secret   []byte
	client   *http.Client
	clock    routingObserverClock
}

func newRoutingIncidentHTTPTransport(cfg config.GatewayRoutingObserverConfig, clock routingObserverClock) *routingIncidentHTTPTransport {
	return &routingIncidentHTTPTransport{
		endpoint: strings.TrimRight(cfg.PanelURL, "/") + routingIncidentHookPath,
		secret:   []byte(cfg.Secret), client: &http.Client{}, clock: clock,
	}
}

func (t *routingIncidentHTTPTransport) Deliver(ctx context.Context, item routingIncidentOutboxItem) (RoutingIncidentAck, string, error) {
	if t == nil || t.client == nil || t.clock == nil || len(t.secret) == 0 {
		return RoutingIncidentAck{}, routingObserverReasonTransport, errors.New("routing incident transport is unavailable")
	}
	timestamp := t.clock.Now().Unix()
	mac := hmac.New(sha256.New, t.secret)
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	_, _ = mac.Write(item.Body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(item.Body))
	if err != nil {
		return RoutingIncidentAck{}, routingObserverReasonTransport, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Dispatch-Signature-Version", RoutingIncidentHookSignatureV1)
	request.Header.Set("X-Dispatch-Timestamp", strconv.FormatInt(timestamp, 10))
	request.Header.Set("X-Dispatch-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	response, err := t.client.Do(request)
	if err != nil {
		return RoutingIncidentAck{}, routingObserverReasonTransport, err
	}
	limited := io.LimitReader(response.Body, routingIncidentMaxResponseBytes+1)
	payload, readErr := io.ReadAll(limited)
	closeErr := response.Body.Close()
	if readErr != nil {
		if closeErr != nil {
			return RoutingIncidentAck{}, routingObserverReasonTransport, errors.Join(readErr, fmt.Errorf("close routing incident response: %w", closeErr))
		}
		return RoutingIncidentAck{}, routingObserverReasonTransport, readErr
	}
	if closeErr != nil {
		return RoutingIncidentAck{}, routingObserverReasonTransport, fmt.Errorf("close routing incident response: %w", closeErr)
	}
	if len(payload) > routingIncidentMaxResponseBytes {
		return RoutingIncidentAck{}, routingObserverReasonAckMismatch, errors.New("routing incident ACK exceeds the response bound")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return RoutingIncidentAck{}, routingObserverReasonHTTPFailure, fmt.Errorf("routing incident hook returned HTTP %d", response.StatusCode)
	}
	var envelope routingIncidentAckEnvelope
	if err := decodeRoutingObserverJSON(payload, &envelope); err != nil {
		return RoutingIncidentAck{}, routingObserverReasonAckMismatch, err
	}
	return envelope.Item, "", nil
}

func (o *RoutingObserver) Close() {
	if o == nil {
		return
	}
	o.closeOnce.Do(func() {
		o.accepting.Store(false)
		deadline := time.Now().Add(time.Duration(o.cfg.ShutdownTimeoutMS) * time.Millisecond)
		close(o.workerStop)
		if !waitRoutingObserverChannel(o.workerDone, time.Until(deadline)) {
			o.shutdownTimedOut.Store(true)
		}
		close(o.senderStop)
		if o.cancelSender != nil {
			o.cancelSender()
		}
		if !waitRoutingObserverChannel(o.senderDone, time.Until(deadline)) {
			o.shutdownTimedOut.Store(true)
		}
	})
}

func waitRoutingObserverChannel(done <-chan struct{}, timeout time.Duration) bool {
	if timeout <= 0 {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
