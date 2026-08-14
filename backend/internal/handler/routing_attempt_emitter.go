package handler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	routingAttemptObservationSchemaV2 = "routing-dispatch-attempt-observation.v2"
	routingAttemptObservationSchemaV3 = "routing-dispatch-attempt-observation.v3"
	routingAttemptHookSignature       = "routing-dispatch-attempt-hook.v1"
	routingAttemptMaxRowsPerRequest   = 5000
	routingAttemptResponseDrainMax    = 64 << 10
	routingAttemptSendMaxAttempts     = 5
	routingCanaryCorrelationHeader    = "X-Neko-Canary-Correlation"
	routingCanaryCorrelationDomain    = "routing-canary-correlation.v1\x00"
	routingCanaryAPIKeyID             = int64(105)
	routingCanaryGroupID              = int64(30)
	routingCanaryNonceEncodedLength   = 43
	routingCanaryNonceDecodedLength   = 32
)

var routingAttemptRetryDelays = [...]time.Duration{
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
}

type routingAttemptFailureKind uint32

const (
	routingAttemptFailureNone routingAttemptFailureKind = iota
	routingAttemptFailureSerialization
	routingAttemptFailureTransport
	routingAttemptFailureHTTPStatus
	routingAttemptFailureShutdown
)

type routingAttemptRow struct {
	APIKeyID          int64   `json:"api_key_id,omitempty"`
	AccountID         int64   `json:"account_id"`
	Attempt           int     `json:"attempt"`
	CorrelationSHA256 *string `json:"correlation_sha256,omitempty"`
	ErrorClass        string  `json:"error_class,omitempty"`
	IsFinal           bool    `json:"is_final"`
	LogicalRequestID  string  `json:"logical_request_id"`
	ObservedAt        string  `json:"observed_at"`
	Outcome           string  `json:"outcome"`
	StatusCode        *int    `json:"status_code"`
	TTFTMs            *int    `json:"ttft_ms"`
}

type routingAttemptCorrelation struct {
	APIKeyID          int64
	CorrelationSHA256 string
}

var (
	errRoutingCanaryCorrelationMalformed = errors.New("invalid canary correlation header")
	errRoutingCanaryCorrelationForbidden = errors.New("canary correlation header is not permitted for this API key or group")
)

func consumeRoutingAttemptCorrelation(request *http.Request, apiKey *service.APIKey) (routingAttemptCorrelation, int, error) {
	if request == nil {
		return routingAttemptCorrelation{}, 0, nil
	}
	values := request.Header.Values(routingCanaryCorrelationHeader)
	request.Header.Del(routingCanaryCorrelationHeader)
	if len(values) == 0 {
		return routingAttemptCorrelation{}, 0, nil
	}
	if len(values) != 1 {
		return routingAttemptCorrelation{}, http.StatusBadRequest, errRoutingCanaryCorrelationMalformed
	}
	nonce := values[0]
	if len(nonce) != routingCanaryNonceEncodedLength {
		return routingAttemptCorrelation{}, http.StatusBadRequest, errRoutingCanaryCorrelationMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decoded) != routingCanaryNonceDecodedLength || base64.RawURLEncoding.EncodeToString(decoded) != nonce {
		return routingAttemptCorrelation{}, http.StatusBadRequest, errRoutingCanaryCorrelationMalformed
	}
	if apiKey == nil || apiKey.ID != routingCanaryAPIKeyID || apiKey.GroupID == nil || *apiKey.GroupID != routingCanaryGroupID {
		return routingAttemptCorrelation{}, http.StatusForbidden, errRoutingCanaryCorrelationForbidden
	}
	digest := sha256.Sum256([]byte(routingCanaryCorrelationDomain + nonce))
	return routingAttemptCorrelation{
		APIKeyID:          apiKey.ID,
		CorrelationSHA256: hex.EncodeToString(digest[:]),
	}, 0, nil
}

func validRoutingAttemptCorrelationForGroup(correlation routingAttemptCorrelation, groupID int64) bool {
	if correlation.APIKeyID == 0 && correlation.CorrelationSHA256 == "" {
		return true
	}
	return groupID == routingCanaryGroupID &&
		correlation.APIKeyID == routingCanaryAPIKeyID &&
		validRoutingCorrelationDigest(correlation.CorrelationSHA256)
}

type routingAttemptChain struct {
	GroupID          int64
	Model            string
	ObservedAt       time.Time
	IdempotencyKey   string
	LogicalRequestID string
	Attempts         []routingAttemptRow
}

type routingAttemptRecorder struct {
	emitter          *RoutingAttemptEmitter
	groupID          int64
	model            string
	correlation      routingAttemptCorrelation
	logicalRequestID string
	idempotencyKey   string
	attempts         []routingAttemptRow
	discarded        bool
}

type routingAttemptWebSocketRecorder struct {
	emitter      *RoutingAttemptEmitter
	groupID      int64
	initialModel string
	correlation  routingAttemptCorrelation
	mu           sync.Mutex
	turns        map[int]*routingAttemptRecorder
}

func newRoutingAttemptWebSocketRecorder(emitter *RoutingAttemptEmitter, groupID int64, model string, correlation routingAttemptCorrelation) *routingAttemptWebSocketRecorder {
	if emitter == nil || !emitter.AllowsGroup(groupID) || strings.TrimSpace(model) == "" || !validRoutingAttemptCorrelationForGroup(correlation, groupID) {
		return nil
	}
	return &routingAttemptWebSocketRecorder{
		emitter: emitter, groupID: groupID, initialModel: strings.TrimSpace(model), correlation: correlation,
		turns: make(map[int]*routingAttemptRecorder),
	}
}

func (r *routingAttemptWebSocketRecorder) record(turn int, accountID int64, result *service.OpenAIForwardResult, err error, observedAt time.Time) {
	if r == nil || turn <= 0 || accountID <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	recorder := r.turns[turn]
	if recorder == nil {
		model := r.initialModel
		if result != nil && strings.TrimSpace(result.Model) != "" {
			model = strings.TrimSpace(result.Model)
		}
		recorder = newRoutingAttemptRecorder(r.emitter, r.groupID, model, r.correlation)
		if recorder == nil {
			return
		}
		r.turns[turn] = recorder
	}
	recorder.record(accountID, result, err, observedAt)
	if turn == 1 && routingAttemptWillRetryAnotherAccount(err) {
		return
	}
	recorder.finish()
	delete(r.turns, turn)
}

func (r *routingAttemptWebSocketRecorder) finish() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for turn, recorder := range r.turns {
		recorder.finish()
		delete(r.turns, turn)
	}
}

func (r *routingAttemptWebSocketRecorder) discard() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for turn, recorder := range r.turns {
		recorder.discard()
		delete(r.turns, turn)
	}
}

func routingAttemptWillRetryAnotherAccount(err error) bool {
	var failoverErr *service.UpstreamFailoverError
	return errors.As(err, &failoverErr) && failoverErr.ShouldRetryNextAccount()
}

func newRoutingAttemptRecorder(emitter *RoutingAttemptEmitter, groupID int64, model string, correlation routingAttemptCorrelation) *routingAttemptRecorder {
	if emitter == nil || !emitter.AllowsGroup(groupID) || !validRoutingAttemptCorrelationForGroup(correlation, groupID) {
		return nil
	}
	chainID := uuid.NewString()
	// The request logger may preserve a client-supplied X-Request-ID. Use a
	// bounded server identifier so separate inbound HTTP requests can never
	// collapse into one chain when a client reuses that header.
	return &routingAttemptRecorder{
		emitter:          emitter,
		groupID:          groupID,
		model:            strings.TrimSpace(model),
		correlation:      correlation,
		logicalRequestID: chainID,
		idempotencyKey:   "gateway-attempt-" + chainID,
		attempts:         make([]routingAttemptRow, 0, 4),
	}
}

func (r *routingAttemptRecorder) record(accountID int64, result *service.OpenAIForwardResult, err error, observedAt time.Time) {
	if r == nil || accountID <= 0 {
		return
	}
	row := routingAttemptRow{
		APIKeyID:         r.correlation.APIKeyID,
		LogicalRequestID: r.logicalRequestID,
		Attempt:          len(r.attempts) + 1,
		ObservedAt:       observedAt.UTC().Format(time.RFC3339Nano),
		AccountID:        accountID,
		Outcome:          "success",
	}
	if r.correlation.CorrelationSHA256 != "" {
		digest := r.correlation.CorrelationSHA256
		row.CorrelationSHA256 = &digest
	}
	if result != nil {
		row.TTFTMs = result.FirstTokenMs
	}
	if err != nil {
		row.Outcome = "failure"
		row.ErrorClass = routingAttemptErrorClass(err)
		var failoverErr *service.UpstreamFailoverError
		if errors.As(err, &failoverErr) && failoverErr.StatusCode >= 100 && failoverErr.StatusCode <= 599 {
			status := failoverErr.StatusCode
			row.StatusCode = &status
		}
	} else if result == nil || !result.SucceededForScheduling() {
		row.Outcome = "failure"
		row.ErrorClass = routingAttemptTerminalErrorClass(result)
	}
	r.attempts = append(r.attempts, row)
}

func (r *routingAttemptRecorder) finish() {
	if r == nil || r.discarded || r.emitter == nil || r.groupID <= 0 || r.model == "" || len(r.attempts) == 0 {
		return
	}
	r.attempts[len(r.attempts)-1].IsFinal = true
	r.emitter.Submit(routingAttemptChain{
		GroupID:          r.groupID,
		Model:            r.model,
		ObservedAt:       time.Now().UTC(),
		IdempotencyKey:   r.idempotencyKey,
		LogicalRequestID: r.logicalRequestID,
		Attempts:         append([]routingAttemptRow(nil), r.attempts...),
	})
}

func (r *routingAttemptRecorder) discard() {
	if r == nil {
		return
	}
	r.discarded = true
	r.attempts = nil
}

func recordRoutingAttemptIfClientPresent(
	c *gin.Context,
	recorder *routingAttemptRecorder,
	accountID int64,
	result *service.OpenAIForwardResult,
	err error,
	observedAt time.Time,
) {
	if c == nil || c.Request == nil || c.Request.Context().Err() != nil {
		recorder.discard()
		return
	}
	recorder.record(accountID, result, err, observedAt)
}

func recordRoutingWebSocketAttemptIfClientPresent(
	c *gin.Context,
	recorder *routingAttemptWebSocketRecorder,
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

func routingAttemptErrorClass(err error) string {
	var failoverErr *service.UpstreamFailoverError
	if errors.As(err, &failoverErr) {
		if failoverErr.Reason != "" {
			return string(failoverErr.Reason)
		}
		if failoverErr.Stage != "" {
			return string(failoverErr.Stage)
		}
		if failoverErr.Scope != "" {
			return string(failoverErr.Scope)
		}
		return "upstream_failover"
	}
	return "gateway_error"
}

func routingAttemptTerminalErrorClass(result *service.OpenAIForwardResult) string {
	if result == nil {
		return "upstream_terminal_failure"
	}
	switch strings.TrimSpace(result.UpstreamTerminalEvent) {
	case "response.failed":
		return "upstream_terminal_response_failed"
	case "response.incomplete":
		return "upstream_terminal_response_incomplete"
	case "response.cancelled", "response.canceled":
		return "upstream_terminal_response_cancelled"
	default:
		return "upstream_terminal_failure"
	}
}

// RoutingAttemptEmitter is an opt-in, bounded, best-effort observer. It never
// runs synchronously in the relay path and drops on queue pressure.
type RoutingAttemptEmitter struct {
	cfg           config.GatewayRoutingAttemptEmitterConfig
	allowedGroups map[int64]struct{}
	queue         chan routingAttemptChain
	client        *http.Client
	stop          chan struct{}
	done          chan struct{}
	ctx           context.Context
	cancel        context.CancelFunc
	submit        sync.RWMutex
	closed        atomic.Bool
	stats         emitterStats
}

type emitterStats struct {
	dropped               atomic.Uint64
	failures              atomic.Uint64
	sent                  atomic.Uint64
	lastFailureAtUnixNano atomic.Int64
	lastFailureKind       atomic.Uint32
	lastFailureStatusCode atomic.Int64
}

func NewRoutingAttemptEmitter(cfg config.GatewayRoutingAttemptEmitterConfig) *RoutingAttemptEmitter {
	// The default-off path is deliberately nil: constructing a gateway handler
	// must not allocate queues, clients, UUIDs, or attempt slices when the
	// observer is disabled.
	if !cfg.Enabled {
		return nil
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 256
	}
	if cfg.QueueSize > config.GatewayRoutingAttemptEmitterMaxQueueSize {
		cfg.QueueSize = config.GatewayRoutingAttemptEmitterMaxQueueSize
	}
	if cfg.BatchSize <= 0 || cfg.BatchSize > cfg.QueueSize {
		cfg.BatchSize = minInt(32, cfg.QueueSize)
	}
	if cfg.BatchSize > config.GatewayRoutingAttemptEmitterMaxBatchSize {
		cfg.BatchSize = config.GatewayRoutingAttemptEmitterMaxBatchSize
	}
	if cfg.FlushIntervalMS <= 0 {
		cfg.FlushIntervalMS = 250
	}
	if cfg.FlushIntervalMS > config.GatewayRoutingAttemptEmitterMaxFlushIntervalMS {
		cfg.FlushIntervalMS = config.GatewayRoutingAttemptEmitterMaxFlushIntervalMS
	}
	if cfg.RequestTimeoutMS <= 0 {
		cfg.RequestTimeoutMS = 1000
	}
	if cfg.RequestTimeoutMS > config.GatewayRoutingAttemptEmitterMaxRequestTimeoutMS {
		cfg.RequestTimeoutMS = config.GatewayRoutingAttemptEmitterMaxRequestTimeoutMS
	}
	if cfg.ShutdownTimeoutMS <= 0 {
		cfg.ShutdownTimeoutMS = 5000
	}
	if cfg.ShutdownTimeoutMS > config.GatewayRoutingAttemptEmitterMaxShutdownTimeoutMS {
		cfg.ShutdownTimeoutMS = config.GatewayRoutingAttemptEmitterMaxShutdownTimeoutMS
	}
	if strings.TrimSpace(cfg.PanelURL) == "" || strings.TrimSpace(cfg.Secret) == "" || cfg.Sub2APIInstanceID <= 0 {
		return nil
	}
	allowedGroups := make(map[int64]struct{}, len(cfg.AllowedGroupIDs))
	for _, groupID := range cfg.AllowedGroupIDs {
		if groupID <= 0 {
			return nil
		}
		if _, exists := allowedGroups[groupID]; exists {
			return nil
		}
		allowedGroups[groupID] = struct{}{}
	}
	if len(allowedGroups) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &RoutingAttemptEmitter{
		cfg:           cfg,
		allowedGroups: allowedGroups,
		queue:         make(chan routingAttemptChain, cfg.QueueSize),
		client:        &http.Client{Timeout: time.Duration(cfg.RequestTimeoutMS) * time.Millisecond},
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
		ctx:           ctx,
		cancel:        cancel,
	}
	go e.run()
	return e
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func (e *RoutingAttemptEmitter) Submit(chain routingAttemptChain) bool {
	if e == nil || len(chain.Attempts) == 0 {
		return false
	}
	if len(chain.Attempts) > routingAttemptMaxRowsPerRequest {
		e.stats.dropped.Add(1)
		return false
	}
	e.submit.RLock()
	defer e.submit.RUnlock()
	if e.closed.Load() {
		return false
	}
	select {
	case e.queue <- chain:
		return true
	default:
		e.stats.dropped.Add(1)
		return false
	}
}

func (e *RoutingAttemptEmitter) Enabled() bool {
	return e != nil && e.cfg.Enabled && !e.closed.Load()
}

func (e *RoutingAttemptEmitter) AllowsGroup(groupID int64) bool {
	if !e.Enabled() || groupID <= 0 {
		return false
	}
	_, allowed := e.allowedGroups[groupID]
	return allowed
}

func (e *RoutingAttemptEmitter) Close() {
	if e == nil {
		return
	}
	e.submit.Lock()
	if e.closed.Swap(true) {
		e.submit.Unlock()
		return
	}
	close(e.stop)
	e.submit.Unlock()
	timer := time.NewTimer(time.Duration(e.cfg.ShutdownTimeoutMS) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-e.done:
		e.cancel()
	case <-timer.C:
		// Evidence is best effort. Cancel an in-flight HTTP request and let the
		// worker discard queued observations instead of extending process shutdown.
		e.cancel()
		select {
		case <-e.done:
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type RoutingAttemptEmitterStats struct {
	Enabled               bool   `json:"enabled"`
	Sent                  uint64 `json:"sent"`
	Dropped               uint64 `json:"dropped"`
	Failures              uint64 `json:"failures"`
	QueueDepth            int    `json:"queue_depth"`
	QueueCapacity         int    `json:"queue_capacity"`
	LastFailureAt         string `json:"last_failure_at,omitempty"`
	LastFailureKind       string `json:"last_failure_kind,omitempty"`
	LastFailureStatusCode int    `json:"last_failure_status_code,omitempty"`
}

func (e *RoutingAttemptEmitter) Stats() RoutingAttemptEmitterStats {
	if e == nil {
		return RoutingAttemptEmitterStats{}
	}
	stats := RoutingAttemptEmitterStats{
		Enabled:       e.cfg.Enabled && !e.closed.Load(),
		Dropped:       e.stats.dropped.Load(),
		Failures:      e.stats.failures.Load(),
		Sent:          e.stats.sent.Load(),
		QueueDepth:    len(e.queue),
		QueueCapacity: cap(e.queue),
	}
	if failedAt := e.stats.lastFailureAtUnixNano.Load(); failedAt > 0 {
		stats.LastFailureAt = time.Unix(0, failedAt).UTC().Format(time.RFC3339Nano)
		stats.LastFailureKind = routingAttemptFailureKindName(
			routingAttemptFailureKind(e.stats.lastFailureKind.Load()),
		)
		stats.LastFailureStatusCode = int(e.stats.lastFailureStatusCode.Load())
	}
	return stats
}

func (e *RoutingAttemptEmitter) recordFailure(kind routingAttemptFailureKind, statusCode int) {
	e.stats.lastFailureStatusCode.Store(int64(statusCode))
	e.stats.lastFailureKind.Store(uint32(kind))
	e.stats.lastFailureAtUnixNano.Store(time.Now().UTC().UnixNano())
	e.stats.failures.Add(1)
}

func routingAttemptFailureKindName(kind routingAttemptFailureKind) string {
	switch kind {
	case routingAttemptFailureSerialization:
		return "serialization"
	case routingAttemptFailureTransport:
		return "transport"
	case routingAttemptFailureHTTPStatus:
		return "http_status"
	case routingAttemptFailureShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}

func (e *RoutingAttemptEmitter) run() {
	defer close(e.done)
	ticker := time.NewTicker(time.Duration(e.cfg.FlushIntervalMS) * time.Millisecond)
	defer ticker.Stop()
	batch := make([]routingAttemptChain, 0, e.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		chains := batch
		batch = make([]routingAttemptChain, 0, e.cfg.BatchSize)
		e.sendGrouped(chains)
	}
	for {
		select {
		case <-e.ctx.Done():
			e.dropQueued(batch)
			return
		case item := <-e.queue:
			batch = append(batch, item)
			if len(batch) >= e.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-e.stop:
			// Close excludes concurrent Submit calls before closing stop. Drain every
			// chain that Submit already accepted, while preserving bounded batches.
			for {
				select {
				case <-e.ctx.Done():
					e.dropQueued(batch)
					return
				case item := <-e.queue:
					batch = append(batch, item)
					if len(batch) >= e.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (e *RoutingAttemptEmitter) dropQueued(batch []routingAttemptChain) {
	dropped := len(batch)
	for {
		select {
		case <-e.queue:
			dropped++
		default:
			if dropped > 0 {
				e.stats.dropped.Add(uint64(dropped))
			}
			return
		}
	}
}

func (e *RoutingAttemptEmitter) sendGrouped(chains []routingAttemptChain) {
	groups := make(map[string][]routingAttemptChain)
	order := make([]string, 0)
	for _, chain := range chains {
		_, contractKey, ok := routingAttemptChainContract(chain)
		if !ok {
			e.stats.dropped.Add(1)
			continue
		}
		key := strconv.FormatInt(chain.GroupID, 10) + "\x00" + chain.Model + "\x00" + contractKey
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], chain)
	}
	for _, key := range order {
		if e.ctx.Err() != nil {
			e.stats.dropped.Add(uint64(len(groups[key])))
			continue
		}
		e.sendBounded(groups[key])
	}
}

func (e *RoutingAttemptEmitter) sendBounded(chains []routingAttemptChain) {
	batch := make([]routingAttemptChain, 0, len(chains))
	rows := 0
	for _, chain := range chains {
		chainRows := len(chain.Attempts)
		if chainRows == 0 || chainRows > routingAttemptMaxRowsPerRequest {
			e.stats.dropped.Add(1)
			continue
		}
		if rows > 0 && rows+chainRows > routingAttemptMaxRowsPerRequest {
			e.send(batch)
			batch = batch[:0]
			rows = 0
		}
		batch = append(batch, chain)
		rows += chainRows
	}
	if len(batch) > 0 {
		e.send(batch)
	}
}

func (e *RoutingAttemptEmitter) send(chains []routingAttemptChain) {
	if len(chains) == 0 {
		return
	}
	schemaVersion, contractKey, ok := routingAttemptChainContract(chains[0])
	if !ok {
		e.stats.dropped.Add(uint64(len(chains)))
		return
	}
	for _, chain := range chains[1:] {
		chainSchema, chainContractKey, valid := routingAttemptChainContract(chain)
		if !valid || chainSchema != schemaVersion || chainContractKey != contractKey {
			e.stats.dropped.Add(uint64(len(chains)))
			return
		}
	}
	identity := batchIdentity(chains)
	observation := map[string]any{
		"schema_version":  schemaVersion,
		"group_id":        chains[0].GroupID,
		"model":           chains[0].Model,
		"observed_at":     chains[len(chains)-1].ObservedAt.UTC().Format(time.RFC3339Nano),
		"idempotency_key": identity,
		"attempts":        flattenChains(chains),
	}
	body := map[string]any{
		"sub2api_instance_id": e.cfg.Sub2APIInstanceID,
		"operation_id":        "routing-attempt-" + identity,
		"observation":         observation,
	}
	payload, err := canonicalJSON(body)
	if err != nil {
		e.recordFailure(routingAttemptFailureSerialization, 0)
		return
	}
	for attempt := 0; attempt < routingAttemptSendMaxAttempts; attempt++ {
		statusCode, err := e.sendPayload(payload)
		if err != nil {
			if e.ctx.Err() != nil {
				e.recordFailure(routingAttemptFailureShutdown, 0)
				return
			}
			if attempt == routingAttemptSendMaxAttempts-1 {
				e.recordFailure(routingAttemptFailureTransport, 0)
				return
			}
		} else {
			if statusCode >= 200 && statusCode < 300 {
				e.stats.sent.Add(1)
				return
			}
			if !routingAttemptRetryableStatus(statusCode) || attempt == routingAttemptSendMaxAttempts-1 {
				e.recordFailure(routingAttemptFailureHTTPStatus, statusCode)
				return
			}
		}
		select {
		case <-e.ctx.Done():
			e.recordFailure(routingAttemptFailureShutdown, 0)
			return
		case <-time.After(routingAttemptRetryDelays[attempt]):
		}
	}
}

func routingAttemptChainContract(chain routingAttemptChain) (string, string, bool) {
	if len(chain.Attempts) == 0 {
		return "", "", false
	}
	first := chain.Attempts[0]
	if first.APIKeyID == 0 && first.CorrelationSHA256 == nil {
		for _, attempt := range chain.Attempts[1:] {
			if attempt.APIKeyID != 0 || attempt.CorrelationSHA256 != nil {
				return "", "", false
			}
		}
		return routingAttemptObservationSchemaV2, routingAttemptObservationSchemaV2, true
	}
	if chain.GroupID != routingCanaryGroupID || first.APIKeyID != routingCanaryAPIKeyID || first.CorrelationSHA256 == nil || !validRoutingCorrelationDigest(*first.CorrelationSHA256) {
		return "", "", false
	}
	digest := *first.CorrelationSHA256
	for _, attempt := range chain.Attempts[1:] {
		if attempt.APIKeyID != first.APIKeyID || attempt.CorrelationSHA256 == nil || *attempt.CorrelationSHA256 != digest {
			return "", "", false
		}
	}
	return routingAttemptObservationSchemaV3, routingAttemptObservationSchemaV3 + "\x00" + strconv.FormatInt(first.APIKeyID, 10) + "\x00" + digest, true
}

func validRoutingCorrelationDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func (e *RoutingAttemptEmitter) sendPayload(payload []byte) (int, error) {
	timestamp := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(e.cfg.Secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	_, _ = mac.Write(payload)
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, strings.TrimRight(e.cfg.PanelURL, "/")+"/api/account-ops/routing/dispatch/attempt-hook", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dispatch-Signature-Version", routingAttemptHookSignature)
	req.Header.Set("X-Dispatch-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Dispatch-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := e.client.Do(req)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, routingAttemptResponseDrainMax))
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func routingAttemptRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func flattenChains(chains []routingAttemptChain) []routingAttemptRow {
	rows := make([]routingAttemptRow, 0)
	for _, chain := range chains {
		rows = append(rows, chain.Attempts...)
	}
	return rows
}

func batchIdentity(chains []routingAttemptChain) string {
	h := sha256.New()
	for _, chain := range chains {
		_, _ = h.Write([]byte(chain.IdempotencyKey))
		_, _ = h.Write([]byte{'\n'})
	}
	return "batch-" + hex.EncodeToString(h.Sum(nil))
}

func canonicalJSON(value any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return nil, err
	}
	payload := bytes.TrimSpace(buf.Bytes())
	// Python's ensure_ascii=False (used by the Panel verifier) emits these two
	// valid UTF-8 separators literally, while encoding/json always escapes them.
	payload = bytes.ReplaceAll(payload, []byte(`\u2028`), []byte("\u2028"))
	payload = bytes.ReplaceAll(payload, []byte(`\u2029`), []byte("\u2029"))
	return payload, nil
}
