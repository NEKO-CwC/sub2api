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
	routingAttemptObservationSchema = "routing-dispatch-attempt-observation.v2"
	routingAttemptHookSignature     = "routing-dispatch-attempt-hook.v1"
	routingAttemptMaxRowsPerRequest = 5000
	routingAttemptResponseDrainMax  = 64 << 10
)

type routingAttemptRow struct {
	AccountID        int64  `json:"account_id"`
	Attempt          int    `json:"attempt"`
	ErrorClass       string `json:"error_class,omitempty"`
	IsFinal          bool   `json:"is_final"`
	LogicalRequestID string `json:"logical_request_id"`
	ObservedAt       string `json:"observed_at"`
	Outcome          string `json:"outcome"`
	StatusCode       *int   `json:"status_code"`
	TTFTMs           *int   `json:"ttft_ms"`
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
	logicalRequestID string
	idempotencyKey   string
	attempts         []routingAttemptRow
	discarded        bool
}

type routingAttemptWebSocketRecorder struct {
	emitter      *RoutingAttemptEmitter
	groupID      int64
	initialModel string
	mu           sync.Mutex
	turns        map[int]*routingAttemptRecorder
}

func newRoutingAttemptWebSocketRecorder(emitter *RoutingAttemptEmitter, groupID int64, model string) *routingAttemptWebSocketRecorder {
	if emitter == nil || !emitter.Enabled() || groupID <= 0 || strings.TrimSpace(model) == "" {
		return nil
	}
	return &routingAttemptWebSocketRecorder{
		emitter: emitter, groupID: groupID, initialModel: strings.TrimSpace(model),
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
		recorder = newRoutingAttemptRecorder(r.emitter, r.groupID, model)
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

func newRoutingAttemptRecorder(emitter *RoutingAttemptEmitter, groupID int64, model string) *routingAttemptRecorder {
	if emitter == nil || !emitter.Enabled() {
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
		LogicalRequestID: r.logicalRequestID,
		Attempt:          len(r.attempts) + 1,
		ObservedAt:       observedAt.UTC().Format(time.RFC3339Nano),
		AccountID:        accountID,
		Outcome:          "success",
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
	cfg    config.GatewayRoutingAttemptEmitterConfig
	queue  chan routingAttemptChain
	client *http.Client
	stop   chan struct{}
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	submit sync.RWMutex
	closed atomic.Bool
	stats  emitterStats
}

type emitterStats struct {
	dropped  atomic.Uint64
	failures atomic.Uint64
	sent     atomic.Uint64
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
	ctx, cancel := context.WithCancel(context.Background())
	e := &RoutingAttemptEmitter{
		cfg:    cfg,
		queue:  make(chan routingAttemptChain, cfg.QueueSize),
		client: &http.Client{Timeout: time.Duration(cfg.RequestTimeoutMS) * time.Millisecond},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
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
	Enabled       bool   `json:"enabled"`
	Sent          uint64 `json:"sent"`
	Dropped       uint64 `json:"dropped"`
	Failures      uint64 `json:"failures"`
	QueueDepth    int    `json:"queue_depth"`
	QueueCapacity int    `json:"queue_capacity"`
}

func (e *RoutingAttemptEmitter) Stats() RoutingAttemptEmitterStats {
	if e == nil {
		return RoutingAttemptEmitterStats{}
	}
	return RoutingAttemptEmitterStats{
		Enabled:       e.cfg.Enabled && !e.closed.Load(),
		Dropped:       e.stats.dropped.Load(),
		Failures:      e.stats.failures.Load(),
		Sent:          e.stats.sent.Load(),
		QueueDepth:    len(e.queue),
		QueueCapacity: cap(e.queue),
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
		key := strconv.FormatInt(chain.GroupID, 10) + "\x00" + chain.Model
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
	identity := batchIdentity(chains)
	observation := map[string]any{
		"schema_version":  routingAttemptObservationSchema,
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
		e.stats.failures.Add(1)
		return
	}
	timestamp := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(e.cfg.Secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "."))
	mac.Write(payload)
	req, err := http.NewRequestWithContext(e.ctx, http.MethodPost, strings.TrimRight(e.cfg.PanelURL, "/")+"/api/account-ops/routing/dispatch/attempt-hook", bytes.NewReader(payload))
	if err != nil {
		e.stats.failures.Add(1)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Dispatch-Signature-Version", routingAttemptHookSignature)
	req.Header.Set("X-Dispatch-Timestamp", strconv.FormatInt(timestamp, 10))
	req.Header.Set("X-Dispatch-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	resp, err := e.client.Do(req)
	if err != nil {
		e.stats.failures.Add(1)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, routingAttemptResponseDrainMax))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		e.stats.failures.Add(1)
		return
	}
	e.stats.sent.Add(1)
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
		h.Write([]byte(chain.IdempotencyKey))
		h.Write([]byte{'\n'})
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
