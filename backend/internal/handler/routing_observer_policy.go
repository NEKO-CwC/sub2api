package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

const (
	RoutingObserverScopeContractV1 = "routing-observer-scope.v1"
	RoutingPolicySetContractV1     = "routing-policy-set.v1"
	RoutingCriticalFailureRuleV1   = "critical.failure-fallback-observed.v1"

	RoutingMetricCompleteFailureChain = "complete_failure_chain"
	RoutingOperatorGTE                = "gte"
	RoutingActionHardFailover         = "hard_failover"

	routingObserverMaxAccounts = 32
	routingObserverMaxRules    = 16
	routingObserverMaxAliases  = 32
)

var (
	routingObserverIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	routingObserverDigestPattern     = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
)

type RoutingTrafficOrigin string

const (
	RoutingTrafficOriginUser       RoutingTrafficOrigin = "user"
	RoutingTrafficOriginMonitor    RoutingTrafficOrigin = "monitor"
	RoutingTrafficOriginUserCanary RoutingTrafficOrigin = "user_canary"
)

type RoutingAccountRole string

const (
	RoutingAccountRolePrimary   RoutingAccountRole = "primary"
	RoutingAccountRoleFallback  RoutingAccountRole = "fallback"
	RoutingAccountRoleCandidate RoutingAccountRole = "candidate"
)

type RoutingOutcome string

const (
	RoutingOutcomeSuccess RoutingOutcome = "success"
	RoutingOutcomeFailure RoutingOutcome = "failure"
)

type RoutingEvaluationState string

const (
	RoutingEvaluationIgnored      RoutingEvaluationState = "ignored"
	RoutingEvaluationNotMatched   RoutingEvaluationState = "not_matched"
	RoutingEvaluationInsufficient RoutingEvaluationState = "insufficient_evidence"
	RoutingEvaluationMatched      RoutingEvaluationState = "matched"
)

type RoutingScopeRoles struct {
	PrimaryAccountIDs   []int64 `json:"primary_account_ids"`
	FallbackAccountIDs  []int64 `json:"fallback_account_ids"`
	CandidateAccountIDs []int64 `json:"candidate_account_ids"`
}

type RoutingScopeTrafficOrigin struct {
	MonitorAPIKeyIDs        []int64 `json:"monitor_api_key_ids"`
	CanaryAPIKeyIDs         []int64 `json:"canary_api_key_ids"`
	CanaryLoopIDHash        string  `json:"canary_loop_id_hash,omitempty"`
	CanaryMaxLogicalRequest int     `json:"canary_max_logical_requests"`
}

type RoutingPolicyWindow struct {
	Kind           string `json:"kind"`
	Seconds        int    `json:"seconds"`
	MinimumSamples int    `json:"minimum_samples"`
}

type RoutingPolicyRule struct {
	RuleID     string              `json:"rule_id"`
	Enabled    bool                `json:"enabled"`
	Metric     string              `json:"metric"`
	Operator   string              `json:"operator"`
	Threshold  string              `json:"threshold"`
	Window     RoutingPolicyWindow `json:"window"`
	Severity   string              `json:"severity"`
	Precedence int                 `json:"precedence"`
	Action     string              `json:"action"`
	ReasonCode string              `json:"reason_code"`
}

type RoutingPolicySet struct {
	ContractVersion string              `json:"contract_version"`
	PolicyID        string              `json:"policy_id"`
	Revision        int64               `json:"revision"`
	Rules           []RoutingPolicyRule `json:"rules"`
}

type RoutingManagedScope struct {
	ContractVersion     string                    `json:"contract_version"`
	Enabled             bool                      `json:"enabled"`
	Sub2APIInstanceID   int64                     `json:"sub2api_instance_id"`
	GroupID             int64                     `json:"group_id"`
	CanonicalModel      string                    `json:"canonical_model"`
	ModelAliases        []string                  `json:"model_aliases"`
	RouteVersion        int64                     `json:"route_version"`
	TopologyFingerprint string                    `json:"topology_fingerprint"`
	ScopeRevision       int64                     `json:"scope_revision"`
	Roles               RoutingScopeRoles         `json:"roles"`
	TrafficOrigin       RoutingScopeTrafficOrigin `json:"traffic_origin"`
	Policy              RoutingPolicySet          `json:"policy"`
	ExpectedPolicyHash  string                    `json:"expected_policy_hash,omitempty"`
	ExpectedCurrentHash string                    `json:"expected_current_hash,omitempty"`
	ExpectedOperationID string                    `json:"operation_id,omitempty"`
	ScopeHash           string                    `json:"-"`
}

type RoutingAttemptFact struct {
	AccountID      int64                        `json:"account_id"`
	AccountRole    RoutingAccountRole           `json:"account_role"`
	AttemptIndex   int                          `json:"attempt_index"`
	Final          bool                         `json:"final"`
	Outcome        RoutingOutcome               `json:"outcome"`
	Stage          service.GatewayFailureStage  `json:"stage,omitempty"`
	Scope          service.GatewayFailureScope  `json:"scope,omitempty"`
	Reason         service.GatewayFailureReason `json:"reason,omitempty"`
	NextAccount    service.NextAccountAction    `json:"next_account_action"`
	ObservedAt     time.Time                    `json:"observed_at"`
	TTFTMillis     *int                         `json:"ttft_ms,omitempty"`
	EvidenceDigest string                       `json:"evidence_digest"`
}

type RoutingFailoverHandoffFact struct {
	OriginalPrimaryAccountID int64     `json:"original_primary_account_id"`
	FallbackAccountID        int64     `json:"fallback_account_id"`
	PrimaryConcurrency       int       `json:"primary_concurrency"`
	FallbackConcurrency      int       `json:"fallback_concurrency"`
	WindowIdentity           string    `json:"window_identity"`
	ObservedAt               time.Time `json:"observed_at"`
	Complete                 bool      `json:"complete"`
}

type RoutingRequestFact struct {
	ObservedAt          time.Time                   `json:"observed_at"`
	Sub2APIInstanceID   int64                       `json:"sub2api_instance_id"`
	ScopeRevision       int64                       `json:"scope_revision"`
	ScopeHash           string                      `json:"scope_hash"`
	RouteVersion        int64                       `json:"route_version"`
	TopologyFingerprint string                      `json:"topology_fingerprint"`
	GroupID             int64                       `json:"group_id"`
	CanonicalModel      string                      `json:"canonical_model"`
	TrafficOrigin       RoutingTrafficOrigin        `json:"traffic_origin"`
	Attempts            []RoutingAttemptFact        `json:"attempts"`
	Handoff             *RoutingFailoverHandoffFact `json:"handoff,omitempty"`
	Gap                 bool                        `json:"gap"`
}

type RoutingRuleEvaluation struct {
	RuleID        string                 `json:"rule_id"`
	State         RoutingEvaluationState `json:"state"`
	ReasonCode    string                 `json:"reason_code"`
	MetricValue   int64                  `json:"metric_value"`
	Severity      string                 `json:"severity"`
	Precedence    int                    `json:"precedence"`
	Action        string                 `json:"action"`
	EvidenceCount int                    `json:"evidence_count"`
	Evidence      []string               `json:"evidence_digests,omitempty"`
}

type RoutingPolicyDecision struct {
	EligibilityState  RoutingEvaluationState  `json:"eligibility_state"`
	EligibilityReason string                  `json:"eligibility_reason"`
	PolicyHash        string                  `json:"policy_hash"`
	Evaluations       []RoutingRuleEvaluation `json:"evaluations"`
	Winner            *RoutingRuleEvaluation  `json:"winner,omitempty"`
}

type RoutingIdentityResolution string

const (
	RoutingIdentityNew       RoutingIdentityResolution = "new"
	RoutingIdentityDuplicate RoutingIdentityResolution = "duplicate"
	RoutingIdentityConflict  RoutingIdentityResolution = "conflict"
)

func ResolveRoutingIdentity(existingIdentity, existingPayloadHash, incomingIdentity, incomingPayloadHash string) (RoutingIdentityResolution, error) {
	if !routingObserverDigestPattern.MatchString(incomingIdentity) || !validRoutingSHA256(incomingPayloadHash) {
		return "", errors.New("routing identity input is invalid")
	}
	if existingIdentity == "" && existingPayloadHash == "" {
		return RoutingIdentityNew, nil
	}
	if !routingObserverDigestPattern.MatchString(existingIdentity) || !validRoutingSHA256(existingPayloadHash) {
		return "", errors.New("stored routing identity is invalid")
	}
	if existingIdentity != incomingIdentity {
		return RoutingIdentityNew, nil
	}
	if hmac.Equal([]byte(existingPayloadHash), []byte(incomingPayloadHash)) {
		return RoutingIdentityDuplicate, nil
	}
	return RoutingIdentityConflict, nil
}

type routingMetricResult struct {
	State      RoutingEvaluationState
	ReasonCode string
	Value      int64
	Evidence   []string
}

type RoutingMetricAdapter interface {
	MetricName() string
	Evaluate(RoutingRequestFact) routingMetricResult
}

type ValidatedRoutingPolicy struct {
	Policy RoutingPolicySet
	Hash   string
}

type RoutingPolicyRegistry struct {
	mu       sync.RWMutex
	metrics  map[string]RoutingMetricAdapter
	lastGood *ValidatedRoutingPolicy
}

func NewRoutingPolicyRegistry(adapters ...RoutingMetricAdapter) *RoutingPolicyRegistry {
	registry := &RoutingPolicyRegistry{metrics: make(map[string]RoutingMetricAdapter)}
	for _, adapter := range adapters {
		if adapter == nil || !routingObserverIdentifierPattern.MatchString(adapter.MetricName()) {
			continue
		}
		registry.metrics[adapter.MetricName()] = adapter
	}
	return registry
}

func NewDefaultRoutingPolicyRegistry() *RoutingPolicyRegistry {
	return NewRoutingPolicyRegistry(criticalFailureMetricAdapter{})
}

func DecodeRoutingPolicySet(payload []byte) (RoutingPolicySet, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var policy RoutingPolicySet
	if err := decoder.Decode(&policy); err != nil {
		return RoutingPolicySet{}, fmt.Errorf("routing policy schema is invalid: %w", err)
	}
	if err := ensureRoutingJSONEOF(decoder); err != nil {
		return RoutingPolicySet{}, err
	}
	return policy, nil
}

func ensureRoutingJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("routing policy trailing data is invalid: %w", err)
	}
	return errors.New("routing policy contains multiple JSON values")
}

func (r *RoutingPolicyRegistry) ValidateAndLoad(policy RoutingPolicySet) (ValidatedRoutingPolicy, error) {
	if r == nil {
		return ValidatedRoutingPolicy{}, errors.New("routing policy registry is unavailable")
	}
	r.mu.RLock()
	metrics := make(map[string]RoutingMetricAdapter, len(r.metrics))
	for name, adapter := range r.metrics {
		metrics[name] = adapter
	}
	r.mu.RUnlock()
	if err := validateRoutingPolicy(policy, metrics); err != nil {
		return ValidatedRoutingPolicy{}, err
	}
	hash, err := routingCanonicalHash(policy)
	if err != nil {
		return ValidatedRoutingPolicy{}, err
	}
	validated := ValidatedRoutingPolicy{Policy: cloneRoutingPolicy(policy), Hash: hash}
	r.mu.Lock()
	r.lastGood = &validated
	r.mu.Unlock()
	return validated, nil
}

func (r *RoutingPolicyRegistry) LastKnownGood() (ValidatedRoutingPolicy, bool) {
	if r == nil {
		return ValidatedRoutingPolicy{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.lastGood == nil {
		return ValidatedRoutingPolicy{}, false
	}
	value := *r.lastGood
	value.Policy = cloneRoutingPolicy(value.Policy)
	return value, true
}

func (r *RoutingPolicyRegistry) Evaluate(scope RoutingManagedScope, fact RoutingRequestFact) RoutingPolicyDecision {
	decision := RoutingPolicyDecision{}
	validated, ok := r.LastKnownGood()
	if !ok {
		decision.EligibilityState = RoutingEvaluationInsufficient
		decision.EligibilityReason = "policy_unavailable"
		return decision
	}
	decision.PolicyHash = validated.Hash
	state, reason := scope.Classify(fact)
	decision.EligibilityState = state
	decision.EligibilityReason = reason
	if state != RoutingEvaluationMatched {
		return decision
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, rule := range validated.Policy.Rules {
		if !rule.Enabled {
			continue
		}
		adapter := r.metrics[rule.Metric]
		result := adapter.Evaluate(fact)
		evaluation := RoutingRuleEvaluation{
			RuleID: rule.RuleID, State: result.State, ReasonCode: result.ReasonCode,
			MetricValue: result.Value, Severity: rule.Severity, Precedence: rule.Precedence,
			Action: rule.Action, EvidenceCount: len(result.Evidence), Evidence: append([]string(nil), result.Evidence...),
		}
		threshold, _ := strconv.ParseInt(rule.Threshold, 10, 64)
		if result.State == RoutingEvaluationMatched && result.Value < threshold {
			evaluation.State = RoutingEvaluationNotMatched
			evaluation.ReasonCode = "metric_below_threshold"
		}
		decision.Evaluations = append(decision.Evaluations, evaluation)
	}
	matched := make([]RoutingRuleEvaluation, 0, len(decision.Evaluations))
	for _, evaluation := range decision.Evaluations {
		if evaluation.State == RoutingEvaluationMatched {
			matched = append(matched, evaluation)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		left, right := matched[i], matched[j]
		if routingSeverityRank(left.Severity) != routingSeverityRank(right.Severity) {
			return routingSeverityRank(left.Severity) < routingSeverityRank(right.Severity)
		}
		if left.Precedence != right.Precedence {
			return left.Precedence < right.Precedence
		}
		return left.RuleID < right.RuleID
	})
	if len(matched) > 0 {
		winner := matched[0]
		decision.Winner = &winner
	}
	return decision
}

func validateRoutingPolicy(policy RoutingPolicySet, metrics map[string]RoutingMetricAdapter) error {
	if policy.ContractVersion != RoutingPolicySetContractV1 {
		return errors.New("routing policy contract_version is unsupported")
	}
	if !routingObserverIdentifierPattern.MatchString(policy.PolicyID) {
		return errors.New("routing policy id is invalid")
	}
	if policy.Revision <= 0 {
		return errors.New("routing policy revision must be positive")
	}
	if len(policy.Rules) == 0 || len(policy.Rules) > routingObserverMaxRules {
		return fmt.Errorf("routing policy rules must contain 1..%d items", routingObserverMaxRules)
	}
	seen := make(map[string]struct{}, len(policy.Rules))
	for _, rule := range policy.Rules {
		if !routingObserverIdentifierPattern.MatchString(rule.RuleID) {
			return errors.New("routing policy rule id is invalid")
		}
		if _, exists := seen[rule.RuleID]; exists {
			return errors.New("routing policy contains duplicate rule id")
		}
		seen[rule.RuleID] = struct{}{}
		if _, exists := metrics[rule.Metric]; !exists {
			return fmt.Errorf("routing policy metric %q is not registered", rule.Metric)
		}
		if rule.Operator != RoutingOperatorGTE {
			return fmt.Errorf("routing policy operator %q is not registered", rule.Operator)
		}
		threshold, err := strconv.ParseInt(rule.Threshold, 10, 64)
		if err != nil || threshold <= 0 || strconv.FormatInt(threshold, 10) != rule.Threshold {
			return errors.New("routing policy threshold must be a canonical positive integer string")
		}
		if rule.Window.Kind != "logical_request" || rule.Window.Seconds != 0 || rule.Window.MinimumSamples != 1 {
			return errors.New("routing policy window is unsupported")
		}
		if routingSeverityRank(rule.Severity) >= 100 {
			return errors.New("routing policy severity is unsupported")
		}
		if rule.Precedence < 0 {
			return errors.New("routing policy precedence must be non-negative")
		}
		if rule.Action != RoutingActionHardFailover {
			return fmt.Errorf("routing policy action %q is not registered", rule.Action)
		}
		if !routingObserverIdentifierPattern.MatchString(rule.ReasonCode) {
			return errors.New("routing policy reason_code is invalid")
		}
	}
	return nil
}

func routingSeverityRank(value string) int {
	switch value {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 100
	}
}

func DefaultRoutingFailurePolicy() RoutingPolicySet {
	return RoutingPolicySet{
		ContractVersion: RoutingPolicySetContractV1,
		PolicyID:        "pro-failure-v1",
		Revision:        1,
		Rules: []RoutingPolicyRule{{
			RuleID: RoutingCriticalFailureRuleV1, Enabled: true,
			Metric: RoutingMetricCompleteFailureChain, Operator: RoutingOperatorGTE, Threshold: "1",
			Window:   RoutingPolicyWindow{Kind: "logical_request", Seconds: 0, MinimumSamples: 1},
			Severity: "critical", Precedence: 0, Action: RoutingActionHardFailover,
			ReasonCode: "complete_primary_failure_fallback_serving",
		}},
	}
}

func (s RoutingManagedScope) Validate(registry *RoutingPolicyRegistry) (string, error) {
	if s.ContractVersion != RoutingObserverScopeContractV1 {
		return "", errors.New("routing observer scope contract_version is unsupported")
	}
	if s.Sub2APIInstanceID <= 0 || s.GroupID <= 0 || s.ScopeRevision <= 0 || s.RouteVersion <= 0 {
		return "", errors.New("routing observer scope identities and revisions must be positive")
	}
	if strings.TrimSpace(s.CanonicalModel) == "" || strings.TrimSpace(s.CanonicalModel) != s.CanonicalModel {
		return "", errors.New("routing observer canonical model is invalid")
	}
	if len(s.ModelAliases) == 0 || len(s.ModelAliases) > routingObserverMaxAliases {
		return "", errors.New("routing observer model aliases are invalid")
	}
	models := make(map[string]struct{}, len(s.ModelAliases)+1)
	models[s.CanonicalModel] = struct{}{}
	for _, model := range s.ModelAliases {
		if model == "" || strings.TrimSpace(model) != model {
			return "", errors.New("routing observer model alias is invalid")
		}
		if _, exists := models[model]; exists && model != s.CanonicalModel {
			return "", errors.New("routing observer model aliases contain duplicates")
		}
		models[model] = struct{}{}
	}
	if !validRoutingSHA256(s.TopologyFingerprint) {
		return "", errors.New("routing observer topology fingerprint is invalid")
	}
	if err := validateRoutingScopeIDs(s.Roles, s.TrafficOrigin); err != nil {
		return "", err
	}
	validated, err := registry.ValidateAndLoad(s.Policy)
	if err != nil {
		return "", err
	}
	if s.ExpectedPolicyHash != "" && s.ExpectedPolicyHash != validated.Hash {
		return "", errors.New("routing observer expected policy hash does not match")
	}
	hash, err := routingCanonicalHash(struct {
		ContractVersion     string                    `json:"contract_version"`
		Enabled             bool                      `json:"enabled"`
		Sub2APIInstanceID   int64                     `json:"sub2api_instance_id"`
		GroupID             int64                     `json:"group_id"`
		CanonicalModel      string                    `json:"canonical_model"`
		ModelAliases        []string                  `json:"model_aliases"`
		RouteVersion        int64                     `json:"route_version"`
		TopologyFingerprint string                    `json:"topology_fingerprint"`
		ScopeRevision       int64                     `json:"scope_revision"`
		Roles               RoutingScopeRoles         `json:"roles"`
		TrafficOrigin       RoutingScopeTrafficOrigin `json:"traffic_origin"`
		PolicyHash          string                    `json:"policy_hash"`
	}{
		s.ContractVersion, s.Enabled, s.Sub2APIInstanceID, s.GroupID, s.CanonicalModel,
		append([]string(nil), s.ModelAliases...), s.RouteVersion, s.TopologyFingerprint,
		s.ScopeRevision, cloneRoutingRoles(s.Roles), cloneRoutingTrafficOrigin(s.TrafficOrigin), validated.Hash,
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

func validateRoutingScopeIDs(roles RoutingScopeRoles, origins RoutingScopeTrafficOrigin) error {
	if len(roles.PrimaryAccountIDs) == 0 || len(roles.FallbackAccountIDs) == 0 {
		return errors.New("routing observer scope requires primary and fallback accounts")
	}
	if len(roles.PrimaryAccountIDs)+len(roles.FallbackAccountIDs)+len(roles.CandidateAccountIDs) > routingObserverMaxAccounts {
		return errors.New("routing observer scope account limit exceeded")
	}
	seen := make(map[int64]string)
	for role, ids := range map[string][]int64{
		"primary": roles.PrimaryAccountIDs, "fallback": roles.FallbackAccountIDs, "candidate": roles.CandidateAccountIDs,
	} {
		for _, id := range ids {
			if id <= 0 {
				return errors.New("routing observer scope account id must be positive")
			}
			if previous, exists := seen[id]; exists {
				return fmt.Errorf("routing observer account %d overlaps %s and %s", id, previous, role)
			}
			seen[id] = role
		}
	}
	keys := make(map[int64]struct{})
	for _, ids := range [][]int64{origins.MonitorAPIKeyIDs, origins.CanaryAPIKeyIDs} {
		if len(ids) > routingObserverMaxAccounts {
			return errors.New("routing observer traffic-origin key limit exceeded")
		}
		for _, id := range ids {
			if id <= 0 {
				return errors.New("routing observer traffic-origin key id must be positive")
			}
			if _, exists := keys[id]; exists {
				return errors.New("routing observer traffic-origin key ids overlap")
			}
			keys[id] = struct{}{}
		}
	}
	if origins.CanaryLoopIDHash == "" && origins.CanaryMaxLogicalRequest != 0 {
		return errors.New("routing observer canary request bound requires a loop hash")
	}
	if origins.CanaryLoopIDHash != "" {
		if !validRoutingSHA256(origins.CanaryLoopIDHash) || origins.CanaryMaxLogicalRequest <= 0 {
			return errors.New("routing observer canary loop contract is invalid")
		}
	}
	return nil
}

func (s RoutingManagedScope) TrafficOriginForAPIKey(apiKeyID int64, validCanaryCorrelation bool) (RoutingTrafficOrigin, string) {
	for _, id := range s.TrafficOrigin.MonitorAPIKeyIDs {
		if id == apiKeyID {
			return RoutingTrafficOriginMonitor, "monitor_traffic"
		}
	}
	for _, id := range s.TrafficOrigin.CanaryAPIKeyIDs {
		if id == apiKeyID {
			if validCanaryCorrelation && s.TrafficOrigin.CanaryLoopIDHash != "" && s.TrafficOrigin.CanaryMaxLogicalRequest > 0 {
				return RoutingTrafficOriginUserCanary, "eligible_user_canary"
			}
			return RoutingTrafficOriginMonitor, "canary_correlation_invalid"
		}
	}
	return RoutingTrafficOriginUser, "eligible_user"
}

func (s RoutingManagedScope) Classify(fact RoutingRequestFact) (RoutingEvaluationState, string) {
	if !s.Enabled {
		return RoutingEvaluationIgnored, "scope_disabled"
	}
	if fact.Sub2APIInstanceID != s.Sub2APIInstanceID {
		return RoutingEvaluationIgnored, "instance_mismatch"
	}
	if fact.GroupID != s.GroupID {
		return RoutingEvaluationIgnored, "group_mismatch"
	}
	modelAllowed := fact.CanonicalModel == s.CanonicalModel
	if !modelAllowed {
		for _, alias := range s.ModelAliases {
			if fact.CanonicalModel == alias {
				modelAllowed = true
				break
			}
		}
	}
	if !modelAllowed {
		return RoutingEvaluationIgnored, "unmanaged_model"
	}
	if fact.RouteVersion != s.RouteVersion || fact.ScopeRevision != s.ScopeRevision || fact.TopologyFingerprint != s.TopologyFingerprint {
		return RoutingEvaluationIgnored, "route_scope_mismatch"
	}
	if s.ScopeHash != "" && fact.ScopeHash != s.ScopeHash {
		return RoutingEvaluationIgnored, "scope_hash_mismatch"
	}
	if fact.TrafficOrigin == RoutingTrafficOriginMonitor {
		return RoutingEvaluationIgnored, "monitor_traffic"
	}
	if fact.TrafficOrigin != RoutingTrafficOriginUser && fact.TrafficOrigin != RoutingTrafficOriginUserCanary {
		return RoutingEvaluationIgnored, "traffic_origin_unmanaged"
	}
	if len(fact.Attempts) == 0 {
		return RoutingEvaluationIgnored, "pre_upstream_request_error"
	}
	for _, attempt := range fact.Attempts {
		role, ok := s.RoleForAccount(attempt.AccountID)
		if !ok || role != attempt.AccountRole {
			return RoutingEvaluationIgnored, "account_role_mismatch"
		}
	}
	return RoutingEvaluationMatched, "eligible"
}

func (s RoutingManagedScope) RoleForAccount(accountID int64) (RoutingAccountRole, bool) {
	for _, id := range s.Roles.PrimaryAccountIDs {
		if id == accountID {
			return RoutingAccountRolePrimary, true
		}
	}
	for _, id := range s.Roles.FallbackAccountIDs {
		if id == accountID {
			return RoutingAccountRoleFallback, true
		}
	}
	for _, id := range s.Roles.CandidateAccountIDs {
		if id == accountID {
			return RoutingAccountRoleCandidate, true
		}
	}
	return "", false
}

type criticalFailureMetricAdapter struct{}

func (criticalFailureMetricAdapter) MetricName() string { return RoutingMetricCompleteFailureChain }

func (criticalFailureMetricAdapter) Evaluate(fact RoutingRequestFact) routingMetricResult {
	if fact.Gap {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "request_fact_gap"}
	}
	if len(fact.Attempts) == 0 {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "failure_chain_incomplete"}
	}
	finalIndex := -1
	var primaryFailure *RoutingAttemptFact
	for index := range fact.Attempts {
		attempt := &fact.Attempts[index]
		if attempt.AttemptIndex != index+1 || attempt.AccountID <= 0 || attempt.ObservedAt.IsZero() || !routingObserverDigestPattern.MatchString(attempt.EvidenceDigest) {
			return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "attempt_attribution_incomplete"}
		}
		if attempt.Final {
			if finalIndex >= 0 {
				return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "multiple_final_attempts"}
			}
			finalIndex = index
		}
		if attempt.AccountRole == RoutingAccountRolePrimary && attempt.Outcome == RoutingOutcomeFailure {
			if attempt.Stage != service.GatewayFailureStageInference && attempt.Stage != service.GatewayFailureStageAccountAuth {
				return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "failure_stage_untyped"}
			}
			if attempt.Scope != service.GatewayFailureScopeAccount || attempt.NextAccount != service.NextAccountRetry || strings.TrimSpace(string(attempt.Reason)) == "" {
				return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "failure_not_account_failover"}
			}
			primaryFailure = attempt
		}
	}
	if finalIndex != len(fact.Attempts)-1 {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "final_attempt_missing_or_not_terminal"}
	}
	if len(fact.Attempts) == 1 && fact.Attempts[0].Outcome == RoutingOutcomeFailure {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "failure_chain_incomplete"}
	}
	final := fact.Attempts[finalIndex]
	if primaryFailure == nil {
		return routingMetricResult{State: RoutingEvaluationNotMatched, ReasonCode: "original_primary_failure_missing"}
	}
	if final.AccountRole != RoutingAccountRoleFallback || final.Outcome != RoutingOutcomeSuccess {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "fallback_final_success_missing"}
	}
	if fact.Handoff == nil || !fact.Handoff.Complete || strings.TrimSpace(fact.Handoff.WindowIdentity) == "" || fact.Handoff.ObservedAt.IsZero() {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "concurrency_handoff_missing"}
	}
	handoff := fact.Handoff
	if handoff.OriginalPrimaryAccountID != primaryFailure.AccountID || handoff.FallbackAccountID != final.AccountID {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "concurrency_handoff_role_mismatch"}
	}
	if handoff.PrimaryConcurrency < 0 || handoff.FallbackConcurrency < 0 {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "concurrency_handoff_invalid"}
	}
	if handoff.PrimaryConcurrency == 0 && handoff.FallbackConcurrency == 0 {
		return routingMetricResult{State: RoutingEvaluationNotMatched, ReasonCode: "idle"}
	}
	if handoff.PrimaryConcurrency > 0 && handoff.FallbackConcurrency > 0 {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "overlapping_timeline"}
	}
	if handoff.PrimaryConcurrency != 0 || handoff.FallbackConcurrency <= 0 {
		return routingMetricResult{State: RoutingEvaluationInsufficient, ReasonCode: "failover_handoff_not_proven"}
	}
	return routingMetricResult{
		State: RoutingEvaluationMatched, ReasonCode: "complete_primary_failure_fallback_serving", Value: 1,
		Evidence: []string{primaryFailure.EvidenceDigest, final.EvidenceDigest},
	}
}

func routingCanonicalHash(value any) (string, error) {
	payload, err := canonicalJSON(value)
	if err != nil {
		return "", fmt.Errorf("routing canonical JSON failed: %w", err)
	}
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validRoutingSHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func RoutingEvidenceDigest(secret []byte, domain, value string) (string, error) {
	if len(secret) < 16 || strings.TrimSpace(domain) == "" || value == "" {
		return "", errors.New("routing evidence digest input is invalid")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(domain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func RoutingIncidentIdentity(secret []byte, scope RoutingManagedScope, policyHash, ruleID string) (string, error) {
	if policyHash == "" || !routingObserverIdentifierPattern.MatchString(ruleID) {
		return "", errors.New("routing incident identity input is invalid")
	}
	value := fmt.Sprintf("%d\x00%d\x00%s\x00%d\x00%s\x00%s", scope.Sub2APIInstanceID, scope.GroupID, scope.CanonicalModel, scope.RouteVersion, policyHash, ruleID)
	return RoutingEvidenceDigest(secret, "routing-incident-identity.v1", value)
}

func cloneRoutingPolicy(policy RoutingPolicySet) RoutingPolicySet {
	policy.Rules = append([]RoutingPolicyRule(nil), policy.Rules...)
	return policy
}

func cloneRoutingRoles(roles RoutingScopeRoles) RoutingScopeRoles {
	// Scope IDs are JSON arrays in the wire contract. Normalize both nil and
	// empty slices to [] so hashing a decoded request never changes [] to null.
	roles.PrimaryAccountIDs = append([]int64{}, roles.PrimaryAccountIDs...)
	roles.FallbackAccountIDs = append([]int64{}, roles.FallbackAccountIDs...)
	roles.CandidateAccountIDs = append([]int64{}, roles.CandidateAccountIDs...)
	return roles
}

func cloneRoutingTrafficOrigin(origin RoutingScopeTrafficOrigin) RoutingScopeTrafficOrigin {
	origin.MonitorAPIKeyIDs = append([]int64{}, origin.MonitorAPIKeyIDs...)
	origin.CanaryAPIKeyIDs = append([]int64{}, origin.CanaryAPIKeyIDs...)
	return origin
}
