package handler

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestRoutingPolicyRegistryStableHashArbitrationAndLastKnownGood(t *testing.T) {
	registry := NewDefaultRoutingPolicyRegistry()
	policy := DefaultRoutingFailurePolicy()
	low := policy.Rules[0]
	low.RuleID = "low.failure-observation.v1"
	low.Severity = "low"
	low.Precedence = 50
	low.ReasonCode = "low_failure_observation"
	policy.Rules = append(policy.Rules, low)

	first, err := registry.ValidateAndLoad(policy)
	require.NoError(t, err)
	second, err := registry.ValidateAndLoad(policy)
	require.NoError(t, err)
	require.Equal(t, first.Hash, second.Hash)

	scope := routingObserverTestScope(policy)
	scope.ExpectedPolicyHash = first.Hash
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	scope.ScopeHash = scopeHash
	fact := routingObserverMatchedFact(scope, scopeHash)
	decision := registry.Evaluate(scope, fact)
	require.Equal(t, RoutingEvaluationMatched, decision.EligibilityState)
	require.Len(t, decision.Evaluations, 2)
	require.NotNil(t, decision.Winner)
	require.Equal(t, RoutingCriticalFailureRuleV1, decision.Winner.RuleID)

	invalid := policy
	invalid.Rules = append([]RoutingPolicyRule(nil), policy.Rules...)
	invalid.Rules[0].Metric = "unknown_metric"
	_, err = registry.ValidateAndLoad(invalid)
	require.ErrorContains(t, err, "not registered")
	lastGood, ok := registry.LastKnownGood()
	require.True(t, ok)
	require.Equal(t, first.Hash, lastGood.Hash)
}

func TestDecodeRoutingPolicySetRejectsUnknownAndTrailingFields(t *testing.T) {
	_, err := DecodeRoutingPolicySet([]byte(`{"contract_version":"routing-policy-set.v1","policy_id":"p","revision":1,"rules":[],"unknown":true}`))
	require.ErrorContains(t, err, "unknown field")
	_, err = DecodeRoutingPolicySet([]byte(`{} {}`))
	require.Error(t, err)
}

func TestRoutingFailureFixtureExactSeventeenIgnoredThreeEligible(t *testing.T) {
	payload, err := os.ReadFile("testdata/routing_observer/failure-v1.json")
	require.NoError(t, err)
	var fixture struct {
		ContractVersion string `json:"contract_version"`
		Items           []struct {
			FixtureID string `json:"fixture_id"`
			Category  string `json:"category"`
			APIKeyID  int64  `json:"api_key_id"`
			Model     string `json:"model"`
			Status    int    `json:"status_code"`
			Expected  string `json:"expected"`
		} `json:"items"`
	}
	require.NoError(t, json.Unmarshal(payload, &fixture))
	require.Equal(t, "routing-failure-fixture.v1", fixture.ContractVersion)
	require.Len(t, fixture.Items, 20)

	policy := DefaultRoutingFailurePolicy()
	registry := NewDefaultRoutingPolicyRegistry()
	validated, err := registry.ValidateAndLoad(policy)
	require.NoError(t, err)
	scope := routingObserverTestScope(policy)
	scope.ExpectedPolicyHash = validated.Hash
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	scope.ScopeHash = scopeHash

	ignored, eligible, evaluationCount := 0, 0, 0
	for _, item := range fixture.Items {
		origin, _ := scope.TrafficOriginForAPIKey(item.APIKeyID, false)
		attempts := []RoutingAttemptFact{routingObserverAttempt(1, 101, RoutingAccountRolePrimary, RoutingOutcomeFailure, false, "fixture-"+item.FixtureID)}
		if item.Category == "pre_upstream" {
			attempts = nil
		}
		fact := RoutingRequestFact{
			ObservedAt: time.Unix(1, 0).UTC(), Sub2APIInstanceID: 1, ScopeRevision: 7,
			ScopeHash: scopeHash, RouteVersion: 12, TopologyFingerprint: scope.TopologyFingerprint,
			GroupID: 31, CanonicalModel: item.Model, TrafficOrigin: origin, Attempts: attempts,
		}
		decision := registry.Evaluate(scope, fact)
		if decision.EligibilityState == RoutingEvaluationMatched {
			eligible++
			evaluationCount += len(decision.Evaluations)
			require.Equal(t, "eligible", item.Expected)
		} else {
			ignored++
			require.Equal(t, "ignored", item.Expected)
			require.Empty(t, decision.Evaluations)
			require.Nil(t, decision.Winner)
		}
	}
	require.Equal(t, 17, ignored)
	require.Equal(t, 3, eligible)
	require.Equal(t, 3, evaluationCount)
}

func TestCriticalFailureDecisionTable(t *testing.T) {
	policy := DefaultRoutingFailurePolicy()
	registry := NewDefaultRoutingPolicyRegistry()
	validated, err := registry.ValidateAndLoad(policy)
	require.NoError(t, err)
	scope := routingObserverTestScope(policy)
	scope.ExpectedPolicyHash = validated.Hash
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	scope.ScopeHash = scopeHash
	base := routingObserverMatchedFact(scope, scopeHash)

	tests := []struct {
		name   string
		mutate func(*RoutingRequestFact)
		state  RoutingEvaluationState
		reason string
	}{
		{"complete", func(*RoutingRequestFact) {}, RoutingEvaluationMatched, "complete_primary_failure_fallback_serving"},
		{"ordinary single success", func(f *RoutingRequestFact) {
			f.Attempts = []RoutingAttemptFact{routingObserverAttempt(1, 101, RoutingAccountRolePrimary, RoutingOutcomeSuccess, true, "ordinary-success")}
			f.Handoff = nil
		}, RoutingEvaluationNotMatched, "original_primary_failure_missing"},
		{"idle", func(f *RoutingRequestFact) { f.Handoff.PrimaryConcurrency = 0; f.Handoff.FallbackConcurrency = 0 }, RoutingEvaluationNotMatched, "idle"},
		{"overlap", func(f *RoutingRequestFact) { f.Handoff.PrimaryConcurrency = 1; f.Handoff.FallbackConcurrency = 1 }, RoutingEvaluationInsufficient, "overlapping_timeline"},
		{"missing handoff", func(f *RoutingRequestFact) { f.Handoff = nil }, RoutingEvaluationInsufficient, "concurrency_handoff_missing"},
		{"missing final", func(f *RoutingRequestFact) { f.Attempts[1].Final = false }, RoutingEvaluationInsufficient, "final_attempt_missing_or_not_terminal"},
		{"untyped failure", func(f *RoutingRequestFact) { f.Attempts[0].NextAccount = service.NextAccountLegacyRetry }, RoutingEvaluationInsufficient, "failure_not_account_failover"},
		{"fallback failed", func(f *RoutingRequestFact) { f.Attempts[1].Outcome = RoutingOutcomeFailure }, RoutingEvaluationInsufficient, "fallback_final_success_missing"},
		{"gap", func(f *RoutingRequestFact) { f.Gap = true }, RoutingEvaluationInsufficient, "request_fact_gap"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fact := cloneRoutingRequestFact(base)
			test.mutate(&fact)
			decision := registry.Evaluate(scope, fact)
			require.Len(t, decision.Evaluations, 1)
			require.Equal(t, test.state, decision.Evaluations[0].State)
			require.Equal(t, test.reason, decision.Evaluations[0].ReasonCode)
			if test.state == RoutingEvaluationMatched {
				require.NotNil(t, decision.Winner)
			} else {
				require.Nil(t, decision.Winner)
			}
		})
	}
}

func TestRoutingManagedScopeAndEvidenceDigestFailClosed(t *testing.T) {
	policy := DefaultRoutingFailurePolicy()
	registry := NewDefaultRoutingPolicyRegistry()
	scope := routingObserverTestScope(policy)
	_, err := scope.Validate(registry)
	require.NoError(t, err)

	overlap := scope
	overlap.Roles.CandidateAccountIDs = []int64{102}
	_, err = overlap.Validate(NewDefaultRoutingPolicyRegistry())
	require.ErrorContains(t, err, "overlaps")

	invalidCanary := scope
	invalidCanary.TrafficOrigin.CanaryAPIKeyIDs = []int64{301}
	invalidCanary.TrafficOrigin.CanaryLoopIDHash = "sha256:" + strings.Repeat("z", 64)
	invalidCanary.TrafficOrigin.CanaryMaxLogicalRequest = 1
	_, err = invalidCanary.Validate(NewDefaultRoutingPolicyRegistry())
	require.ErrorContains(t, err, "canary loop contract")

	digest, err := RoutingEvidenceDigest([]byte("0123456789abcdef"), "test.v1", "anonymous-value")
	require.NoError(t, err)
	require.Regexp(t, routingObserverDigestPattern, digest)
	require.NotContains(t, digest, "anonymous-value")
	_, err = RoutingEvidenceDigest([]byte("short"), "test.v1", "value")
	require.Error(t, err)
}

func TestResolveRoutingIdentityDuplicateAndConflict(t *testing.T) {
	identity, err := RoutingEvidenceDigest([]byte("0123456789abcdef"), "identity.v1", "one")
	require.NoError(t, err)
	firstHash := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secondHash := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	resolution, err := ResolveRoutingIdentity("", "", identity, firstHash)
	require.NoError(t, err)
	require.Equal(t, RoutingIdentityNew, resolution)
	resolution, err = ResolveRoutingIdentity(identity, firstHash, identity, firstHash)
	require.NoError(t, err)
	require.Equal(t, RoutingIdentityDuplicate, resolution)
	resolution, err = ResolveRoutingIdentity(identity, firstHash, identity, secondHash)
	require.NoError(t, err)
	require.Equal(t, RoutingIdentityConflict, resolution)
}

func TestRoutingObserverDTOsExcludeForbiddenFields(t *testing.T) {
	for _, value := range []any{
		RoutingManagedScope{}, RoutingRequestFact{}, RoutingAttemptFact{}, RoutingFailoverHandoffFact{},
		RoutingPolicyDecision{}, RoutingRuleEvaluation{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
			for _, forbidden := range []string{"email", "ip_address", "secret", "prompt", "response_body", "logical_request_id", "status_message"} {
				require.NotContains(t, name, forbidden, "%s contains forbidden field %s", typeOf.Name(), field.Name)
			}
		}
	}
}

func routingObserverTestScope(policy RoutingPolicySet) RoutingManagedScope {
	return RoutingManagedScope{
		ContractVersion: RoutingObserverScopeContractV1, Enabled: true,
		Sub2APIInstanceID: 1, GroupID: 31, CanonicalModel: "gpt-5.6-sol",
		ModelAliases: []string{"gpt-5.6-sol"}, RouteVersion: 12, ScopeRevision: 7,
		TopologyFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Roles:               RoutingScopeRoles{PrimaryAccountIDs: []int64{101}, FallbackAccountIDs: []int64{102}, CandidateAccountIDs: []int64{103}},
		TrafficOrigin:       RoutingScopeTrafficOrigin{MonitorAPIKeyIDs: []int64{201, 202, 203, 204, 205, 206, 207, 208}},
		Policy:              policy,
	}
}

func routingObserverAttempt(index int, accountID int64, role RoutingAccountRole, outcome RoutingOutcome, final bool, seed string) RoutingAttemptFact {
	digest, err := RoutingEvidenceDigest([]byte("0123456789abcdef"), "routing-test-evidence.v1", seed)
	if err != nil {
		panic(err)
	}
	attempt := RoutingAttemptFact{
		AccountID: accountID, AccountRole: role, AttemptIndex: index, Final: final,
		Outcome: outcome, ObservedAt: time.Unix(int64(index), 0).UTC(), EvidenceDigest: digest,
	}
	if outcome == RoutingOutcomeFailure {
		attempt.Stage = service.GatewayFailureStageInference
		attempt.Scope = service.GatewayFailureScopeAccount
		attempt.Reason = service.GatewayFailureReason("upstream_account_failure")
		attempt.NextAccount = service.NextAccountRetry
	}
	return attempt
}

func routingObserverMatchedFact(scope RoutingManagedScope, scopeHash string) RoutingRequestFact {
	return RoutingRequestFact{
		ObservedAt: time.Unix(3, 0).UTC(), Sub2APIInstanceID: scope.Sub2APIInstanceID,
		ScopeRevision: scope.ScopeRevision, ScopeHash: scopeHash, RouteVersion: scope.RouteVersion,
		TopologyFingerprint: scope.TopologyFingerprint, GroupID: scope.GroupID,
		CanonicalModel: scope.CanonicalModel, TrafficOrigin: RoutingTrafficOriginUser,
		Attempts: []RoutingAttemptFact{
			routingObserverAttempt(1, 101, RoutingAccountRolePrimary, RoutingOutcomeFailure, false, "primary"),
			routingObserverAttempt(2, 102, RoutingAccountRoleFallback, RoutingOutcomeSuccess, true, "fallback"),
		},
		Handoff: &RoutingFailoverHandoffFact{
			OriginalPrimaryAccountID: 101, FallbackAccountID: 102,
			PrimaryConcurrency: 0, FallbackConcurrency: 1,
			WindowIdentity: "window-1", ObservedAt: time.Unix(2, 0).UTC(), Complete: true,
		},
	}
}

func cloneRoutingRequestFact(fact RoutingRequestFact) RoutingRequestFact {
	fact.Attempts = append([]RoutingAttemptFact(nil), fact.Attempts...)
	if fact.Handoff != nil {
		handoff := *fact.Handoff
		fact.Handoff = &handoff
	}
	return fact
}
