package handler

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoutingObserverPanelCanonicalHashVector(t *testing.T) {
	policy := DefaultRoutingFailurePolicy()
	registry := NewDefaultRoutingPolicyRegistry()
	validated, err := registry.ValidateAndLoad(policy)
	require.NoError(t, err)
	require.Equal(t, "sha256:928f02d0625e9c3e55eacb6cafb317fc9594d2ef1ea62957702817c7e3388adb", validated.Hash)

	scope := RoutingManagedScope{
		ContractVersion:     RoutingObserverScopeContractV1,
		Enabled:             true,
		Sub2APIInstanceID:   1,
		GroupID:             5,
		CanonicalModel:      "gpt-5.6-sol",
		ModelAliases:        []string{"gpt-5.6-sol"},
		RouteVersion:        1,
		TopologyFingerprint: "sha256:" + strings.Repeat("a", 64),
		ScopeRevision:       1,
		Roles: RoutingScopeRoles{
			PrimaryAccountIDs:   []int64{175},
			FallbackAccountIDs:  []int64{176},
			CandidateAccountIDs: []int64{177},
		},
		TrafficOrigin: RoutingScopeTrafficOrigin{
			MonitorAPIKeyIDs: []int64{201},
		},
		Policy:             policy,
		ExpectedPolicyHash: validated.Hash,
	}
	scopeHash, err := scope.Validate(registry)
	require.NoError(t, err)
	require.Equal(t, "sha256:588d31432179293f648cf26b975d794f8458f9653839b314835a03240df00330", scopeHash)
}
