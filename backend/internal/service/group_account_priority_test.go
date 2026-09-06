//go:build unit

package service

import (
	"context"
	"testing"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
	"github.com/stretchr/testify/require"
)

type groupAccountPriorityRepoStub struct {
	AccountRepository
	putInput GroupAccountPriorityUpdate
	snapshot *GroupAccountPrioritySnapshot
}

func (s *groupAccountPriorityRepoStub) GetGroupAccountPriorities(context.Context, int64) (*GroupAccountPrioritySnapshot, error) {
	return s.snapshot, nil
}

func (s *groupAccountPriorityRepoStub) PutGroupAccountPriorities(_ context.Context, input GroupAccountPriorityUpdate) (*GroupAccountPrioritySnapshot, error) {
	s.putInput = input
	return s.snapshot, nil
}

type groupAccountPriorityGroupRepoStub struct {
	GroupRepository
	group *Group
}

func (s groupAccountPriorityGroupRepoStub) GetByIDLite(context.Context, int64) (*Group, error) {
	return s.group, nil
}

func TestAdminServiceSetGroupAccountPrioritiesValidatesAndNormalizes(t *testing.T) {
	items := []GroupAccountPriorityItem{{AccountID: 20, Priority: 9}, {AccountID: 10, Priority: 3}}
	expectedHash := GroupAccountPriorityHash(items)
	repository := &groupAccountPriorityRepoStub{snapshot: &GroupAccountPrioritySnapshot{
		ContractVersion: GroupAccountPriorityContractVersion,
		GroupID:         7,
		Items:           []GroupAccountPriorityItem{{AccountID: 10, Priority: 3}, {AccountID: 20, Priority: 9}},
		ReadbackHash:    expectedHash,
	}}
	adminService := &adminServiceImpl{
		accountRepo: repository,
		groupRepo:   groupAccountPriorityGroupRepoStub{group: &Group{ID: 7}},
	}

	got, err := adminService.SetGroupAccountPriorities(context.Background(), 7, GroupAccountPriorityUpdate{
		OperationID:          "price-epoch-7",
		ExpectedReadbackHash: expectedHash,
		Items:                items,
	})

	require.NoError(t, err)
	require.Equal(t, repository.snapshot, got)
	require.Equal(t, []GroupAccountPriorityItem{{AccountID: 10, Priority: 3}, {AccountID: 20, Priority: 9}}, repository.putInput.Items)
	require.Equal(t, int64(7), repository.putInput.GroupID)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, repository.putInput.RequestHash)
}

func TestGroupAccountPriorityHashMatchesPanelCanonicalContract(t *testing.T) {
	items := []GroupAccountPriorityItem{{AccountID: 20, Priority: 9}, {AccountID: 10, Priority: 3}}

	require.Equal(
		t,
		"sha256:fccd1d83a7bf977fe91450b535079bca87e889c58fcd2b4f84bb7e2a6c1656a8",
		GroupAccountPriorityHash(items),
	)
}

func TestAdminServiceSetGroupAccountPrioritiesRejectsInvalidInputs(t *testing.T) {
	repository := &groupAccountPriorityRepoStub{}
	adminService := &adminServiceImpl{
		accountRepo: repository,
		groupRepo:   groupAccountPriorityGroupRepoStub{group: &Group{ID: 7}},
	}
	validHash := GroupAccountPriorityHash([]GroupAccountPriorityItem{{AccountID: 10, Priority: 1}})
	tests := []struct {
		name  string
		input GroupAccountPriorityUpdate
	}{
		{name: "missing operation", input: GroupAccountPriorityUpdate{ExpectedReadbackHash: validHash, Items: []GroupAccountPriorityItem{{AccountID: 10, Priority: 1}}}},
		{name: "invalid hash", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: "nope", Items: []GroupAccountPriorityItem{{AccountID: 10, Priority: 1}}}},
		{name: "empty", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: validHash}},
		{name: "account zero", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: validHash, Items: []GroupAccountPriorityItem{{AccountID: 0, Priority: 1}}}},
		{name: "priority below", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: validHash, Items: []GroupAccountPriorityItem{{AccountID: 10, Priority: -1}}}},
		{name: "priority above", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: validHash, Items: []GroupAccountPriorityItem{{AccountID: 10, Priority: GroupAccountPriorityMax + 1}}}},
		{name: "duplicate", input: GroupAccountPriorityUpdate{OperationID: "op", ExpectedReadbackHash: validHash, Items: []GroupAccountPriorityItem{{AccountID: 10, Priority: 1}, {AccountID: 10, Priority: 2}}}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := adminService.SetGroupAccountPriorities(context.Background(), 7, testCase.input)
			require.Error(t, err)
			require.Equal(t, 400, infraerrors.Code(err))
		})
	}
}

func TestAdminServiceGroupAccountPrioritiesFailsClosedWithoutRepositoryCapability(t *testing.T) {
	adminService := &adminServiceImpl{
		accountRepo: struct{ AccountRepository }{},
		groupRepo:   groupAccountPriorityGroupRepoStub{group: &Group{ID: 7}},
	}

	_, err := adminService.GetGroupAccountPriorities(context.Background(), 7)

	require.Error(t, err)
	require.Equal(t, 503, infraerrors.Code(err))
}
