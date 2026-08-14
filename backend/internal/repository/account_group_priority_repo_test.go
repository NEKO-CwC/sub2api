package repository

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestPutGroupAccountPrioritiesCommitsValidatedUpdatesReadbackLedgerAndOutboxTogether(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := newAccountRepositoryWithSQL(nil, database, nil)
	items := []service.GroupAccountPriorityItem{{AccountID: 10, Priority: 3}, {AccountID: 20, Priority: 9}}
	expectedHash := service.GroupAccountPriorityHash(items)
	input := service.GroupAccountPriorityUpdate{
		GroupID:              7,
		OperationID:          "priority-op-7",
		ExpectedReadbackHash: expectedHash,
		RequestHash:          "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Items:                items,
	}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO group_account_priority_operations").
		WithArgs(int64(7), input.OperationID, input.RequestHash, expectedHash, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT account_id, priority").
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "priority"}).AddRow(int64(10), 1).AddRow(int64(20), 2))
	for _, item := range items {
		mock.ExpectExec("UPDATE account_groups").
			WithArgs(item.AccountID, int64(7), item.Priority).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectQuery("SELECT account_id, priority").
		WithArgs(int64(7)).
		WillReturnRows(sqlmock.NewRows([]string{"account_id", "priority"}).AddRow(int64(10), 3).AddRow(int64(20), 9))
	for _, item := range items {
		mock.ExpectExec(regexp.QuoteMeta("INSERT INTO scheduler_outbox (event_type, account_id, group_id, payload)")).
			WithArgs(service.SchedulerOutboxEventAccountGroupsChanged, item.AccountID, nil, sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(1, 1))
	}
	mock.ExpectExec("UPDATE group_account_priority_operations").
		WithArgs(int64(7), input.OperationID, expectedHash, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := repository.PutGroupAccountPriorities(context.Background(), input)

	require.NoError(t, err)
	require.Equal(t, expectedHash, got.ReadbackHash)
	require.False(t, got.Replayed)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPutGroupAccountPrioritiesRejectsNonMemberBeforeAnyUpdate(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := newAccountRepositoryWithSQL(nil, database, nil)
	input := service.GroupAccountPriorityUpdate{
		GroupID:              7,
		OperationID:          "priority-nonmember",
		ExpectedReadbackHash: service.GroupAccountPriorityHash([]service.GroupAccountPriorityItem{{AccountID: 10, Priority: 3}, {AccountID: 20, Priority: 9}}),
		RequestHash:          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Items:                []service.GroupAccountPriorityItem{{AccountID: 10, Priority: 3}, {AccountID: 20, Priority: 9}},
	}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO group_account_priority_operations").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT account_id, priority").WillReturnRows(sqlmock.NewRows([]string{"account_id", "priority"}).AddRow(int64(10), 1))
	mock.ExpectRollback()

	_, err = repository.PutGroupAccountPriorities(context.Background(), input)

	require.ErrorIs(t, err, service.ErrGroupAccountPriorityMembershipConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPutGroupAccountPrioritiesRejectsOmittedMemberBeforeAnyUpdate(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := newAccountRepositoryWithSQL(nil, database, nil)
	items := []service.GroupAccountPriorityItem{{AccountID: 10, Priority: 3}}
	input := service.GroupAccountPriorityUpdate{
		GroupID:              7,
		OperationID:          "priority-omitted-member",
		ExpectedReadbackHash: service.GroupAccountPriorityHash(items),
		RequestHash:          "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		Items:                items,
	}

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO group_account_priority_operations").WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT account_id, priority").WillReturnRows(
		sqlmock.NewRows([]string{"account_id", "priority"}).AddRow(int64(10), 1).AddRow(int64(20), 2),
	)
	mock.ExpectRollback()

	_, err = repository.PutGroupAccountPriorities(context.Background(), input)

	require.ErrorIs(t, err, service.ErrGroupAccountPriorityMembershipConflict)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPutGroupAccountPrioritiesReplaysStoredResponseWithoutWrites(t *testing.T) {
	database, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	repository := newAccountRepositoryWithSQL(nil, database, nil)
	items := []service.GroupAccountPriorityItem{{AccountID: 10, Priority: 3}}
	hash := service.GroupAccountPriorityHash(items)
	input := service.GroupAccountPriorityUpdate{
		GroupID:              7,
		OperationID:          "priority-replay",
		ExpectedReadbackHash: hash,
		RequestHash:          "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Items:                items,
	}
	stored, err := json.Marshal(service.GroupAccountPrioritySnapshot{
		ContractVersion: service.GroupAccountPriorityContractVersion,
		GroupID:         7,
		OperationID:     input.OperationID,
		Items:           items,
		ExpectedHash:    hash,
		ReadbackHash:    hash,
	})
	require.NoError(t, err)

	mock.ExpectBegin()
	mock.ExpectExec("INSERT INTO group_account_priority_operations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT request_hash, response_json").
		WithArgs(int64(7), input.OperationID).
		WillReturnRows(sqlmock.NewRows([]string{"request_hash", "response_json"}).AddRow(input.RequestHash, stored))
	mock.ExpectCommit()

	got, err := repository.PutGroupAccountPriorities(context.Background(), input)

	require.NoError(t, err)
	require.True(t, got.Replayed)
	require.Equal(t, hash, got.ReadbackHash)
	require.NoError(t, mock.ExpectationsWereMet())
}
