package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

type groupAccountPriorityTxBeginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

type groupAccountPriorityQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func (r *accountRepository) GetGroupAccountPriorities(ctx context.Context, groupID int64) (*service.GroupAccountPrioritySnapshot, error) {
	if r == nil || r.sql == nil {
		return nil, service.ErrGroupAccountPriorityUnsupported
	}
	items, err := queryGroupAccountPriorities(ctx, r.sql, groupID, false)
	if err != nil {
		return nil, err
	}
	return &service.GroupAccountPrioritySnapshot{
		ContractVersion: service.GroupAccountPriorityContractVersion,
		GroupID:         groupID,
		Items:           items,
		ReadbackHash:    service.GroupAccountPriorityHash(items),
	}, nil
}

func (r *accountRepository) PutGroupAccountPriorities(ctx context.Context, input service.GroupAccountPriorityUpdate) (*service.GroupAccountPrioritySnapshot, error) {
	if r == nil || r.sql == nil {
		return nil, service.ErrGroupAccountPriorityUnsupported
	}
	beginner, ok := r.sql.(groupAccountPriorityTxBeginner)
	if !ok {
		return nil, service.ErrGroupAccountPriorityUnsupported
	}
	requestPayload, err := json.Marshal(input.Items)
	if err != nil {
		return nil, err
	}
	tx, err := beginner.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	claim, err := tx.ExecContext(ctx, `
		INSERT INTO group_account_priority_operations (
			group_id, operation_id, request_hash, expected_readback_hash, request_json
		) VALUES ($1, $2, $3, $4, $5::jsonb)
		ON CONFLICT (group_id, operation_id) DO NOTHING
	`, input.GroupID, input.OperationID, input.RequestHash, input.ExpectedReadbackHash, string(requestPayload))
	if err != nil {
		return nil, err
	}
	claimed, err := claim.RowsAffected()
	if err != nil {
		return nil, err
	}
	if claimed == 0 {
		var storedRequestHash string
		var responseJSON []byte
		if err := tx.QueryRowContext(ctx, `
			SELECT request_hash, response_json
			FROM group_account_priority_operations
			WHERE group_id = $1 AND operation_id = $2
		`, input.GroupID, input.OperationID).Scan(&storedRequestHash, &responseJSON); err != nil {
			return nil, err
		}
		if storedRequestHash != input.RequestHash {
			return nil, service.ErrGroupAccountPriorityOperationConflict
		}
		var replay service.GroupAccountPrioritySnapshot
		if err := json.Unmarshal(responseJSON, &replay); err != nil {
			return nil, fmt.Errorf("decode group account priority replay: %w", err)
		}
		if replay.ReadbackHash == "" {
			return nil, fmt.Errorf("decode group account priority replay: response is incomplete")
		}
		replay.Replayed = true
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return &replay, nil
	}

	current, err := queryGroupAccountPriorities(ctx, tx, input.GroupID, true)
	if err != nil {
		return nil, err
	}
	if !sameGroupAccountPriorityAccounts(current, input.Items) {
		return nil, service.ErrGroupAccountPriorityMembershipConflict
	}
	for _, item := range input.Items {
		result, err := tx.ExecContext(ctx, `
			UPDATE account_groups SET priority = $3
			WHERE account_id = $1 AND group_id = $2
		`, item.AccountID, input.GroupID, item.Priority)
		if err != nil {
			return nil, err
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return nil, err
		}
		if updated != 1 {
			return nil, service.ErrGroupAccountPriorityMembershipConflict
		}
	}
	items, err := queryGroupAccountPriorities(ctx, tx, input.GroupID, false)
	if err != nil {
		return nil, err
	}
	readbackHash := service.GroupAccountPriorityHash(items)
	if readbackHash != input.ExpectedReadbackHash {
		return nil, service.ErrGroupAccountPriorityReadbackMismatch
	}
	for _, item := range input.Items {
		accountID := item.AccountID
		if err := enqueueSchedulerOutbox(
			ctx,
			tx,
			service.SchedulerOutboxEventAccountGroupsChanged,
			&accountID,
			nil,
			buildSchedulerGroupPayload([]int64{input.GroupID}),
		); err != nil {
			return nil, err
		}
	}
	snapshot := &service.GroupAccountPrioritySnapshot{
		ContractVersion: service.GroupAccountPriorityContractVersion,
		GroupID:         input.GroupID,
		OperationID:     input.OperationID,
		Items:           items,
		ExpectedHash:    input.ExpectedReadbackHash,
		ReadbackHash:    readbackHash,
	}
	responseJSON, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE group_account_priority_operations
		SET readback_hash = $3, response_json = $4::jsonb, updated_at = NOW()
		WHERE group_id = $1 AND operation_id = $2
	`, input.GroupID, input.OperationID, readbackHash, string(responseJSON)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func queryGroupAccountPriorities(ctx context.Context, queryer groupAccountPriorityQueryer, groupID int64, lock bool) ([]service.GroupAccountPriorityItem, error) {
	query := `
		SELECT account_id, priority
		FROM account_groups
		WHERE group_id = $1
		ORDER BY account_id ASC
	`
	if lock {
		query += " FOR UPDATE"
	}
	rows, err := queryer.QueryContext(ctx, query, groupID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	items := make([]service.GroupAccountPriorityItem, 0)
	for rows.Next() {
		var item service.GroupAccountPriorityItem
		if err := rows.Scan(&item.AccountID, &item.Priority); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}


func sameGroupAccountPriorityAccounts(current, requested []service.GroupAccountPriorityItem) bool {
	if len(current) != len(requested) {
		return false
	}
	members := make(map[int64]struct{}, len(current))
	for _, item := range current {
		members[item.AccountID] = struct{}{}
	}
	for _, item := range requested {
		if _, ok := members[item.AccountID]; !ok {
			return false
		}
	}
	return true
}
