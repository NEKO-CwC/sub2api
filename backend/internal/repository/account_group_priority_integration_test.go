//go:build integration

package repository

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestGroupAccountPriorityUpdatePropagatesThroughOutboxToRedisSnapshot(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	redisClient := testRedis(t)
	cache := NewSchedulerCache(redisClient)
	repository := newAccountRepositoryWithSQL(client, integrationDB, nil)
	outboxRepository := NewSchedulerOutboxRepository(integrationDB)
	groupRepository := newGroupRepositoryWithSQL(client, integrationDB)
	suffix := time.Now().UnixNano()

	_, err := integrationDB.ExecContext(ctx, "TRUNCATE scheduler_outbox")
	require.NoError(t, err)
	group, err := client.Group.Create().
		SetName(fmt.Sprintf("group-priority-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		SetStatus(service.StatusActive).
		Save(ctx)
	require.NoError(t, err)
	createAccount := func(name string, globalPriority int) int64 {
		account, createErr := client.Account.Create().
			SetName(name).
			SetPlatform(service.PlatformOpenAI).
			SetType(service.AccountTypeAPIKey).
			SetStatus(service.StatusActive).
			SetSchedulable(true).
			SetConcurrency(1).
			SetPriority(globalPriority).
			Save(ctx)
		require.NoError(t, createErr)
		return account.ID
	}
	firstID := createAccount(fmt.Sprintf("group-priority-first-%d", suffix), 1)
	secondID := createAccount(fmt.Sprintf("group-priority-second-%d", suffix), 100000)
	for _, binding := range []struct {
		accountID int64
		priority  int
	}{{firstID, 10}, {secondID, 20}} {
		_, err = client.AccountGroup.Create().
			SetAccountID(binding.accountID).
			SetGroupID(group.ID).
			SetPriority(binding.priority).
			Save(ctx)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scheduler_outbox WHERE account_id IN ($1, $2)", firstID, secondID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM group_account_priority_operations WHERE group_id = $1", group.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM account_groups WHERE group_id = $1", group.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM accounts WHERE id IN ($1, $2)", firstID, secondID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM groups WHERE id = $1", group.ID)
	})

	configuration := &config.Config{
		RunMode: config.RunModeStandard,
		Gateway: config.GatewayConfig{Scheduling: config.GatewaySchedulingConfig{
			OutboxPollIntervalSeconds:  1,
			FullRebuildIntervalSeconds: 0,
			DbFallbackEnabled:          true,
		}},
	}
	snapshotService := service.NewSchedulerSnapshotService(cache, outboxRepository, repository, groupRepository, configuration)
	snapshotService.Start()
	t.Cleanup(snapshotService.Stop)
	bucket := service.SchedulerBucket{GroupID: group.ID, Platform: service.PlatformOpenAI, Mode: service.SchedulerModeSingle}
	require.Eventually(t, func() bool {
		accounts, hit, snapshotErr := cache.GetSnapshot(ctx, bucket)
		return snapshotErr == nil && hit && len(accounts) == 2 && accounts[0].ID == firstID && accounts[1].ID == secondID
	}, 10*time.Second, 100*time.Millisecond)

	desiredItems := []service.GroupAccountPriorityItem{{AccountID: firstID, Priority: 30}, {AccountID: secondID, Priority: 20}}
	expectedHash := service.GroupAccountPriorityHash(desiredItems)
	written, err := repository.PutGroupAccountPriorities(ctx, service.GroupAccountPriorityUpdate{
		GroupID:              group.ID,
		OperationID:          fmt.Sprintf("group-priority-%d", suffix),
		ExpectedReadbackHash: expectedHash,
		RequestHash:          fmt.Sprintf("sha256:%064x", suffix),
		Items:                desiredItems,
	})
	require.NoError(t, err)
	require.Equal(t, desiredItems, written.Items)
	require.Equal(t, expectedHash, written.ReadbackHash)

	var eventID int64
	require.NoError(t, integrationDB.QueryRowContext(ctx, `
		SELECT id FROM scheduler_outbox
		WHERE account_id = $1 AND event_type = $2
		ORDER BY id DESC LIMIT 1
	`, firstID, service.SchedulerOutboxEventAccountGroupsChanged).Scan(&eventID))
	require.Eventually(t, func() bool {
		watermark, watermarkErr := cache.GetOutboxWatermark(ctx)
		return watermarkErr == nil && watermark >= eventID
	}, 10*time.Second, 100*time.Millisecond)
	require.Eventually(t, func() bool {
		accounts, hit, snapshotErr := cache.GetSnapshot(ctx, bucket)
		if snapshotErr != nil || !hit || len(accounts) != 2 || accounts[0].ID != secondID || accounts[1].ID != firstID {
			return false
		}
		return groupPriority(accounts[0], group.ID) == 20 && groupPriority(accounts[1], group.ID) == 30
	}, 10*time.Second, 100*time.Millisecond)

	replayed, err := repository.PutGroupAccountPriorities(ctx, service.GroupAccountPriorityUpdate{
		GroupID:              group.ID,
		OperationID:          fmt.Sprintf("group-priority-%d", suffix),
		ExpectedReadbackHash: expectedHash,
		RequestHash:          fmt.Sprintf("sha256:%064x", suffix),
		Items:                desiredItems,
	})
	require.NoError(t, err)
	require.True(t, replayed.Replayed)
}

func TestGroupAccountPriorityUpdateRejectsOmittedMemberWithoutSideEffects(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repository := newAccountRepositoryWithSQL(client, integrationDB, nil)
	suffix := time.Now().UnixNano()
	group, err := client.Group.Create().
		SetName(fmt.Sprintf("group-priority-omission-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		Save(ctx)
	require.NoError(t, err)
	createAccount := func(name string) int64 {
		account, createErr := client.Account.Create().
			SetName(name).
			SetPlatform(service.PlatformOpenAI).
			SetType(service.AccountTypeAPIKey).
			Save(ctx)
		require.NoError(t, createErr)
		return account.ID
	}
	firstID := createAccount(fmt.Sprintf("group-priority-omission-first-%d", suffix))
	secondID := createAccount(fmt.Sprintf("group-priority-omission-second-%d", suffix))
	for _, binding := range []struct {
		accountID int64
		priority  int
	}{{firstID, 10}, {secondID, 20}} {
		_, err = client.AccountGroup.Create().
			SetAccountID(binding.accountID).
			SetGroupID(group.ID).
			SetPriority(binding.priority).
			Save(ctx)
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scheduler_outbox WHERE account_id IN ($1, $2)", firstID, secondID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM group_account_priority_operations WHERE group_id = $1", group.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM account_groups WHERE group_id = $1", group.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM accounts WHERE id IN ($1, $2)", firstID, secondID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM groups WHERE id = $1", group.ID)
	})

	var outboxCountBefore int
	require.NoError(t, integrationDB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM scheduler_outbox
		WHERE account_id IN ($1, $2) AND event_type = $3
	`, firstID, secondID, service.SchedulerOutboxEventAccountGroupsChanged).Scan(&outboxCountBefore))
	requestedItems := []service.GroupAccountPriorityItem{{AccountID: firstID, Priority: 30}}
	_, err = repository.PutGroupAccountPriorities(ctx, service.GroupAccountPriorityUpdate{
		GroupID:              group.ID,
		OperationID:          fmt.Sprintf("omitted-member-%d", suffix),
		ExpectedReadbackHash: service.GroupAccountPriorityHash(requestedItems),
		RequestHash:          fmt.Sprintf("sha256:%064x", suffix),
		Items:                requestedItems,
	})
	require.ErrorIs(t, err, service.ErrGroupAccountPriorityMembershipConflict)

	var firstPriority, secondPriority, outboxCountAfter, operationCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT priority FROM account_groups WHERE account_id = $1 AND group_id = $2", firstID, group.ID).Scan(&firstPriority))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT priority FROM account_groups WHERE account_id = $1 AND group_id = $2", secondID, group.ID).Scan(&secondPriority))
	require.NoError(t, integrationDB.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM scheduler_outbox
		WHERE account_id IN ($1, $2) AND event_type = $3
	`, firstID, secondID, service.SchedulerOutboxEventAccountGroupsChanged).Scan(&outboxCountAfter))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM group_account_priority_operations WHERE group_id = $1", group.ID).Scan(&operationCount))
	require.Equal(t, 10, firstPriority)
	require.Equal(t, 20, secondPriority)
	require.Equal(t, outboxCountBefore, outboxCountAfter)
	require.Zero(t, operationCount)
}

func groupPriority(account *service.Account, groupID int64) int {
	if account == nil {
		return -1
	}
	for _, accountGroup := range account.AccountGroups {
		if accountGroup.GroupID == groupID {
			return accountGroup.Priority
		}
	}
	return -1
}

func TestGroupAccountPriorityUpdateRejectsNonMemberWithoutCreatingBinding(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repository := newAccountRepositoryWithSQL(client, integrationDB, nil)
	suffix := time.Now().UnixNano()
	group, err := client.Group.Create().
		SetName(fmt.Sprintf("group-priority-nonmember-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		Save(ctx)
	require.NoError(t, err)
	account, err := client.Account.Create().
		SetName(fmt.Sprintf("group-priority-outsider-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		SetType(service.AccountTypeAPIKey).
		Save(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM group_account_priority_operations WHERE group_id = $1", group.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM account_groups WHERE account_id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM accounts WHERE id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM groups WHERE id = $1", group.ID)
	})

	_, err = repository.PutGroupAccountPriorities(ctx, service.GroupAccountPriorityUpdate{
		GroupID:              group.ID,
		OperationID:          fmt.Sprintf("nonmember-%d", suffix),
		ExpectedReadbackHash: service.GroupAccountPriorityHash([]service.GroupAccountPriorityItem{{AccountID: account.ID, Priority: 1}}),
		RequestHash:          fmt.Sprintf("sha256:%064x", suffix),
		Items:                []service.GroupAccountPriorityItem{{AccountID: account.ID, Priority: 1}},
	})
	require.ErrorIs(t, err, service.ErrGroupAccountPriorityMembershipConflict)

	var bindingCount, operationCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM account_groups WHERE account_id = $1 AND group_id = $2", account.ID, group.ID).Scan(&bindingCount))
	require.NoError(t, integrationDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM group_account_priority_operations WHERE group_id = $1", group.ID).Scan(&operationCount))
	require.Zero(t, bindingCount)
	require.Zero(t, operationCount)
}
