//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestBindGroupsEmptyMembershipEnqueuesOldGroupInSameCommit(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repo := newAccountRepositoryWithSQL(client, integrationDB, nil)
	suffix := time.Now().UnixNano()

	group, err := client.Group.Create().
		SetName(fmt.Sprintf("bind-groups-empty-group-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		Save(ctx)
	require.NoError(t, err)
	account, err := client.Account.Create().
		SetName(fmt.Sprintf("bind-groups-empty-account-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		SetType(service.AccountTypeAPIKey).
		Save(ctx)
	require.NoError(t, err)
	_, err = client.AccountGroup.Create().
		SetAccountID(account.ID).
		SetGroupID(group.ID).
		SetPriority(1).
		Save(ctx)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scheduler_outbox WHERE account_id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM account_groups WHERE account_id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM accounts WHERE id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM groups WHERE id = $1", group.ID)
	})

	require.NoError(t, repo.BindGroups(ctx, account.ID, nil))

	var bindingCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_groups WHERE account_id = $1",
		account.ID,
	).Scan(&bindingCount))
	require.Zero(t, bindingCount)

	var payloadRaw []byte
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT payload FROM scheduler_outbox WHERE account_id = $1 AND event_type = $2 ORDER BY id DESC LIMIT 1",
		account.ID,
		service.SchedulerOutboxEventAccountGroupsChanged,
	).Scan(&payloadRaw))
	var payload map[string][]int64
	require.NoError(t, json.Unmarshal(payloadRaw, &payload))
	require.Equal(t, []int64{group.ID}, payload["group_ids"])
}

func TestBindGroupsRollsBackWhenOutboxInsertFails(t *testing.T) {
	ctx := context.Background()
	client := testEntClient(t)
	repo := newAccountRepositoryWithSQL(client, integrationDB, nil)
	suffix := time.Now().UnixNano()

	group, err := client.Group.Create().
		SetName(fmt.Sprintf("bind-groups-rollback-group-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		Save(ctx)
	require.NoError(t, err)
	account, err := client.Account.Create().
		SetName(fmt.Sprintf("bind-groups-rollback-account-%d", suffix)).
		SetPlatform(service.PlatformOpenAI).
		SetType(service.AccountTypeAPIKey).
		Save(ctx)
	require.NoError(t, err)
	_, err = client.AccountGroup.Create().
		SetAccountID(account.ID).
		SetGroupID(group.ID).
		SetPriority(1).
		Save(ctx)
	require.NoError(t, err)

	functionName := fmt.Sprintf("fail_bind_groups_outbox_%d", suffix)
	triggerName := fmt.Sprintf("fail_bind_groups_outbox_trigger_%d", suffix)
	_, err = integrationDB.ExecContext(ctx, fmt.Sprintf(`
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.event_type = '%s' AND NEW.account_id = %d THEN
				RAISE EXCEPTION 'forced bind groups outbox failure';
			END IF;
			RETURN NEW;
		END;
		$$`, functionName, service.SchedulerOutboxEventAccountGroupsChanged, account.ID))
	require.NoError(t, err)
	_, err = integrationDB.ExecContext(ctx, fmt.Sprintf(
		"CREATE TRIGGER %s BEFORE INSERT ON scheduler_outbox FOR EACH ROW EXECUTE FUNCTION %s()",
		triggerName,
		functionName,
	))
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = integrationDB.ExecContext(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON scheduler_outbox", triggerName))
		_, _ = integrationDB.ExecContext(context.Background(), fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", functionName))
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM scheduler_outbox WHERE account_id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM account_groups WHERE account_id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM accounts WHERE id = $1", account.ID)
		_, _ = integrationDB.ExecContext(context.Background(), "DELETE FROM groups WHERE id = $1", group.ID)
	})

	err = repo.BindGroups(ctx, account.ID, nil)
	require.ErrorContains(t, err, "forced bind groups outbox failure")

	var bindingCount, outboxCount int
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM account_groups WHERE account_id = $1 AND group_id = $2",
		account.ID,
		group.ID,
	).Scan(&bindingCount))
	require.Equal(t, 1, bindingCount, "the old binding must survive a failed invalidation write")
	require.NoError(t, integrationDB.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM scheduler_outbox WHERE account_id = $1 AND event_type = $2",
		account.ID,
		service.SchedulerOutboxEventAccountGroupsChanged,
	).Scan(&outboxCount))
	require.Zero(t, outboxCount)
}
