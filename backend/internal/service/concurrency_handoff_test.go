package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type accountSlotHandoffTestCache struct {
	schedulerTestConcurrencyCache
	result           AccountSlotHandoffAcquireResult
	handoffCalls     int
	predecessorID    int64
	fallbackID       int64
	maxConcurrency   int
	handoffRequestID string
}

func (c *accountSlotHandoffTestCache) AcquireAccountSlotWithHandoff(
	_ context.Context,
	predecessorAccountID int64,
	fallbackAccountID int64,
	maxConcurrency int,
	requestID string,
) (AccountSlotHandoffAcquireResult, error) {
	c.handoffCalls++
	c.predecessorID = predecessorAccountID
	c.fallbackID = fallbackAccountID
	c.maxConcurrency = maxConcurrency
	c.handoffRequestID = requestID
	return c.result, nil
}

func TestFailoverHandoffTrackerUsesAtomicCapability(t *testing.T) {
	cache := &accountSlotHandoffTestCache{
		result: AccountSlotHandoffAcquireResult{
			Acquired:               true,
			PredecessorConcurrency: 0,
			FallbackConcurrency:    1,
			RedisUnix:              1_800_000_000,
		},
	}
	tracker := NewAccountSlotHandoffTracker()
	require.True(t, tracker.SetPredecessor(101))
	ctx := ContextWithAccountSlotHandoffTracker(context.Background(), tracker)

	result, err := NewConcurrencyService(cache).AcquireAccountSlot(ctx, 202, 3)
	require.NoError(t, err)
	require.True(t, result.Acquired)
	require.NotNil(t, result.Handoff)
	require.True(t, result.Handoff.Complete)
	require.Equal(t, int64(101), result.Handoff.PredecessorAccountID)
	require.Equal(t, int64(202), result.Handoff.FallbackAccountID)
	require.Equal(t, 0, result.Handoff.PredecessorConcurrency)
	require.Equal(t, 1, result.Handoff.FallbackConcurrency)
	require.Equal(t, time.Unix(1_800_000_000, 0).UTC(), result.Handoff.ObservedAt)
	require.Regexp(t, `^sha256:[0-9a-f]{64}$`, result.Handoff.WindowIdentity)
	require.Equal(t, 1, cache.handoffCalls)
	require.Equal(t, int64(101), cache.predecessorID)
	require.Equal(t, int64(202), cache.fallbackID)
	require.Equal(t, 3, cache.maxConcurrency)
	require.NotEmpty(t, cache.handoffRequestID)

	tracked, ok := tracker.Take(202)
	require.True(t, ok)
	require.Equal(t, *result.Handoff, tracked)
	_, ok = tracker.Take(202)
	require.False(t, ok, "handoff evidence must be consumed once")
	result.ReleaseFunc()
}

func TestFailoverHandoffTrackerLeavesUntrackedAcquireUnchanged(t *testing.T) {
	acquiredIDs := make([]int64, 0, 1)
	cache := &accountSlotHandoffTestCache{
		schedulerTestConcurrencyCache: schedulerTestConcurrencyCache{acquiredIDs: &acquiredIDs},
		result: AccountSlotHandoffAcquireResult{
			Acquired: true,
		},
	}

	result, err := NewConcurrencyService(cache).AcquireAccountSlot(context.Background(), 202, 3)
	require.NoError(t, err)
	require.True(t, result.Acquired)
	require.Nil(t, result.Handoff)
	require.Zero(t, cache.handoffCalls)
	require.Equal(t, []int64{202}, acquiredIDs)
	result.ReleaseFunc()
}

func TestFailoverHandoffTrackerMarksUnsupportedAndUnlimitedSnapshotsIncomplete(t *testing.T) {
	t.Run("unsupported cache", func(t *testing.T) {
		tracker := NewAccountSlotHandoffTracker()
		require.True(t, tracker.SetPredecessor(101))
		ctx := ContextWithAccountSlotHandoffTracker(context.Background(), tracker)

		result, err := NewConcurrencyService(schedulerTestConcurrencyCache{}).AcquireAccountSlot(ctx, 202, 3)
		require.NoError(t, err)
		require.True(t, result.Acquired)
		require.NotNil(t, result.Handoff)
		require.False(t, result.Handoff.Complete)
		require.Equal(t, -1, result.Handoff.PredecessorConcurrency)
		require.Equal(t, -1, result.Handoff.FallbackConcurrency)
		require.Equal(t, "atomic_handoff_cache_unsupported", result.Handoff.ReasonCode)
		result.ReleaseFunc()
	})

	t.Run("unlimited account", func(t *testing.T) {
		tracker := NewAccountSlotHandoffTracker()
		require.True(t, tracker.SetPredecessor(101))
		ctx := ContextWithAccountSlotHandoffTracker(context.Background(), tracker)

		result, err := NewConcurrencyService(schedulerTestConcurrencyCache{}).AcquireAccountSlot(ctx, 202, 0)
		require.NoError(t, err)
		require.True(t, result.Acquired)
		require.NotNil(t, result.Handoff)
		require.False(t, result.Handoff.Complete)
		require.Equal(t, -1, result.Handoff.PredecessorConcurrency)
		require.Equal(t, -1, result.Handoff.FallbackConcurrency)
		require.Equal(t, "unlimited_slot_no_atomic_snapshot", result.Handoff.ReasonCode)
	})
}

func TestFailoverHandoffTrackerClearPreventsStaleLongLivedHandoff(t *testing.T) {
	acquiredIDs := make([]int64, 0, 1)
	cache := &accountSlotHandoffTestCache{
		schedulerTestConcurrencyCache: schedulerTestConcurrencyCache{acquiredIDs: &acquiredIDs},
		result: AccountSlotHandoffAcquireResult{
			Acquired: true,
		},
	}
	tracker := NewAccountSlotHandoffTracker()
	require.True(t, tracker.SetPredecessor(101))
	tracker.ClearPredecessor()
	ctx := ContextWithAccountSlotHandoffTracker(context.Background(), tracker)

	result, err := NewConcurrencyService(cache).AcquireAccountSlot(ctx, 202, 3)
	require.NoError(t, err)
	require.True(t, result.Acquired)
	require.Nil(t, result.Handoff)
	require.Zero(t, cache.handoffCalls)
	require.Equal(t, []int64{202}, acquiredIDs)
	result.ReleaseFunc()
}
