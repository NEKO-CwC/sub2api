//go:build unit

package repository

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/stretchr/testify/require"
)

func TestInspectSchedulerSnapshotDistinguishesEmptySnapshotFromMiss(t *testing.T) {
	ctx := context.Background()
	cache, redisServer := newSchedulerCacheUnitWithRedis(t)
	bucket := service.SchedulerBucket{GroupID: 5, Platform: service.PlatformOpenAI, Mode: service.SchedulerModeSingle}

	missing, err := cache.InspectSchedulerSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.False(t, missing.Ready)
	require.Zero(t, missing.ActiveVersion)

	redisServer.Set(schedulerBucketKey(schedulerReadyPrefix, bucket), "1")
	redisServer.Set(schedulerBucketKey(schedulerActivePrefix, bucket), "17")

	empty, err := cache.InspectSchedulerSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.True(t, empty.Ready)
	require.Equal(t, int64(17), empty.ActiveVersion)
	require.Empty(t, empty.AccountIDs)
}

func TestInspectSchedulerSnapshotReturnsActiveMembers(t *testing.T) {
	ctx := context.Background()
	cache, redisServer := newSchedulerCacheUnitWithRedis(t)
	bucket := service.SchedulerBucket{GroupID: 5, Platform: service.PlatformOpenAI, Mode: service.SchedulerModeForced}

	redisServer.Set(schedulerBucketKey(schedulerReadyPrefix, bucket), "1")
	redisServer.Set(schedulerBucketKey(schedulerActivePrefix, bucket), "18")
	redisServer.ZAdd(schedulerSnapshotKey(bucket, "18"), 0, "175")
	redisServer.ZAdd(schedulerSnapshotKey(bucket, "18"), 1, "176")

	inspection, err := cache.InspectSchedulerSnapshot(ctx, bucket)
	require.NoError(t, err)
	require.True(t, inspection.Ready)
	require.Equal(t, int64(18), inspection.ActiveVersion)
	require.Equal(t, []int64{175, 176}, inspection.AccountIDs)
}

func TestInspectSchedulerSnapshotRejectsMalformedActiveVersion(t *testing.T) {
	ctx := context.Background()
	cache, redisServer := newSchedulerCacheUnitWithRedis(t)
	bucket := service.SchedulerBucket{GroupID: 5, Platform: service.PlatformOpenAI, Mode: service.SchedulerModeSingle}

	redisServer.Set(schedulerBucketKey(schedulerReadyPrefix, bucket), "1")
	redisServer.Set(schedulerBucketKey(schedulerActivePrefix, bucket), "invalid")

	_, err := cache.InspectSchedulerSnapshot(ctx, bucket)
	require.Error(t, err)
}
