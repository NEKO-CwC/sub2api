//go:build unit

package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

type membershipConfirmationCache struct {
	SchedulerCache
	account      *Account
	watermark    int64
	inspections  map[string]SchedulerSnapshotInspection
	inspectErr   error
	watermarkErr error
}

func (c *membershipConfirmationCache) GetAccount(context.Context, int64) (*Account, error) {
	return c.account, nil
}

func (c *membershipConfirmationCache) GetOutboxWatermark(context.Context) (int64, error) {
	return c.watermark, c.watermarkErr
}

func (c *membershipConfirmationCache) InspectSchedulerSnapshot(_ context.Context, bucket SchedulerBucket) (SchedulerSnapshotInspection, error) {
	if c.inspectErr != nil {
		return SchedulerSnapshotInspection{Bucket: bucket}, c.inspectErr
	}
	inspection, ok := c.inspections[bucket.String()]
	if !ok {
		return SchedulerSnapshotInspection{Bucket: bucket}, nil
	}
	return inspection, nil
}

func newMembershipConfirmationService(cache SchedulerCache, runMode string) *SchedulerSnapshotService {
	return NewSchedulerSnapshotService(cache, nil, nil, nil, &config.Config{RunMode: runMode})
}

func membershipInspection(bucket SchedulerBucket, version int64, accountIDs ...int64) SchedulerSnapshotInspection {
	return SchedulerSnapshotInspection{Bucket: bucket, Ready: true, ActiveVersion: version, AccountIDs: accountIDs}
}

func TestConfirmSchedulerMembershipProvesPresenceAndAbsence(t *testing.T) {
	cache := &membershipConfirmationCache{
		account:     &Account{ID: 175, Platform: PlatformOpenAI, GroupIDs: []int64{5}},
		watermark:   219,
		inspections: make(map[string]SchedulerSnapshotInspection),
	}
	for _, mode := range []string{SchedulerModeSingle, SchedulerModeForced} {
		removed := SchedulerBucket{GroupID: 4, Platform: PlatformOpenAI, Mode: mode}
		expected := SchedulerBucket{GroupID: 5, Platform: PlatformOpenAI, Mode: mode}
		cache.inspections[removed.String()] = membershipInspection(removed, 8)
		cache.inspections[expected.String()] = membershipInspection(expected, 13, 175, 176)
	}

	result, err := newMembershipConfirmationService(cache, config.RunModeStandard).
		ConfirmSchedulerMembership(context.Background(), 175, []int64{5}, []int64{5, 4})

	require.NoError(t, err)
	require.True(t, result.Confirmed)
	require.Equal(t, []int64{5}, result.GroupIDs)
	require.Equal(t, int64(8), result.GroupVersions["4"])
	require.Equal(t, int64(13), result.GroupVersions["5"])
	require.Equal(t, int64(219), result.Watermark)
	require.Len(t, result.Buckets, 4)
	require.False(t, result.ObservedAt.IsZero())
	require.Equal(t, time.UTC, result.ObservedAt.Location())
}

func TestConfirmSchedulerMembershipProvesEmptyTargetFromOldBuckets(t *testing.T) {
	cache := &membershipConfirmationCache{
		account:     &Account{ID: 175, Platform: PlatformOpenAI, GroupIDs: []int64{}},
		watermark:   220,
		inspections: make(map[string]SchedulerSnapshotInspection),
	}
	for _, mode := range []string{SchedulerModeSingle, SchedulerModeForced} {
		removed := SchedulerBucket{GroupID: 5, Platform: PlatformOpenAI, Mode: mode}
		cache.inspections[removed.String()] = membershipInspection(removed, 14)
	}

	result, err := newMembershipConfirmationService(cache, config.RunModeStandard).
		ConfirmSchedulerMembership(context.Background(), 175, nil, []int64{5})

	require.NoError(t, err)
	require.True(t, result.Confirmed)
	require.Empty(t, result.GroupIDs)
	require.Equal(t, int64(14), result.GroupVersions["5"])
	require.Equal(t, int64(220), result.Watermark)
}

func TestConfirmSchedulerMembershipFailsClosedUntilEveryExpectedBucketIsReady(t *testing.T) {
	cache := &membershipConfirmationCache{
		account:     &Account{ID: 175, Platform: PlatformOpenAI, GroupIDs: []int64{5}},
		inspections: make(map[string]SchedulerSnapshotInspection),
	}
	single := SchedulerBucket{GroupID: 5, Platform: PlatformOpenAI, Mode: SchedulerModeSingle}
	cache.inspections[single.String()] = membershipInspection(single, 4, 175)

	result, err := newMembershipConfirmationService(cache, config.RunModeStandard).
		ConfirmSchedulerMembership(context.Background(), 175, []int64{5}, []int64{5})

	require.NoError(t, err)
	require.False(t, result.Confirmed)
	require.Equal(t, "scheduler_membership_not_converged", result.ReasonCode)
	require.False(t, result.ObservedAt.IsZero())
	require.Equal(t, time.UTC, result.ObservedAt.Location())
}

func TestSchedulerMembershipConfirmationRejectsUnsafeInputsAndModes(t *testing.T) {
	cache := &membershipConfirmationCache{
		account:     &Account{ID: 175, Platform: PlatformOpenAI, GroupIDs: []int64{5}},
		inspections: make(map[string]SchedulerSnapshotInspection),
	}
	confirmationService := newMembershipConfirmationService(cache, config.RunModeStandard)

	_, err := confirmationService.ConfirmSchedulerMembership(context.Background(), 175, []int64{5, 5}, []int64{5})
	require.Error(t, err)
	_, err = confirmationService.ConfirmSchedulerMembership(context.Background(), 175, []int64{5}, []int64{4})
	require.Error(t, err)
	_, err = confirmationService.ConfirmSchedulerMembership(context.Background(), 175, nil, nil)
	require.Error(t, err)

	capability, err := newMembershipConfirmationService(cache, config.RunModeSimple).
		SchedulerMembershipConfirmationCapability(context.Background())
	require.NoError(t, err)
	require.False(t, capability.ActiveAllowed)
	require.Equal(t, "scheduler_simple_mode_unsupported", capability.ReasonCode)
}

func TestSchedulerMembershipConfirmationPropagatesInspectionAndRedisFailures(t *testing.T) {
	cache := &membershipConfirmationCache{
		account:     &Account{ID: 175, Platform: PlatformOpenAI, GroupIDs: []int64{5}},
		inspections: make(map[string]SchedulerSnapshotInspection),
		inspectErr:  errors.New("redis read failed"),
	}
	_, err := newMembershipConfirmationService(cache, config.RunModeStandard).
		ConfirmSchedulerMembership(context.Background(), 175, []int64{5}, []int64{5})
	require.Error(t, err)

	cache.inspectErr = nil
	cache.watermarkErr = errors.New("watermark read failed")
	capability, err := newMembershipConfirmationService(cache, config.RunModeStandard).
		SchedulerMembershipConfirmationCapability(context.Background())
	require.Error(t, err)
	require.False(t, capability.ActiveAllowed)
}
