package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"
)

const SchedulerMembershipConfirmationContractVersion = "scheduler-membership-confirmation.v1"

type SchedulerMembershipConfirmationCapability struct {
	ContractVersion string `json:"contract_version"`
	Source          string `json:"source"`
	ActiveAllowed   bool   `json:"active_allowed"`
	ReasonCode      string `json:"reason_code,omitempty"`
}

type SchedulerMembershipBucketEvidence struct {
	GroupID        int64  `json:"group_id"`
	Platform       string `json:"platform"`
	Mode           string `json:"mode"`
	Ready          bool   `json:"ready"`
	ActiveVersion  int64  `json:"active_version"`
	AccountPresent bool   `json:"account_present"`
}

type SchedulerMembershipConfirmation struct {
	ContractVersion string                              `json:"contract_version"`
	Source          string                              `json:"source"`
	Confirmed       bool                                `json:"confirmed"`
	AccountID       int64                               `json:"account_id"`
	GroupIDs        []int64                             `json:"group_ids"`
	GroupVersions   map[string]int64                    `json:"group_versions"`
	Watermark       int64                               `json:"watermark"`
	ObservedAt      time.Time                           `json:"observed_at"`
	ReasonCode      string                              `json:"reason_code,omitempty"`
	Buckets         []SchedulerMembershipBucketEvidence `json:"buckets"`
}

func (s *SchedulerSnapshotService) SchedulerMembershipConfirmationCapability(ctx context.Context) (SchedulerMembershipConfirmationCapability, error) {
	capability := SchedulerMembershipConfirmationCapability{
		ContractVersion: SchedulerMembershipConfirmationContractVersion,
		Source:          "scheduler_snapshot",
	}
	if s == nil || s.cache == nil {
		capability.ReasonCode = "scheduler_cache_unavailable"
		return capability, nil
	}
	if s.isRunModeSimple() {
		capability.ReasonCode = "scheduler_simple_mode_unsupported"
		return capability, nil
	}
	if _, ok := s.cache.(SchedulerSnapshotInspector); !ok {
		capability.ReasonCode = "scheduler_snapshot_inspection_unsupported"
		return capability, nil
	}
	if _, err := s.cache.GetOutboxWatermark(ctx); err != nil {
		return capability, err
	}
	capability.ActiveAllowed = true
	return capability, nil
}

func (s *SchedulerSnapshotService) ConfirmSchedulerMembership(
	ctx context.Context,
	accountID int64,
	expectedGroupIDs []int64,
	affectedGroupIDs []int64,
) (SchedulerMembershipConfirmation, error) {
	result := SchedulerMembershipConfirmation{
		ContractVersion: SchedulerMembershipConfirmationContractVersion,
		Source:          "scheduler_snapshot",
		AccountID:       accountID,
		GroupVersions:   make(map[string]int64),
		Buckets:         make([]SchedulerMembershipBucketEvidence, 0),
		ObservedAt:      time.Now().UTC(),
	}
	if accountID <= 0 {
		return result, fmt.Errorf("account id must be positive")
	}
	expected, err := validateSchedulerMembershipGroupIDs(expectedGroupIDs, true)
	if err != nil {
		return result, fmt.Errorf("expected group ids: %w", err)
	}
	affected, err := validateSchedulerMembershipGroupIDs(affectedGroupIDs, false)
	if err != nil {
		return result, fmt.Errorf("affected group ids: %w", err)
	}
	if len(affected) > 64 {
		return result, fmt.Errorf("affected group ids exceed the maximum of 64")
	}
	affectedSet := make(map[int64]struct{}, len(affected))
	for _, groupID := range affected {
		affectedSet[groupID] = struct{}{}
		result.GroupVersions[strconv.FormatInt(groupID, 10)] = 0
	}
	for _, groupID := range expected {
		if _, ok := affectedSet[groupID]; !ok {
			return result, fmt.Errorf("expected group id %d is not affected", groupID)
		}
	}
	result.GroupIDs = expected

	capability, err := s.SchedulerMembershipConfirmationCapability(ctx)
	if err != nil {
		return result, err
	}
	if !capability.ActiveAllowed {
		result.ReasonCode = capability.ReasonCode
		return result, nil
	}

	account, err := s.cache.GetAccount(ctx, accountID)
	if err != nil {
		return result, err
	}
	if account == nil {
		result.ReasonCode = "scheduler_account_snapshot_not_ready"
		return s.withSchedulerMembershipWatermark(ctx, result)
	}
	if account.Platform != PlatformOpenAI {
		result.ReasonCode = "scheduler_account_platform_unsupported"
		return s.withSchedulerMembershipWatermark(ctx, result)
	}
	observedGroups, err := validateSchedulerMembershipGroupIDs(account.GroupIDs, true)
	if err != nil || !equalInt64Slices(observedGroups, expected) {
		result.ReasonCode = "scheduler_account_snapshot_not_converged"
		return s.withSchedulerMembershipWatermark(ctx, result)
	}

	expectedSet := make(map[int64]struct{}, len(expected))
	for _, groupID := range expected {
		expectedSet[groupID] = struct{}{}
	}
	inspector, ok := s.cache.(SchedulerSnapshotInspector)
	if !ok {
		result.ReasonCode = "scheduler_snapshot_inspection_unsupported"
		return s.withSchedulerMembershipWatermark(ctx, result)
	}
	confirmed := true
	for _, groupID := range affected {
		buckets := []SchedulerBucket{
			{GroupID: groupID, Platform: PlatformOpenAI, Mode: SchedulerModeSingle},
			{GroupID: groupID, Platform: PlatformOpenAI, Mode: SchedulerModeForced},
		}
		_, shouldContain := expectedSet[groupID]
		for _, bucket := range buckets {
			inspection, err := inspector.InspectSchedulerSnapshot(ctx, bucket)
			if err != nil {
				return result, err
			}
			present := containsSchedulerAccountID(inspection.AccountIDs, accountID)
			result.Buckets = append(result.Buckets, SchedulerMembershipBucketEvidence{
				GroupID:        groupID,
				Platform:       bucket.Platform,
				Mode:           bucket.Mode,
				Ready:          inspection.Ready,
				ActiveVersion:  inspection.ActiveVersion,
				AccountPresent: present,
			})
			versionKey := strconv.FormatInt(groupID, 10)
			currentVersion := result.GroupVersions[versionKey]
			if inspection.Ready && (currentVersion == 0 || inspection.ActiveVersion < currentVersion) {
				result.GroupVersions[versionKey] = inspection.ActiveVersion
			}
			matches := (!shouldContain && (!inspection.Ready || !present)) ||
				(shouldContain && inspection.Ready && present)
			if !matches {
				confirmed = false
				if result.ReasonCode == "" {
					result.ReasonCode = "scheduler_membership_not_converged"
				}
			}
		}
	}
	result.Confirmed = confirmed
	return s.withSchedulerMembershipWatermark(ctx, result)
}

func (s *SchedulerSnapshotService) withSchedulerMembershipWatermark(
	ctx context.Context,
	result SchedulerMembershipConfirmation,
) (SchedulerMembershipConfirmation, error) {
	watermark, err := s.cache.GetOutboxWatermark(ctx)
	if err != nil {
		return result, err
	}
	result.Watermark = watermark
	return result, nil
}

func validateSchedulerMembershipGroupIDs(groupIDs []int64, allowEmpty bool) ([]int64, error) {
	if len(groupIDs) == 0 && !allowEmpty {
		return nil, fmt.Errorf("must be non-empty")
	}
	seen := make(map[int64]struct{}, len(groupIDs))
	result := make([]int64, 0, len(groupIDs))
	for _, groupID := range groupIDs {
		if groupID <= 0 {
			return nil, fmt.Errorf("must contain positive ids")
		}
		if _, ok := seen[groupID]; ok {
			return nil, fmt.Errorf("contains duplicate id %d", groupID)
		}
		seen[groupID] = struct{}{}
		result = append(result, groupID)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func containsSchedulerAccountID(accountIDs []int64, target int64) bool {
	for _, accountID := range accountIDs {
		if accountID == target {
			return true
		}
	}
	return false
}

func equalInt64Slices(left, right []int64) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
