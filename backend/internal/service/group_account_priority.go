package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

const (
	GroupAccountPriorityContractVersion = "group-account-priority.v1"
	GroupAccountPriorityMax             = 1_000_000
	groupAccountPriorityMaxItems        = 10_000
)

var (
	ErrGroupAccountPriorityUnsupported = infraerrors.ServiceUnavailable(
		"GROUP_ACCOUNT_PRIORITY_UNSUPPORTED",
		"group account priority contract is unavailable",
	)
	ErrGroupAccountPriorityOperationConflict = infraerrors.Conflict(
		"GROUP_ACCOUNT_PRIORITY_OPERATION_CONFLICT",
		"operation_id belongs to a different request",
	)
	ErrGroupAccountPriorityMembershipConflict = infraerrors.Conflict(
		"GROUP_ACCOUNT_PRIORITY_MEMBERSHIP_CONFLICT",
		"items must exactly match the requested group's current account membership",
	)
	ErrGroupAccountPriorityReadbackMismatch = infraerrors.Conflict(
		"GROUP_ACCOUNT_PRIORITY_READBACK_MISMATCH",
		"group account priority readback hash does not match expected hash",
	)
)

type GroupAccountPriorityItem struct {
	AccountID int64 `json:"account_id"`
	Priority  int   `json:"priority"`
}

type GroupAccountPriorityUpdate struct {
	GroupID              int64                      `json:"-"`
	OperationID          string                     `json:"operation_id"`
	ExpectedReadbackHash string                     `json:"expected_readback_hash"`
	Items                []GroupAccountPriorityItem `json:"items"`
	RequestHash          string                     `json:"-"`
}

type GroupAccountPrioritySnapshot struct {
	ContractVersion string                     `json:"contract_version"`
	GroupID         int64                      `json:"group_id"`
	OperationID     string                     `json:"operation_id,omitempty"`
	Items           []GroupAccountPriorityItem `json:"items"`
	ExpectedHash    string                     `json:"expected_hash,omitempty"`
	ReadbackHash    string                     `json:"readback_hash"`
	Replayed        bool                       `json:"replayed"`
}

type groupAccountPriorityRepository interface {
	GetGroupAccountPriorities(ctx context.Context, groupID int64) (*GroupAccountPrioritySnapshot, error)
	PutGroupAccountPriorities(ctx context.Context, input GroupAccountPriorityUpdate) (*GroupAccountPrioritySnapshot, error)
}

func GroupAccountPriorityHash(items []GroupAccountPriorityItem) string {
	canonical := append([]GroupAccountPriorityItem(nil), items...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].AccountID < canonical[j].AccountID })
	payload, _ := json.Marshal(struct {
		ContractVersion string                     `json:"contract_version"`
		Items           []GroupAccountPriorityItem `json:"items"`
	}{ContractVersion: GroupAccountPriorityContractVersion, Items: canonical})
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *adminServiceImpl) GetGroupAccountPriorities(ctx context.Context, groupID int64) (*GroupAccountPrioritySnapshot, error) {
	if err := s.validateGroupAccountPriorityCapability(ctx, groupID); err != nil {
		return nil, err
	}
	repo, ok := s.accountRepo.(groupAccountPriorityRepository)
	if !ok {
		return nil, ErrGroupAccountPriorityUnsupported
	}
	return repo.GetGroupAccountPriorities(ctx, groupID)
}

func (s *adminServiceImpl) SetGroupAccountPriorities(ctx context.Context, groupID int64, input GroupAccountPriorityUpdate) (*GroupAccountPrioritySnapshot, error) {
	if groupID <= 0 {
		return nil, infraerrors.BadRequest("GROUP_ID_INVALID", "group id must be positive")
	}
	input.OperationID = strings.TrimSpace(input.OperationID)
	if !validGroupAccountPriorityOperationID(input.OperationID) {
		return nil, infraerrors.BadRequest("OPERATION_ID_INVALID", "operation_id is invalid")
	}
	if !validGroupAccountPrioritySHA256(input.ExpectedReadbackHash) {
		return nil, infraerrors.BadRequest("EXPECTED_HASH_INVALID", "expected_readback_hash is invalid")
	}
	if len(input.Items) == 0 || len(input.Items) > groupAccountPriorityMaxItems {
		return nil, infraerrors.BadRequest("PRIORITY_ITEMS_INVALID", "items must contain between 1 and 10000 entries")
	}
	seen := make(map[int64]struct{}, len(input.Items))
	for _, item := range input.Items {
		if item.AccountID <= 0 {
			return nil, infraerrors.BadRequest("ACCOUNT_ID_INVALID", "account_id must be positive")
		}
		if item.Priority < 0 || item.Priority > GroupAccountPriorityMax {
			return nil, infraerrors.BadRequest("PRIORITY_INVALID", "priority must be between 0 and 1000000")
		}
		if _, exists := seen[item.AccountID]; exists {
			return nil, infraerrors.BadRequest("ACCOUNT_ID_DUPLICATE", "items contain a duplicate account_id")
		}
		seen[item.AccountID] = struct{}{}
	}
	sort.Slice(input.Items, func(i, j int) bool { return input.Items[i].AccountID < input.Items[j].AccountID })
	requestPayload, _ := json.Marshal(struct {
		ContractVersion string                     `json:"contract_version"`
		GroupID         int64                      `json:"group_id"`
		ExpectedHash    string                     `json:"expected_readback_hash"`
		Items           []GroupAccountPriorityItem `json:"items"`
	}{GroupAccountPriorityContractVersion, groupID, input.ExpectedReadbackHash, input.Items})
	requestSum := sha256.Sum256(requestPayload)
	input.RequestHash = "sha256:" + hex.EncodeToString(requestSum[:])
	input.GroupID = groupID
	if err := s.validateGroupAccountPriorityCapability(ctx, groupID); err != nil {
		return nil, err
	}
	repo, ok := s.accountRepo.(groupAccountPriorityRepository)
	if !ok {
		return nil, ErrGroupAccountPriorityUnsupported
	}
	return repo.PutGroupAccountPriorities(ctx, input)
}

func (s *adminServiceImpl) validateGroupAccountPriorityCapability(ctx context.Context, groupID int64) error {
	if groupID <= 0 {
		return infraerrors.BadRequest("GROUP_ID_INVALID", "group id must be positive")
	}
	if s == nil || s.groupRepo == nil || s.accountRepo == nil {
		return ErrGroupAccountPriorityUnsupported
	}
	if _, err := s.groupRepo.GetByIDLite(ctx, groupID); err != nil {
		return err
	}
	if _, ok := s.accountRepo.(groupAccountPriorityRepository); !ok {
		return ErrGroupAccountPriorityUnsupported
	}
	return nil
}

func validGroupAccountPriorityOperationID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._:/-", character) {
			continue
		}
		return false
	}
	return true
}

func validGroupAccountPrioritySHA256(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}
