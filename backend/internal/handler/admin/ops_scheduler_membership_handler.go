package admin

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

type schedulerMembershipConfirmationRequest struct {
	AccountID        int64   `json:"account_id"`
	ExpectedGroupIDs []int64 `json:"expected_group_ids"`
	AffectedGroupIDs []int64 `json:"affected_group_ids"`
	OperationID      string  `json:"operation_id"`
}

func (h *OpsHandler) GetSchedulerMembershipConfirmationCapability(c *gin.Context) {
	if h == nil || h.schedulerSnapshot == nil {
		response.Success(c, service.SchedulerMembershipConfirmationCapability{
			ContractVersion: service.SchedulerMembershipConfirmationContractVersion,
			Source:          "scheduler_snapshot",
			ReasonCode:      "scheduler_snapshot_service_unavailable",
		})
		return
	}
	capability, err := h.schedulerSnapshot.SchedulerMembershipConfirmationCapability(c.Request.Context())
	if err != nil {
		response.Error(c, http.StatusServiceUnavailable, "Scheduler membership confirmation is unavailable")
		return
	}
	response.Success(c, capability)
}

func (h *OpsHandler) ConfirmSchedulerMembership(c *gin.Context) {
	if h == nil || h.schedulerSnapshot == nil {
		response.Error(c, http.StatusServiceUnavailable, "Scheduler membership confirmation is unavailable")
		return
	}
	var request schedulerMembershipConfirmationRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		response.BadRequest(c, "Invalid scheduler membership confirmation request")
		return
	}
	if request.AccountID <= 0 ||
		!validSchedulerMembershipGroupIDs(request.ExpectedGroupIDs, 64, true) ||
		!validSchedulerMembershipGroupIDs(request.AffectedGroupIDs, 64, false) ||
		!schedulerMembershipSubset(request.ExpectedGroupIDs, request.AffectedGroupIDs) ||
		!validSchedulerMembershipOperationID(request.OperationID) {
		response.BadRequest(c, "Invalid scheduler membership confirmation request")
		return
	}
	confirmation, err := h.schedulerSnapshot.ConfirmSchedulerMembership(
		c.Request.Context(),
		request.AccountID,
		request.ExpectedGroupIDs,
		request.AffectedGroupIDs,
	)
	if err != nil {
		response.Error(c, http.StatusServiceUnavailable, "Scheduler membership confirmation is unavailable")
		return
	}
	response.Success(c, confirmation)
}

func validSchedulerMembershipGroupIDs(groupIDs []int64, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && len(groupIDs) == 0) || len(groupIDs) > maximum {
		return false
	}
	seen := make(map[int64]struct{}, len(groupIDs))
	for _, groupID := range groupIDs {
		if groupID <= 0 {
			return false
		}
		if _, exists := seen[groupID]; exists {
			return false
		}
		seen[groupID] = struct{}{}
	}
	return true
}

func schedulerMembershipSubset(expected, affected []int64) bool {
	affectedSet := make(map[int64]struct{}, len(affected))
	for _, groupID := range affected {
		affectedSet[groupID] = struct{}{}
	}
	for _, groupID := range expected {
		if _, ok := affectedSet[groupID]; !ok {
			return false
		}
	}
	return true
}

func validSchedulerMembershipOperationID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == ':' ||
			character == '/' || character == '-' {
			continue
		}
		return false
	}
	return true
}
