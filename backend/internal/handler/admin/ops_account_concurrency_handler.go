package admin

import (
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

type accountConcurrencyConfirmationRequest struct {
	AccountIDs []int64 `json:"account_ids"`
}

// ConfirmAccountConcurrency exposes a strict Redis readback for bounded
// control-plane drain verification.
func (h *OpsHandler) ConfirmAccountConcurrency(c *gin.Context) {
	if h == nil || h.opsService == nil {
		response.Error(c, http.StatusServiceUnavailable, "Account concurrency confirmation is unavailable")
		return
	}
	var request accountConcurrencyConfirmationRequest
	if err := c.ShouldBindJSON(&request); err != nil || !validAccountConcurrencyIDs(request.AccountIDs, 64) {
		response.BadRequest(c, "Invalid account concurrency confirmation request")
		return
	}
	confirmation, err := h.opsService.ConfirmAccountConcurrency(c.Request.Context(), request.AccountIDs)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, confirmation)
}

func validAccountConcurrencyIDs(accountIDs []int64, maximum int) bool {
	if len(accountIDs) == 0 || len(accountIDs) > maximum {
		return false
	}
	seen := make(map[int64]struct{}, len(accountIDs))
	for _, accountID := range accountIDs {
		if accountID <= 0 {
			return false
		}
		if _, exists := seen[accountID]; exists {
			return false
		}
		seen[accountID] = struct{}{}
	}
	return true
}
