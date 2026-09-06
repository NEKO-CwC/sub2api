package handler

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

func (h *OpenAIGatewayHandler) GetRoutingObserverHealth(c *gin.Context) {
	if h == nil {
		response.Success(c, RoutingObserverHealth{})
		return
	}
	response.Success(c, h.routingObserver.Health())
}

func (h *OpenAIGatewayHandler) GetRoutingObserverScope(c *gin.Context) {
	groupID, model, ok := routingObserverPath(c)
	if !ok {
		return
	}
	if h == nil || h.routingObserver == nil {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_disabled", "routing observer is disabled"))
		return
	}
	readback, err := h.routingObserver.GetScope(groupID, model)
	if err != nil {
		writeRoutingObserverError(c, err)
		return
	}
	response.Success(c, gin.H{"item": readback})
}

func (h *OpenAIGatewayHandler) PutRoutingObserverScope(c *gin.Context) {
	groupID, model, ok := routingObserverPath(c)
	if !ok {
		return
	}
	if h == nil || h.routingObserver == nil {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_disabled", "routing observer is disabled"))
		return
	}
	var request RoutingObserverScopePutRequest
	if err := decodeRoutingObserverAdminRequest(c, &request); err != nil {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusBadRequest, "routing_scope_request_invalid", "routing scope request is invalid"))
		return
	}
	readback, err := h.routingObserver.PutScope(groupID, model, request)
	if err != nil {
		writeRoutingObserverError(c, err)
		return
	}
	response.Success(c, gin.H{"item": readback})
}

func (h *OpenAIGatewayHandler) DeleteRoutingObserverScope(c *gin.Context) {
	groupID, model, ok := routingObserverPath(c)
	if !ok {
		return
	}
	if h == nil || h.routingObserver == nil {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusServiceUnavailable, "routing_observer_disabled", "routing observer is disabled"))
		return
	}
	var request RoutingObserverScopeDeleteRequest
	if err := decodeRoutingObserverAdminRequest(c, &request); err != nil {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusBadRequest, "routing_scope_delete_invalid", "routing scope delete request is invalid"))
		return
	}
	if err := h.routingObserver.DeleteScope(groupID, model, request); err != nil {
		writeRoutingObserverError(c, err)
		return
	}
	response.Success(c, gin.H{"deleted": true, "operation_id": request.OperationID})
}

func routingObserverPath(c *gin.Context) (int64, string, bool) {
	groupID, err := strconv.ParseInt(c.Param("group_id"), 10, 64)
	model := c.Param("canonical_model")
	if err != nil || groupID <= 0 || model == "" || strings.TrimSpace(model) != model {
		writeRoutingObserverError(c, routingObserverOperationError(http.StatusBadRequest, "routing_scope_path_invalid", "routing scope path is invalid"))
		return 0, "", false
	}
	return groupID, model, true
}

func decodeRoutingObserverAdminRequest(c *gin.Context, target any) error {
	if c == nil || c.Request == nil || c.Request.Body == nil {
		return errors.New("routing observer request body is missing")
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, routingObserverAdminMaxBodyBytes)
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil || len(payload) == 0 {
		return errors.New("routing observer request body is invalid")
	}
	return decodeRoutingObserverJSON(payload, target)
}

func writeRoutingObserverError(c *gin.Context, err error) {
	var operationError *RoutingObserverOperationError
	if errors.As(err, &operationError) {
		response.ErrorWithDetails(c, operationError.StatusCode, operationError.Message, operationError.ReasonCode, nil)
		return
	}
	response.ErrorWithDetails(c, http.StatusInternalServerError, "routing observer operation failed", "routing_observer_internal_error", nil)
}
