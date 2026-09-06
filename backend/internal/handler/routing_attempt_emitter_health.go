package handler

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/gin-gonic/gin"
)

// GetRoutingAttemptEmitterHealth exposes counters and queue pressure only. It
// intentionally omits the Panel URL, shared secret, and observation payloads.
func (h *OpenAIGatewayHandler) GetRoutingAttemptEmitterHealth(c *gin.Context) {
	if h == nil {
		response.Success(c, RoutingAttemptEmitterStats{})
		return
	}
	response.Success(c, h.routingAttemptEmitter.Stats())
}
