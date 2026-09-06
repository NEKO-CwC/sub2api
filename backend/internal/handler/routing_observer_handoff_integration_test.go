//go:build integration

package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/repository"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"go.uber.org/zap"
)

func TestFailoverHandoffRealRedisHandlerPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tcredis.Run(ctx, "redis:8.4-alpine")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(context.Background())) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "6379/tcp")
	require.NoError(t, err)
	client := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("%s:%d", host, port.Int())})
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	require.NoError(t, client.Ping(ctx).Err())

	cache := repository.NewConcurrencyCache(client, 15, 900)
	concurrencyService := service.NewConcurrencyService(cache)
	backend := newRoutingObserverRecorderTestBackend(t)
	recorder := newRoutingObserverRecorderWithBackend(backend, 31, "gpt-5.6-sol", 301, routingAttemptCorrelation{})
	failure := &service.UpstreamFailoverError{
		Scope:             service.GatewayFailureScopeAccount,
		Reason:            service.GatewayFailureReason("real_redis_primary_failure"),
		NextAccountAction: service.NextAccountRetry,
	}

	primary, err := concurrencyService.AcquireAccountSlot(ctx, 101, 1)
	require.NoError(t, err)
	require.True(t, primary.Acquired)
	recorder.record(101, nil, failure, time.Unix(1, 0))
	primary.ReleaseFunc()
	predecessor := recorder.prepareFailover(101, failure)
	require.Equal(t, int64(101), predecessor)
	tracker := service.NewAccountSlotHandoffTracker()
	require.True(t, tracker.SetPredecessor(predecessor))

	requestContext := service.ContextWithAccountSlotHandoffTracker(ctx, tracker)
	handler := &OpenAIGatewayHandler{
		gatewayService:    &service.OpenAIGatewayService{},
		concurrencyHelper: NewConcurrencyHelper(concurrencyService, SSEPingFormatComment, 0),
	}
	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil).WithContext(requestContext)
	selection := &service.AccountSelectionResult{
		Account:  &service.Account{ID: 102, Concurrency: 1},
		WaitPlan: &service.AccountWaitPlan{AccountID: 102, MaxConcurrency: 1, Timeout: time.Second, MaxWaiting: 1},
	}
	streamStarted := false
	release, slotResult := handler.acquireResponsesAccountSlot(ginContext, nil, "", selection, false, &streamStarted, zap.NewNop())
	require.Equal(t, openAISlotAcquireOK, slotResult)
	require.NotNil(t, release)
	recorder.captureHandoff(tracker, 102)
	recorder.record(102, &service.OpenAIForwardResult{}, nil, time.Unix(3, 0))
	recorder.finish(true)
	release()

	require.Len(t, backend.submitted, 1)
	fact := backend.submitted[0]
	require.NotNil(t, fact.Handoff)
	require.True(t, fact.Handoff.Complete)
	require.Equal(t, 0, fact.Handoff.PrimaryConcurrency)
	require.Equal(t, 1, fact.Handoff.FallbackConcurrency)
	registry := NewDefaultRoutingPolicyRegistry()
	_, err = registry.ValidateAndLoad(backend.scope.Policy)
	require.NoError(t, err)
	decision := registry.Evaluate(backend.scope, fact)
	require.NotNil(t, decision.Winner)
	require.Equal(t, RoutingCriticalFailureRuleV1, decision.Winner.RuleID)
}
