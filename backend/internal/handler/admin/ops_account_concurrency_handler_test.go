//go:build unit

package admin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type accountConcurrencyConfirmationCache struct {
	service.ConcurrencyCache
	counts map[int64]int
	err    error
}

func (c accountConcurrencyConfirmationCache) GetAccountConcurrencyBatch(_ context.Context, accountIDs []int64) (map[int64]int, error) {
	if c.err != nil {
		return nil, c.err
	}
	result := make(map[int64]int, len(accountIDs))
	for _, accountID := range accountIDs {
		result[accountID] = c.counts[accountID]
	}
	return result, nil
}

func newAccountConcurrencyConfirmationRouter(cache service.ConcurrencyCache) *gin.Engine {
	gateway := service.NewConcurrencyService(cache)
	ops := service.NewOpsService(nil, nil, nil, nil, nil, gateway, nil, nil, nil, nil, nil)
	handler := NewOpsHandler(ops)
	router := gin.New()
	router.POST("/confirm", handler.ConfirmAccountConcurrency)
	return router
}

func TestAccountConcurrencyConfirmationIsVersionedAndFailClosed(t *testing.T) {
	router := newAccountConcurrencyConfirmationRouter(accountConcurrencyConfirmationCache{
		counts: map[int64]int{175: 0, 176: 2},
	})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/confirm", bytes.NewBufferString(`{"account_ids":[175,176]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"contract_version":"account-concurrency-confirmation.v1"`)
	require.Contains(t, recorder.Body.String(), `"source":"redis_concurrency"`)
	require.Contains(t, recorder.Body.String(), `"account_id":176,"current_concurrency":2`)

	failed := newAccountConcurrencyConfirmationRouter(accountConcurrencyConfirmationCache{err: context.DeadlineExceeded})
	failure := httptest.NewRecorder()
	failureRequest := httptest.NewRequest(http.MethodPost, "/confirm", bytes.NewBufferString(`{"account_ids":[175]}`))
	failureRequest.Header.Set("Content-Type", "application/json")
	failed.ServeHTTP(failure, failureRequest)
	require.Equal(t, http.StatusServiceUnavailable, failure.Code)
}

func TestAccountConcurrencyConfirmationRejectsDuplicateAccounts(t *testing.T) {
	router := newAccountConcurrencyConfirmationRouter(accountConcurrencyConfirmationCache{counts: map[int64]int{175: 0}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/confirm", bytes.NewBufferString(`{"account_ids":[175,175]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
}
