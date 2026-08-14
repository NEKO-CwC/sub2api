//go:build unit

package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

type schedulerMembershipHandlerCache struct {
	service.SchedulerCache
	emptyMembership bool
}

func (schedulerMembershipHandlerCache) GetOutboxWatermark(context.Context) (int64, error) {
	return 31, nil
}

func (c schedulerMembershipHandlerCache) GetAccount(context.Context, int64) (*service.Account, error) {
	if c.emptyMembership {
		return &service.Account{ID: 175, Platform: service.PlatformOpenAI, GroupIDs: []int64{}}, nil
	}
	return &service.Account{ID: 175, Platform: service.PlatformOpenAI, GroupIDs: []int64{5}}, nil
}

func (c schedulerMembershipHandlerCache) InspectSchedulerSnapshot(_ context.Context, bucket service.SchedulerBucket) (service.SchedulerSnapshotInspection, error) {
	accountIDs := []int64{175}
	if c.emptyMembership {
		accountIDs = nil
	}
	return service.SchedulerSnapshotInspection{
		Bucket:        bucket,
		Ready:         true,
		ActiveVersion: 7,
		AccountIDs:    accountIDs,
	}, nil
}

func newSchedulerMembershipHandlerTestRouter(cache schedulerMembershipHandlerCache) *gin.Engine {
	gin.SetMode(gin.TestMode)
	snapshot := service.NewSchedulerSnapshotService(
		cache,
		nil,
		nil,
		nil,
		&config.Config{RunMode: config.RunModeStandard},
	)
	handler := ProvideOpsHandler(nil, snapshot)
	router := gin.New()
	router.GET("/capability", handler.GetSchedulerMembershipConfirmationCapability)
	router.POST("/confirm", handler.ConfirmSchedulerMembership)
	return router
}

func TestSchedulerMembershipHandlerExposesReadOnlyConfirmationContract(t *testing.T) {
	router := newSchedulerMembershipHandlerTestRouter(schedulerMembershipHandlerCache{})

	capability := httptest.NewRecorder()
	router.ServeHTTP(capability, httptest.NewRequest(http.MethodGet, "/capability", nil))
	require.Equal(t, http.StatusOK, capability.Code)
	require.JSONEq(t, `{
		"code": 0,
		"message": "success",
		"data": {
			"contract_version": "scheduler-membership-confirmation.v1",
			"source": "scheduler_snapshot",
			"active_allowed": true
		}
	}`, capability.Body.String())

	confirmation := httptest.NewRecorder()
	body := bytes.NewBufferString(`{
		"account_id": 175,
		"expected_group_ids": [5],
		"affected_group_ids": [5],
		"operation_id": "confirm-175"
	}`)
	request := httptest.NewRequest(http.MethodPost, "/confirm", body)
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(confirmation, request)
	require.Equal(t, http.StatusOK, confirmation.Code)
	require.Contains(t, confirmation.Body.String(), `"confirmed":true`)
	require.Contains(t, confirmation.Body.String(), `"watermark":31`)
	var confirmationEnvelope struct {
		Data struct {
			ObservedAt time.Time `json:"observed_at"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(confirmation.Body.Bytes(), &confirmationEnvelope))
	require.False(t, confirmationEnvelope.Data.ObservedAt.IsZero())
	require.Equal(t, time.UTC, confirmationEnvelope.Data.ObservedAt.Location())
}

func TestSchedulerMembershipHandlerRejectsDuplicateGroups(t *testing.T) {
	router := newSchedulerMembershipHandlerTestRouter(schedulerMembershipHandlerCache{})
	recorder := httptest.NewRecorder()
	body := bytes.NewBufferString(`{
		"account_id": 175,
		"expected_group_ids": [5, 5],
		"affected_group_ids": [5],
		"operation_id": "confirm-175"
	}`)
	request := httptest.NewRequest(http.MethodPost, "/confirm", body)
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestSchedulerMembershipHandlerAcceptsEmptyExpectedGroups(t *testing.T) {
	router := newSchedulerMembershipHandlerTestRouter(schedulerMembershipHandlerCache{emptyMembership: true})
	recorder := httptest.NewRecorder()
	body := bytes.NewBufferString(`{
		"account_id": 175,
		"expected_group_ids": [],
		"affected_group_ids": [5],
		"operation_id": "confirm-empty-175"
	}`)
	request := httptest.NewRequest(http.MethodPost, "/confirm", body)
	request.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	require.Contains(t, recorder.Body.String(), `"confirmed":true`)
	require.Contains(t, recorder.Body.String(), `"group_ids":[]`)
}
