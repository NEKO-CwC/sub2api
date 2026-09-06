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

type groupAccountPriorityAdminStub struct {
	service.AdminService
	getCalls int
	putCalls int
	input    service.GroupAccountPriorityUpdate
	snapshot *service.GroupAccountPrioritySnapshot
}

func (s *groupAccountPriorityAdminStub) GetGroupAccountPriorities(context.Context, int64) (*service.GroupAccountPrioritySnapshot, error) {
	s.getCalls++
	return s.snapshot, nil
}

func (s *groupAccountPriorityAdminStub) SetGroupAccountPriorities(_ context.Context, _ int64, input service.GroupAccountPriorityUpdate) (*service.GroupAccountPrioritySnapshot, error) {
	s.putCalls++
	s.input = input
	return s.snapshot, nil
}

func setupGroupAccountPriorityRouter(adminService service.AdminService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	handler := NewGroupHandler(adminService, nil, nil)
	router.GET("/api/v1/admin/groups/:id/account-priorities", handler.GetGroupAccountPriorities)
	router.PUT("/api/v1/admin/groups/:id/account-priorities", handler.SetGroupAccountPriorities)
	return router
}

func TestGroupAccountPriorityHandlerGETAndPUTContract(t *testing.T) {
	items := []service.GroupAccountPriorityItem{{AccountID: 11, Priority: 2}}
	hash := service.GroupAccountPriorityHash(items)
	adminService := &groupAccountPriorityAdminStub{snapshot: &service.GroupAccountPrioritySnapshot{
		ContractVersion: service.GroupAccountPriorityContractVersion,
		GroupID:         7,
		OperationID:     "op-7",
		Items:           items,
		ExpectedHash:    hash,
		ReadbackHash:    hash,
	}}
	router := setupGroupAccountPriorityRouter(adminService)

	getRecorder := httptest.NewRecorder()
	router.ServeHTTP(getRecorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/groups/7/account-priorities", nil))
	require.Equal(t, http.StatusOK, getRecorder.Code)
	require.Contains(t, getRecorder.Body.String(), `"contract_version":"group-account-priority.v1"`)
	require.Contains(t, getRecorder.Body.String(), `"readback_hash":"`+hash+`"`)

	putRecorder := httptest.NewRecorder()
	body := []byte(`{"operation_id":"op-7","expected_readback_hash":"` + hash + `","items":[{"account_id":11,"priority":2}]}`)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/groups/7/account-priorities", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(putRecorder, request)
	require.Equal(t, http.StatusOK, putRecorder.Code)
	require.Equal(t, 1, adminService.getCalls)
	require.Equal(t, 1, adminService.putCalls)
	require.Equal(t, "op-7", adminService.input.OperationID)
}

func TestGroupAccountPriorityHandlerRejectsInvalidIDAndBody(t *testing.T) {
	adminService := &groupAccountPriorityAdminStub{}
	router := setupGroupAccountPriorityRouter(adminService)

	for _, target := range []string{"0", "-1", "bad"} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/admin/groups/"+target+"/account-priorities", nil))
		require.Equal(t, http.StatusBadRequest, recorder.Code)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPut, "/api/v1/admin/groups/7/account-priorities", bytes.NewBufferString(`{"items":[]}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.Zero(t, adminService.putCalls)
}
