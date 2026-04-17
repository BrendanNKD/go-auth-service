package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"auth-service/handlers"

	"github.com/stretchr/testify/assert"
)

func TestInstanceInfoHandlerUsesOverride(t *testing.T) {
	t.Setenv("AUTH_SERVICE_INSTANCE_ID", "local-task-a")
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/instance", nil)
	rec := httptest.NewRecorder()

	handlers.InstanceInfoHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	var response handlers.InstanceInfo
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, "auth-service", response.Service)
	assert.Equal(t, "local-task-a", response.InstanceID)
	assert.Equal(t, "local-task-a", response.DisplayID)
	assert.Equal(t, "env", response.Source)
	assert.NotEmpty(t, response.TimeUTC)
}

func TestInstanceInfoHandlerUsesECSMetadata(t *testing.T) {
	taskID := "1234567890abcdef1234567890abcdef"
	metadataServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/task", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"TaskARN": "arn:aws:ecs:ap-southeast-1:111122223333:task/auth-cluster/` + taskID + `",
			"Family": "auth-service",
			"Revision": "42",
			"AvailabilityZone": "ap-southeast-1a",
			"LaunchType": "FARGATE"
		}`))
	}))
	defer metadataServer.Close()

	t.Setenv("AUTH_SERVICE_INSTANCE_ID", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", metadataServer.URL)
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/instance", nil)
	rec := httptest.NewRecorder()

	handlers.InstanceInfoHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response handlers.InstanceInfo
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.Equal(t, taskID, response.InstanceID)
	assert.Equal(t, taskID, response.TaskID)
	assert.Equal(t, "auth-service", response.TaskFamily)
	assert.Equal(t, "42", response.TaskRevision)
	assert.Equal(t, "ap-southeast-1a", response.AvailabilityZone)
	assert.Equal(t, "FARGATE", response.LaunchType)
	assert.Equal(t, "ecs-task-metadata", response.Source)
}

func TestInstanceInfoHandlerFallsBackToHostname(t *testing.T) {
	t.Setenv("AUTH_SERVICE_INSTANCE_ID", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI_V4", "")
	t.Setenv("ECS_CONTAINER_METADATA_URI", "")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/instance", nil)
	rec := httptest.NewRecorder()

	handlers.InstanceInfoHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var response handlers.InstanceInfo
	assert.NoError(t, json.Unmarshal(rec.Body.Bytes(), &response))
	assert.NotEmpty(t, response.InstanceID)
	assert.NotEmpty(t, response.DisplayID)
	assert.Contains(t, []string{"hostname", "process"}, response.Source)
}
