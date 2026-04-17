package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const serviceName = "auth-service"

var instanceMetadataClient = &http.Client{Timeout: 750 * time.Millisecond}

type InstanceInfo struct {
	Service          string `json:"service"`
	InstanceID       string `json:"instance_id"`
	DisplayID        string `json:"display_id"`
	Hostname         string `json:"hostname,omitempty"`
	TaskID           string `json:"task_id,omitempty"`
	TaskFamily       string `json:"task_family,omitempty"`
	TaskRevision     string `json:"task_revision,omitempty"`
	AvailabilityZone string `json:"availability_zone,omitempty"`
	LaunchType       string `json:"launch_type,omitempty"`
	Source           string `json:"source"`
	TimeUTC          string `json:"time_utc"`
}

type ecsTaskMetadata struct {
	TaskARN          string `json:"TaskARN"`
	Family           string `json:"Family"`
	Revision         string `json:"Revision"`
	AvailabilityZone string `json:"AvailabilityZone"`
	LaunchType       string `json:"LaunchType"`
}

// InstanceInfoHandler returns a small runtime identity for load-balancer demos.
func InstanceInfoHandler(w http.ResponseWriter, r *http.Request) {
	info := ResolveInstanceInfo(r.Context())

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(info)
}

func ResolveInstanceInfo(ctx context.Context) InstanceInfo {
	hostname := resolveHostname()

	if override := strings.TrimSpace(os.Getenv("AUTH_SERVICE_INSTANCE_ID")); override != "" {
		return newInstanceInfo(override, "env", hostname, ecsTaskMetadata{})
	}

	if metadata, ok := fetchECSMetadata(ctx); ok {
		taskID := taskIDFromARN(metadata.TaskARN)
		if taskID != "" {
			return newInstanceInfo(taskID, "ecs-task-metadata", hostname, metadata)
		}
	}

	instanceID := hostname
	source := "hostname"
	if instanceID == "" {
		instanceID = fmt.Sprintf("pid-%d", os.Getpid())
		source = "process"
	}

	return newInstanceInfo(instanceID, source, hostname, ecsTaskMetadata{})
}

func newInstanceInfo(instanceID, source, hostname string, metadata ecsTaskMetadata) InstanceInfo {
	return InstanceInfo{
		Service:          serviceName,
		InstanceID:       instanceID,
		DisplayID:        stableDisplayID(instanceID),
		Hostname:         hostname,
		TaskID:           taskIDFromARN(metadata.TaskARN),
		TaskFamily:       metadata.Family,
		TaskRevision:     metadata.Revision,
		AvailabilityZone: metadata.AvailabilityZone,
		LaunchType:       metadata.LaunchType,
		Source:           source,
		TimeUTC:          time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func resolveHostname() string {
	if hostname, err := os.Hostname(); err == nil {
		return strings.TrimSpace(hostname)
	}
	return strings.TrimSpace(os.Getenv("HOSTNAME"))
}

func fetchECSMetadata(ctx context.Context) (ecsTaskMetadata, bool) {
	metadataURI := strings.TrimRight(strings.TrimSpace(os.Getenv("ECS_CONTAINER_METADATA_URI_V4")), "/")
	if metadataURI == "" {
		metadataURI = strings.TrimRight(strings.TrimSpace(os.Getenv("ECS_CONTAINER_METADATA_URI")), "/")
	}
	if metadataURI == "" {
		return ecsTaskMetadata{}, false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURI+"/task", nil)
	if err != nil {
		return ecsTaskMetadata{}, false
	}

	resp, err := instanceMetadataClient.Do(req)
	if err != nil {
		return ecsTaskMetadata{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return ecsTaskMetadata{}, false
	}

	var metadata ecsTaskMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return ecsTaskMetadata{}, false
	}
	return metadata, true
}

func taskIDFromARN(taskARN string) string {
	taskARN = strings.TrimSpace(taskARN)
	if taskARN == "" {
		return ""
	}
	if idx := strings.LastIndex(taskARN, "/"); idx >= 0 && idx < len(taskARN)-1 {
		return taskARN[idx+1:]
	}
	return taskARN
}

func stableDisplayID(instanceID string) string {
	instanceID = strings.TrimSpace(instanceID)
	if instanceID == "" {
		return "unknown"
	}
	if len(instanceID) <= 12 {
		return instanceID
	}

	sum := sha256.Sum256([]byte(instanceID))
	return hex.EncodeToString(sum[:])[:12]
}
