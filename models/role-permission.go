package models

import "time"

type RolePermission struct {
	RoleID       string    `json:"roleId"`
	PermissionID string    `json:"permissionId"`
	CreatedAt    time.Time `json:"createdAt"`
}
