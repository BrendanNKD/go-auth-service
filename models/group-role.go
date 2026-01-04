package models

import "time"

type GroupRole struct {
	GroupID   string    `json:"groupId"`
	RoleID    string    `json:"roleId"`
	CreatedAt time.Time `json:"createdAt"`
}
