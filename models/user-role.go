package models

import "time"

type UserRole struct {
	UserID    string    `json:"userId"`
	RoleID    string    `json:"roleId"`
	CreatedAt time.Time `json:"createdAt"`
}
