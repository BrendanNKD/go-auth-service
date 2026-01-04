package models

import "time"

type UserGroup struct {
	UserID    string    `json:"userId"`
	GroupID   string    `json:"groupId"`
	CreatedAt time.Time `json:"createdAt"`
}
