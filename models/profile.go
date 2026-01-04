package models

import "time"

type Profile struct {
	ID          string    `json:"id"`
	UserID      string    `json:"userId"`
	FirstName   string    `json:"firstName,omitempty"`
	LastName    string    `json:"lastName,omitempty"`
	DisplayName string    `json:"displayName,omitempty"`
	AvatarURL   string    `json:"avatarUrl,omitempty"`
	PhoneNumber string    `json:"phoneNumber,omitempty"`
	Locale      string    `json:"locale,omitempty"`
	Timezone    string    `json:"timezone,omitempty"`
	Bio         string    `json:"bio,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}
