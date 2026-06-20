package models

import (
	"time"

	"github.com/google/uuid"
)

type APIKeyAccess string

const (
	APIKeyAccessReadOnly  APIKeyAccess = "read_only"
	APIKeyAccessReadWrite APIKeyAccess = "read_write"
)

type APIKey struct {
	ID         uuid.UUID    `gorm:"default:(-)"                                             json:"id"`
	UserID     uuid.UUID    `gorm:"not null;index;uniqueIndex:idx_api_keys_user_name_active" json:"user_id"`
	User       User         `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"            json:"-"`
	Name       string       `gorm:"not null;uniqueIndex:idx_api_keys_user_name_active"       json:"name"`
	Access     APIKeyAccess `gorm:"not null;default:read_only"                                json:"access"`
	ExpiresAt  *time.Time   `gorm:"default:null"                                               json:"expires_at,omitempty"`
	RevokedAt  *time.Time   `gorm:"default:null"                                               json:"revoked_at,omitempty"`
	LastUsedAt *time.Time   `gorm:"default:null"                                               json:"last_used_at,omitempty"`
	CreatedAt  time.Time    `                                                                  json:"created_at"`
	UpdatedAt  time.Time    `                                                                  json:"updated_at"`
}

type APIKeyCreateBody struct {
	Name      string       `json:"name" validate:"required,max=100"`
	Access    APIKeyAccess `json:"access" validate:"required,oneof=read_only read_write"`
	ExpiresAt *time.Time   `json:"expires_at" validate:"omitempty"`
}

type APIKeyCreateResponse struct {
	ID        uuid.UUID    `json:"id"`
	Name      string       `json:"name"`
	Access    APIKeyAccess `json:"access"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	Token     string       `json:"token"`
}
