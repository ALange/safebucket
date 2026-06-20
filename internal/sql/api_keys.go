package sql

import (
	"github.com/safebucket/safebucket/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func GetAPIKeyByID(db *gorm.DB, id uuid.UUID) (models.APIKey, error) {
	var apiKey models.APIKey
	if err := db.Where("id = ?", id).First(&apiKey).Error; err != nil {
		return models.APIKey{}, err
	}
	return apiKey, nil
}
