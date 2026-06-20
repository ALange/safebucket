package services

import (
	"errors"
	"net/http"
	"time"

	apierrors "github.com/safebucket/safebucket/internal/errors"
	"github.com/safebucket/safebucket/internal/handlers"
	h "github.com/safebucket/safebucket/internal/helpers"
	m "github.com/safebucket/safebucket/internal/middlewares"
	"github.com/safebucket/safebucket/internal/models"
	"github.com/safebucket/safebucket/internal/sql"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type APIKeyService struct {
	DB         *gorm.DB
	AuthConfig models.AuthConfig
}

func (s APIKeyService) Routes() chi.Router {
	r := chi.NewRouter()

	r.With(m.AuthorizeSelfOrAdmin(0)).
		Get("/", handlers.GetListHandler(s.ListAPIKeys))

	r.With(m.AuthorizeSelfOrAdmin(0)).
		With(m.Validate[models.APIKeyCreateBody]).
		Post("/", handlers.CreateHandler(s.CreateAPIKey))

	r.Route("/{id1}", func(r chi.Router) {
		r.With(m.AuthorizeSelfOrAdmin(0)).
			Delete("/", handlers.DeleteHandler(s.RevokeAPIKey))
	})

	return r
}

func (s APIKeyService) ListAPIKeys(
	logger *zap.Logger,
	_ models.UserClaims,
	ids uuid.UUIDs,
) []models.APIKey {
	userID := ids[0]
	var keys []models.APIKey
	if err := s.DB.Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("created_at DESC").
		Find(&keys).Error; err != nil {
		logger.Error("Failed to list API keys", zap.Error(err), zap.String("user_id", userID.String()))
		return []models.APIKey{}
	}
	return keys
}

func (s APIKeyService) CreateAPIKey(
	_ *zap.Logger,
	_ models.UserClaims,
	ids uuid.UUIDs,
	body models.APIKeyCreateBody,
) (models.APIKeyCreateResponse, error) {
	userID := ids[0]

	user, err := sql.GetUserByID(s.DB, userID)
	if err != nil {
		return models.APIKeyCreateResponse{}, err
	}

	if body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return models.APIKeyCreateResponse{}, apierrors.New(http.StatusBadRequest, apierrors.CodeInvalidAPIKeyExpiry)
	}

	apiKey := models.APIKey{
		UserID:    userID,
		Name:      body.Name,
		Access:    body.Access,
		ExpiresAt: body.ExpiresAt,
	}

	if err := s.DB.Create(&apiKey).Error; err != nil {
		return models.APIKeyCreateResponse{}, apierrors.New(http.StatusConflict, apierrors.CodeInvalidRequest)
	}

	token, err := h.NewAPIKeyToken(s.AuthConfig.TokenSecret, &user, apiKey.ID, apiKey.Access, apiKey.ExpiresAt)
	if err != nil {
		return models.APIKeyCreateResponse{}, apierrors.New(http.StatusInternalServerError, apierrors.CodeTokenGenerationFailed)
	}

	return models.APIKeyCreateResponse{
		ID:        apiKey.ID,
		Name:      apiKey.Name,
		Access:    apiKey.Access,
		ExpiresAt: apiKey.ExpiresAt,
		CreatedAt: apiKey.CreatedAt,
		Token:     token,
	}, nil
}

func (s APIKeyService) RevokeAPIKey(
	_ *zap.Logger,
	_ models.UserClaims,
	ids uuid.UUIDs,
) error {
	userID, apiKeyID := ids[0], ids[1]

	apiKey, err := sql.GetAPIKeyByID(s.DB, apiKeyID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return apierrors.New(http.StatusNotFound, apierrors.CodeNotFound)
		}
		return apierrors.New(http.StatusInternalServerError, apierrors.CodeInternalServerError)
	}

	if apiKey.UserID != userID {
		return apierrors.New(http.StatusNotFound, apierrors.CodeNotFound)
	}

	now := time.Now()
	if err := s.DB.Model(&apiKey).Update("revoked_at", &now).Error; err != nil {
		return apierrors.New(http.StatusInternalServerError, apierrors.CodeUpdateFailed)
	}
	return nil
}
