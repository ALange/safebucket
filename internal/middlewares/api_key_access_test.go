package middlewares

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/safebucket/safebucket/internal/configuration"
	"github.com/safebucket/safebucket/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAPIKeyAccess(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	tests := []struct {
		name     string
		method   string
		audience string
		scope    string
		status   int
	}{
		{
			name:     "access token bypasses API key restrictions",
			method:   http.MethodPost,
			audience: configuration.AudienceAccessToken,
			status:   http.StatusNoContent,
		},
		{
			name:     "read-only key can read",
			method:   http.MethodGet,
			audience: configuration.AudienceAPIKey,
			scope:    string(models.APIKeyAccessReadOnly),
			status:   http.StatusNoContent,
		},
		{
			name:     "read-only key cannot write",
			method:   http.MethodPost,
			audience: configuration.AudienceAPIKey,
			scope:    string(models.APIKeyAccessReadOnly),
			status:   http.StatusForbidden,
		},
		{
			name:     "read-write key can write",
			method:   http.MethodDelete,
			audience: configuration.AudienceAPIKey,
			scope:    string(models.APIKeyAccessReadWrite),
			status:   http.StatusNoContent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/v1/buckets", nil)
			req = req.WithContext(context.WithValue(req.Context(), models.UserClaimKey{}, models.UserClaims{
				UserID:      uuid.New(),
				Email:       "user@example.com",
				APIKeyScope: tt.scope,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{tt.audience},
				},
			}))

			recorder := httptest.NewRecorder()
			APIKeyAccess(next).ServeHTTP(recorder, req)
			assert.Equal(t, tt.status, recorder.Code)
		})
	}
}
