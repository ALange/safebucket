package middlewares

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	apierrors "github.com/safebucket/safebucket/internal/errors"

	"github.com/safebucket/safebucket/internal/cache"
	"github.com/safebucket/safebucket/internal/configuration"
	"github.com/safebucket/safebucket/internal/helpers"
	"github.com/safebucket/safebucket/internal/models"
	"github.com/safebucket/safebucket/internal/sql"
	"github.com/safebucket/safebucket/internal/tracing"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AuthExcludedKey struct{}

func Authenticate(
	jwtSecret string, c cache.ICache, db *gorm.DB, refreshTokenExpiry int,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx, span := tracing.StartSpan(r.Context(), "middleware.Authenticate")
			defer span.End()
			r = r.WithContext(ctx)

			excluded := isPathExcludedFromAuth(r.URL.Path, r.Method)
			ctx = context.WithValue(r.Context(), AuthExcludedKey{}, excluded)

			if excluded {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			var tokenStr string
			var requireBearer bool

			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				tokenStr = h
				requireBearer = true
			} else if mfaCookie, mfaErr := r.Cookie("safebucket_mfa_token"); mfaErr == nil {
				tokenStr = mfaCookie.Value
				requireBearer = false
			} else if accessCookie, accessErr := r.Cookie("safebucket_access_token"); accessErr == nil {
				tokenStr = accessCookie.Value
				requireBearer = false
			} else {
				tokenStr = h
				requireBearer = true
			}

			userClaims, err := helpers.ParseToken(jwtSecret, tokenStr, requireBearer)
			if err != nil {
				helpers.RespondWithErrorCtx(r.Context(), w, 403, []string{apierrors.CodeForbidden})
				return
			}

			if userClaims.Audience[0] == configuration.AudienceAccessToken {
				if userClaims.SID == "" {
					helpers.RespondWithErrorCtx(r.Context(), w, 401, []string{apierrors.CodeSessionRevoked})
					return
				}

				maxAge := time.Duration(refreshTokenExpiry) * time.Minute
				active, sessionErr := cache.IsSessionActive(
					c, userClaims.UserID.String(), userClaims.SID, maxAge,
				)
				if sessionErr != nil || !active {
					helpers.RespondWithErrorCtx(r.Context(), w, 401, []string{apierrors.CodeSessionRevoked})
					return
				}
			}

			if userClaims.Audience[0] == configuration.AudienceAPIKey {
				if err := validateAPIKeyToken(db, userClaims); err != nil {
					helpers.RespondWithErrorCtx(r.Context(), w, 403, []string{apierrors.CodeForbidden})
					return
				}
			}

			ctx = context.WithValue(ctx, models.UserClaimKey{}, userClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

func validateAPIKeyToken(db *gorm.DB, claims models.UserClaims) error {
	if db == nil || claims.APIKeyID == nil {
		return errors.New("invalid api key")
	}

	apiKey, err := sql.GetAPIKeyByID(db, *claims.APIKeyID)
	if err != nil {
		return err
	}

	if apiKey.UserID != claims.UserID || apiKey.RevokedAt != nil {
		return errors.New("invalid api key")
	}

	if apiKey.ExpiresAt != nil && apiKey.ExpiresAt.Before(time.Now()) {
		return errors.New("expired api key")
	}

	if string(apiKey.Access) != claims.APIKeyScope {
		return errors.New("invalid api key scope")
	}

	now := time.Now()
	if err := db.Model(&apiKey).Update("last_used_at", &now).Error; err != nil {
		zap.L().Warn("failed to update API key last_used_at",
			zap.String("api_key_id", apiKey.ID.String()),
			zap.Error(err),
		)
	}
	return nil
}

func isPathExcludedFromAuth(path, method string) bool {
	if m, ok := configuration.AuthExcludedExactPaths[path]; ok {
		if m == "*" || m == method {
			return true
		}
	}

	for _, rule := range configuration.AuthExcludedPatterns {
		if rule.Pattern.MatchString(path) && (rule.Method == "*" || rule.Method == method) {
			return true
		}
	}

	return false
}
