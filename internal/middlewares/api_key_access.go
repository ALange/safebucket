package middlewares

import (
	"net/http"

	"github.com/safebucket/safebucket/internal/configuration"
	apierrors "github.com/safebucket/safebucket/internal/errors"
	"github.com/safebucket/safebucket/internal/helpers"
	"github.com/safebucket/safebucket/internal/models"
)

func APIKeyAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := r.Context().Value(models.UserClaimKey{}).(models.UserClaims)
		if !ok {
			helpers.RespondWithError(w, http.StatusForbidden, []string{apierrors.CodeForbidden})
			return
		}

		if claims.AudienceString() != configuration.AudienceAPIKey {
			next.ServeHTTP(w, r)
			return
		}

		if claims.APIKeyScope == string(models.APIKeyAccessReadOnly) &&
			r.Method != http.MethodGet &&
			r.Method != http.MethodHead &&
			r.Method != http.MethodOptions {
			helpers.RespondWithError(w, http.StatusForbidden, []string{apierrors.CodeForbidden})
			return
		}

		next.ServeHTTP(w, r)
	})
}
