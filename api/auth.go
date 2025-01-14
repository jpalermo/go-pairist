package api

import (
	"context"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	identitytoolkit "google.golang.org/api/identitytoolkit/v3"
	"google.golang.org/api/option"
)

type Auth struct {
	APIKey   string
	Email    string
	Password string

	idToken      string
	refreshAfter time.Time
}

func (a *Auth) IDToken() (string, error) {
	if a.idToken == "" || a.refreshAfter.Before(time.Now()) {
		ctx := context.Background()

		client, err := identitytoolkit.NewService(ctx, option.WithAPIKey(a.APIKey))
		if err != nil {
			return "", err
		}

		resp, err := client.Relyingparty.VerifyPassword(&identitytoolkit.IdentitytoolkitRelyingpartyVerifyPasswordRequest{
			Email:             a.Email,
			Password:          a.Password,
			ReturnSecureToken: true,
		}).Context(ctx).Do()
		if err != nil {
			return "", err
		}

		a.idToken = resp.IdToken

		var claims jwt.RegisteredClaims
		parser := &jwt.Parser{}

		_, _, err = parser.ParseUnverified(a.idToken, &claims)
		if err != nil {
			return "", errors.Wrap(err, "parsing auth token")
		}

		a.refreshAfter = claims.ExpiresAt.Add(-5 * time.Minute)
	}

	return a.idToken, nil
}
