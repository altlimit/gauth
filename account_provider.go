package gauth

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt/v4"
)

type (
	Claims jwt.MapClaims
	// AccountProvider must be implemented to login, register, update your user
	AccountProvider interface {
		// IdentityLoad must return map of fields that has InSettings enabled or
		// IdentityFieldID, EmailFieldID and PasswordFieldID if present, return ErrAccountNotFound id doesn't exists
		IdentityLoad(ctx context.Context, id string) (data map[string]string, err error)
		// IdentitySave for saving the actual registered user, you'll get the data from your AccountFields here
		// if password is present you'll get an already hashed password ready to save to DB directly
		IdentitySave(ctx context.Context, data map[string]string) error
	}

	TokenProvider interface {
		// You must return sub such as ID of the account, username or any db identifier if not implemented it uses IdentifierFieldID's value
		IdentityRefreshToken(ctx context.Context, id string) (sub string, err error)
		// Return claims here, by default this uses sub also from refresh token, you can use this for other things such as different access
		IdentityAccessToken(ctx context.Context, sub string) (claims Claims, err error)
	}

	DefaultTokenProvider struct{}
)

var (
	ErrAccountNotFound = errors.New("account not found")

	// Return this error in IdentityLogin to provide Re-Send Activation link flow
	ErrAccountNotActive = errors.New("account not active")
)

func (dtp *DefaultTokenProvider) IdentityRefreshToken(ctx context.Context, id string) (sub string, err error) {
	sub = id
	return
}

func (dtp *DefaultTokenProvider) IdentityAccessToken(ctx context.Context, sub string) (claims Claims, err error) {
	claims = make(Claims)
	claims["sub"] = sub
	return
}
