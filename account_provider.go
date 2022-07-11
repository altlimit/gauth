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
		// return ErrAccountNotActive to re-prompt send mail verification/support account verification
		IdentityLoad(ctx context.Context, id string) (data map[string]string, err error)
		// IdentitySave for saving the actual registered user, you'll get the data from your AccountFields here
		// if password is present you'll get an already hashed password ready to save to DB directly
		IdentitySave(ctx context.Context, data map[string]string) error
	}

	ClaimsProvider interface {
		// Implement this to add additional claims for your access token, by default
		// "sub" will use your IdentityID so this will just be extra claims
		AccessTokenClaims(ctx context.Context, id string) (claims Claims, err error)
	}
)

var (
	ErrAccountNotFound = errors.New("account not found")

	// Return this error in IdentityLoad to provide Re-Send Activation link flow
	ErrAccountNotActive = errors.New("account not active")
)
