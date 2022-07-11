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
		// IdentityUID should return a unique identifier from your Identifier field(email/username)
		// this will be use as the subject in your refresh and access token, you should return
		// ErrAccountNotFound if it doesn't exists or ErrAccountNotActive if they are not allowed to login while inactive.
		IdentityUID(ctx context.Context, id string) (uid string, err error)
		// IdentityLoad must return map of fields that has InSettings enabled or
		// IdentityFieldID, EmailFieldID and PasswordFieldID if present
		IdentityLoad(ctx context.Context, uid string) (data map[string]string, err error)
		// IdentitySave for saving the actual registered user, you'll get the data from your AccountFields here
		// if password is present you'll get an already hashed password ready to save to DB directly, uid will
		// be "" if it's a new user. Return the created or the same uid if it's an update.
		IdentitySave(ctx context.Context, uid string, data map[string]string) (nuid string, err error)
	}

	ClaimsProvider interface {
		// Implement this to add additional claims for your access token, by default
		// "sub" will use your UID so this will just be extra claims under "grants"
		AccessTokenClaims(ctx context.Context, uid string) (interface{}, error)
	}
)

var (
	ErrAccountNotFound = errors.New("account not found")

	// Return this error in IdentityLoad to provide Re-Send Activation link flow
	ErrAccountNotActive = errors.New("account not active")
)
