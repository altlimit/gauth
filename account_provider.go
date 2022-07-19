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
		// IdentityLoad must return a struct that implements Identity interface, provide "gauth" tag
		// to map AccountFields ID to your struct properties. If the account does not exists you must
		// return an zero/default struct Identity that will be populated for a new registration.
		IdentityLoad(ctx context.Context, uid string) (identity Identity, err error)
	}

	Identity interface {
		// IdentitySave is called to safely save an account, fields provided with "gauth" tag will
		// automatically be updated with it's corresponding values based on registration/login/account
		// forms. Return the unique identifier of this account once saved.
		IdentitySave(ctx context.Context) (uid string, err error)
	}

	// Optionally implement this interface to customize your refresh token with a specific client ID or
	// anything that can be identified that is linked to the UID so you can easily revoke it somewhere.
	RefreshTokenProvider interface {
		CreateRefreshToken(ctx context.Context, uid string) (cid string, err error)
		// Called on logout
		DeleteRefreshToken(ctx context.Context, uid, cid string) error
	}

	AccessTokenProvider interface {
		// Optionally implement this to add additional claims under "grants"
		// and add more role and access information for your token, this token is what's checked against
		// your middleware.
		CreateAccessToken(ctx context.Context, uid string, cid string) (interface{}, error)
	}
)

var (
	ErrAccountNotFound = errors.New("account not found")

	// Return this error in IdentityLoad to provide Re-Send Activation link flow
	ErrAccountNotActive = errors.New("account not active")
)
