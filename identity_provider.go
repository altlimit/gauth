package gauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

type (
	Claims jwt.MapClaims
	// IdentityProvider must be implemented to login, register, update your user/account.
	IdentityProvider interface {
		// IdentityUID should return a unique identifier from your Identifier field(email/username)
		// this will be use as the subject in your refresh and access token, you should return
		// ErrIdentityNotFound if it doesn't exists or ErrIdentityNotActive if they are not allowed to login while inactive.
		IdentityUID(ctx context.Context, id string) (uid string, err error)
		// IdentityLoad must return a struct that implements Identity interface, provide "gauth" tag
		// to map gauth.Fields ID to your struct properties. If the account does not exists you must
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
	ErrIdentityNotFound = errors.New("identity not found")
	// Return this error in IdentityLoad to provide Re-Send Activation link flow
	ErrIdentityNotActive = errors.New("identity not active")
	// Return in Token Providers to return 401 instead of 500
	ErrTokenDenied = errors.New("token denied")
)

type (
	DefaultRefreshTokenProvider struct {
		ga *GAuth
	}
	DefaultAccessTokenProvider struct {
		ga *GAuth
	}
)

// Default behaviour of refresh token is using cid -> IP + UserAgent + PWHash
func (dr *DefaultRefreshTokenProvider) CreateRefreshToken(ctx context.Context, uid string) (cid string, err error) {
	if req, ok := ctx.Value(RequestKey).(*http.Request); ok {
		pw := toString(ctx.Value(pwHashKey))
		cid := clientFromRequest(req, pw, "")
		return cid, nil
	}
	return "", errors.New("RequestKey not found")
}

// Default behaviour of logout is in memory black list of cid that only keeps the last 500
func (dr *DefaultRefreshTokenProvider) DeleteRefreshToken(ctx context.Context, uid, cid string) error {
	dr.ga.lru.Put("x:"+uid+cid, true)
	return nil
}

// Default behaviour of access token is check cid against client and current pw hash and "access" grants
func (da *DefaultAccessTokenProvider) CreateAccessToken(ctx context.Context, uid string, cid string) (interface{}, error) {
	if req, ok := ctx.Value(RequestKey).(*http.Request); ok {
		_, ok := da.ga.lru.Get("x:" + uid + cid)
		if !ok {
			var pw string
			if da.ga.PasswordFieldID != "" {
				identity, err := da.ga.IdentityProvider.IdentityLoad(ctx, uid)
				if err != nil {
					return nil, err
				}
				data := da.ga.loadIdentity(identity)
				pw = toString(data[da.ga.PasswordFieldID])
			}
			reqCID := clientFromRequest(req, pw, cid[strings.Index(cid, "$"):])
			if cid == reqCID {
				return "access", nil
			}
		}
		return nil, ErrTokenDenied
	}
	return nil, errors.New("RequestKey not found")
}
