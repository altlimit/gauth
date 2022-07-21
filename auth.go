package gauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type (
	ctxKey string

	Auth struct {
		UID    string          `json:"sub"`
		Grants json.RawMessage `json:"grants"`
	}
)

const (
	// AuthKey used to store value of *Auth in context
	AuthKey ctxKey = "authKey"
	// RequestKey for accessing request inside context
	RequestKey ctxKey = "requestKey"

	// used for default refresh token cid to invalidate by password update
	pwHashKey ctxKey = "pwhash"
)

// Load populates your Grants struct
func (a *Auth) Load(dst interface{}) error {
	if len(a.Grants) == 0 {
		return nil
	}
	return json.Unmarshal(a.Grants, dst)
}

func (ga *GAuth) headerToken(r *http.Request) string {
	auth := strings.Split(r.Header.Get("Authorization"), " ")
	if len(auth) == 2 && strings.ToLower(auth[0]) == "bearer" {
		return auth[1]
	}
	return ""
}

func (ga *GAuth) Authorized(r *http.Request) (*Auth, error) {
	t := ga.headerToken(r)
	if t == "" {
		return nil, errors.New("no token")
	}
	claims, err := ga.tokenClaims(t, "")
	if err != nil {
		return nil, fmt.Errorf("tokenAuth: %v", err)
	}
	auth := &Auth{
		UID: claims["sub"].(string),
	}
	if grants, ok := claims["grants"]; ok {
		if g, ok := grants.(string); ok && g == "access" {
			return auth, nil
		}
		auth.Grants, err = json.Marshal(grants)
		if err != nil {
			return nil, fmt.Errorf("tokenAuth: marshal error %v", err)
		}
		return auth, nil
	}
	return nil, errors.New("invalid access token")
}

func (ga *GAuth) AuthMiddleware(next http.Handler) http.Handler {
	errorUnauthorized := func(w http.ResponseWriter, r *http.Request) {
		msg := http.StatusText(http.StatusUnauthorized)
		if ga.isJson(r) {
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: msg})
		} else {
			http.Error(w, msg, http.StatusUnauthorized)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := ga.Authorized(r)
		if err != nil {
			ga.log("AuthError: ", err)
			errorUnauthorized(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), AuthKey, auth)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}
