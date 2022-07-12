package gauth

import (
	"context"
	"encoding/json"
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
	AuthKey ctxKey = "authKey"
)

// Load populates your Grants struct
func (a *Auth) Load(dst interface{}) error {
	if len(a.Grants) == 0 {
		return nil
	}
	return json.Unmarshal(a.Grants, dst)
}

func (ga *GAuth) AuthMiddleware(next http.Handler) http.Handler {
	errorUnauthorized := func(w http.ResponseWriter, r *http.Request) {
		msg := http.StatusText(http.StatusUnauthorized)
		if strings.HasPrefix(r.Header.Get("Accept"), "application/json") ||
			strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: msg})
		} else {
			http.Error(w, msg, http.StatusUnauthorized)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ga.headerToken(r)
		if token == "" {
			errorUnauthorized(w, r)
			return
		}
		auth, err := ga.Authorized(token)
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
