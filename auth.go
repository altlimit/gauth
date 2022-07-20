package gauth

import (
	"context"
	"encoding/json"
	"net/http"
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
