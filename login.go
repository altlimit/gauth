package gauth

import (
	"net/http"
	"strings"
	"time"

	"github.com/altlimit/gauth/cache"
)

func (ga *GAuth) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}
	ctx := r.Context()
	identity := req[ga.IdentityFieldID]
	if identity == "" {
		ga.validationError(w, ga.IdentityFieldID, "required")
		return
	}
	passwd := req[ga.PasswordFieldID]
	if passwd == "" {
		ga.validationError(w, ga.PasswordFieldID, "required")
		return
	}
	loginKey := "login:" + strings.ToLower(identity)
	if err := ga.rateLimiter.RateLimit(ctx, loginKey, 10, time.Hour); err != nil {
		if errRL, ok := err.(cache.RateLimitError); ok {
			ga.validationError(w, ga.IdentityFieldID, errRL.Error())
			return
		}
		ga.internalError(w, err)
		return
	}
	// _, ok := req["remember"]
	// 6 hours without remember me
	// tokenExpire := time.Hour * 6
	// if ok {
	// 30 days with remember me
	// tokenExpire = time.Hour * 24 * 30
	// }

	// todo provider for getting hashedpassword and totpsecret from identity
	// todo check if hashedpassword is valid
	// todo if totpsecret != "" then check against code
	// if valid then generate tokn and send to loggedInProvider
}
