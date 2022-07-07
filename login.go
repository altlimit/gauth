package gauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/form"
	"github.com/golang-jwt/jwt/v4"
)

func (ga *GAuth) loginHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}
	ctx := r.Context()
	identity := req[ga.IdentityFieldID]
	var valErrs []string
	if identity == "" {
		valErrs = append(valErrs, ga.IdentityFieldID, "required")
	}
	passwd := req[ga.PasswordFieldID]
	if passwd == "" {
		valErrs = append(valErrs, ga.PasswordFieldID, "required")
	}
	if len(valErrs) > 0 {
		ga.validationError(w, valErrs...)
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

	account, err := ga.AccountProvider.IdentityLoad(ctx, identity)
	if err != nil {
		if err == ErrAccountNotActive {
			ga.validationError(w, ga.IdentityFieldID, "inactive")
			return
		}
		if err == ErrAccountNotFound {
			ga.validationError(w, ga.PasswordFieldID, "invalid")
			return
		}
		ga.internalError(w, err)
		return
	}
	if !validPassword(account[ga.PasswordFieldID], passwd) {
		ga.validationError(w, ga.PasswordFieldID, "invalid")
		return
	}

	// todo if totpsecret != "" then check against code

	sub, err := ga.TokenProvider.IdentityRefreshToken(ctx, identity)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	expire := time.Hour * 24
	if _, ok := req["remember"]; ok {
		expire = time.Hour * 24 * 7
	}
	expiry := time.Now().Add(expire)
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["sub"] = sub
	claims["exp"] = expiry.Unix()
	tok, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		ga.internalError(w, fmt.Errorf("loginHandler: SignedString error %v", err))
		return
	}
	// todo maybe make this a gauth config
	http.SetCookie(w, &http.Cookie{
		Name:     "rts",
		Value:    tok,
		Expires:  expiry,
		HttpOnly: true,
		Secure:   true,
		MaxAge:   int(expire.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
	ga.writeJSON(http.StatusOK, w, map[string]string{"refresh_token": tok})
}

func (ga *GAuth) refreshHandler(w http.ResponseWriter, r *http.Request) {

}

func (ga *GAuth) renderLoginHandler(w http.ResponseWriter, r *http.Request) {
	fc := &form.Config{
		Brand:       ga.Brand,
		BasePath:    ga.BasePath,
		AlpineJSURL: ga.AlpineJSURL,
	}
	fc.Fields = append(fc.Fields, ga.fieldByID(ga.IdentityFieldID))
	// todo magic login link
	if ga.PasswordFieldID != "" {
		fc.Fields = append(fc.Fields, ga.fieldByID(ga.PasswordFieldID))
	}
	if err := form.Render(w, "login", fc); err != nil {
		ga.internalError(w, err)
	}
}
