package gauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/form"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pquerna/otp/totp"
)

func (ga *GAuth) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fc := ga.formConfig()
		fc.Fields = append(fc.Fields, ga.fieldByID(ga.IdentityFieldID))
		// todo magic login link
		if ga.PasswordFieldID != "" {
			fc.Fields = append(fc.Fields, ga.fieldByID(ga.PasswordFieldID))
		}
		if err := form.Render(w, "login", fc); err != nil {
			ga.internalError(w, err)
		}
		return
	}
	if r.Method != http.MethodPost {
		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.badError(w, err)
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
		if _, ok := err.(cache.RateLimitError); ok {
			ga.validationError(w, ga.IdentityFieldID, "try again later")
			return
		}
		ga.internalError(w, err)
		return
	}
	uid, err := ga.AccountProvider.IdentityUID(ctx, identity)
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
	account, err := ga.AccountProvider.IdentityLoad(ctx, uid)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	if !validPassword(account[ga.PasswordFieldID], passwd) {
		ga.validationError(w, ga.PasswordFieldID, "invalid")
		return
	}

	if totpSecret, ok := account[FieldTOTPSecretID]; ok && len(totpSecret) > 0 {
		_, ok := req[FieldCodeID]
		if !ok {
			ga.validationError(w, FieldCodeID, "required")
			return
		}
		if !totp.Validate(req[FieldCodeID], totpSecret) {
			ga.validationError(w, FieldCodeID, "invalid")
			return
		}
	}

	expire := time.Hour * 24
	if _, ok := req[FieldRememberID]; ok {
		expire = time.Hour * 24 * 7
	}
	expiry := time.Now().Add(expire)
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["exp"] = expiry.Unix()
	claims["sub"] = uid
	tok, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		ga.internalError(w, fmt.Errorf("loginHandler: SignedString error %v", err))
		return
	}
	// todo maybe make this a gauth config
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookieName,
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
	var req struct {
		Token string `json:"token"`
	}
	if r.Method == http.MethodPost {
		if err := ga.bind(r, &req); err != nil {
			ga.internalError(w, err)
			return
		}
	} else if r.Method == http.MethodGet {
		c, err := r.Cookie(RefreshCookieName)
		if err != nil {
			ga.internalError(w, err)
			return
		}
		req.Token = c.Value
	} else {
		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}
	if req.Token == "" {
		ga.writeJSON(http.StatusUnauthorized, w, nil)
		return
	}

	claims, err := ga.tokenClaims(req.Token)
	if err != nil {
		ga.log("tokenClaims error", err)
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
		return
	}

	expire := time.Hour * 2
	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["sub"] = claims["sub"]
	accessClaims["exp"] = time.Now().Add(expire).Unix()

	if cp, ok := ga.AccountProvider.(ClaimsProvider); ok {
		grants, err := cp.AccessTokenClaims(r.Context(), "")
		if err != nil {
			ga.internalError(w, err)
			return
		}
		accessClaims["grants"], err = structToMap(grants)
		if err != nil {
			ga.internalError(w, err)
			return
		}
	}

	tok, err := accessToken.SignedString(ga.JwtKey)
	if err != nil {
		ga.internalError(w, fmt.Errorf("refreshHandler: SignedString error %v", err))
		return
	}
	ga.writeJSON(http.StatusOK, w, map[string]string{
		"access_token": tok,
	})
}
