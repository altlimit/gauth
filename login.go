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
	withPW := ga.PasswordFieldID != ""
	if r.Method == http.MethodGet {
		fc := ga.formConfig()
		action := r.URL.Query().Get("a")
		if withPW {
			fc.Links = append(fc.Links, &form.Link{
				URL:   ga.Path.Base + ga.Path.Register,
				Label: "Register",
			})
		}

		fc.Fields = append(fc.Fields, ga.fieldByID(ga.IdentityFieldID))
		switch action {
		case "resetlink":
			fc.Title = "Forgot Password"
			fc.Submit = "Send Reset Link"
			fc.Links = append(fc.Links, &form.Link{
				URL:   ga.Path.Base + ga.Path.Login,
				Label: "Login",
			})
		case "reset":
			fc.Fields = ga.resetFields()
			fc.Title = "Reset Password"
			fc.Submit = "Update"
			fc.Links = append(fc.Links, &form.Link{
				URL:   ga.Path.Base + ga.Path.Login,
				Label: "Login",
			})
		default:
			if !withPW {
				fc.Title = "Login or Register"
				fc.Submit = "Send Link"
			} else {
				fc.Title = "Login"
				fc.Submit = "Login"
			}

			if withPW {
				fc.Fields = append(fc.Fields, ga.fieldByID(ga.PasswordFieldID))
				fc.Fields = append(fc.Fields, &form.Field{ID: FieldCodeID, Type: "text", Label: "Enter Code"})
				if ga.emailSender != nil && ga.EmailFieldID != "" {
					fc.Links = append(fc.Links, &form.Link{
						URL:   "?a=resetlink",
						Label: "Forgot Password",
					})
				}
				fc.Fields = append(fc.Fields, &form.Field{ID: FieldRememberID, Type: "checkbox", Label: "Remember"})
			}
		}
		if err := form.Render(w, fc); err != nil {
			ga.internalError(w, err)
		}
		return
	}
	if r.Method != http.MethodPost {
		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}
	var req map[string]interface{}
	if err := ga.bind(r, &req); err != nil {
		ga.badError(w, err)
		return
	}
	ctx := r.Context()
	var (
		identity string
		passwd   string
		isToken  bool
	)
	if token, ok := req["token"].(string); ok && !withPW && token != "" {
		identity = token
		isToken = true
	} else {
		identity, _ = req[ga.IdentityFieldID].(string)
	}

	var valErrs []string
	if identity == "" {
		valErrs = append(valErrs, ga.IdentityFieldID, "required")
	}
	if withPW {
		passwd, _ = req[ga.PasswordFieldID].(string)
		if passwd == "" {
			valErrs = append(valErrs, ga.PasswordFieldID, "required")
		}
	}
	if len(valErrs) > 0 {
		ga.validationError(w, valErrs...)
		return
	}

	if err := ga.rateLimiter.RateLimit(ctx, "login:"+strings.ToLower(identity), ga.RateLimit.Login.Rate, ga.RateLimit.Login.Duration); err != nil {
		if _, ok := err.(cache.RateLimitError); ok {
			ga.validationError(w, ga.IdentityFieldID, "try again later")
			return
		}
		ga.internalError(w, err)
		return
	}

	if isToken {
		claims, err := ga.tokenStringClaims(identity, "")
		if err != nil || claims["act"] != actionLogin {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
			return
		}
		identity = claims["uid"]
	} else if !withPW {
		_, err := ga.sendMail(ctx, actionLogin, identity, req)
		if err != nil {
			ga.internalError(w, err)
			return
		}
		ga.writeJSON(http.StatusCreated, w, nil)
		return
	}

	uid, err := ga.AccountProvider.IdentityUID(ctx, identity)
	if err == ErrAccountNotFound && !withPW {
		// skip, no user yet
	} else if err != nil {
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
		if err != ErrAccountNotFound || withPW {
			ga.internalError(w, err)
			return
		}
	}
	data := ga.loadIdentity(account)

	if withPW {
		if !validPassword(data[ga.PasswordFieldID].(string), passwd) {
			ga.validationError(w, ga.PasswordFieldID, "invalid")
			return
		}

		if totpSecret, ok := data[FieldTOTPSecretID].(string); ok && len(totpSecret) > 0 {
			code, ok := req[FieldCodeID].(string)
			if !ok {
				ga.validationError(w, FieldCodeID, "required")
				return
			}
			usedRecovery := false
			if len(code) == 10 {
				recovery, ok := data[FieldRecoveryCodesID].(string)
				if ok && len(recovery) > 0 {
					var unused []string
					for _, val := range strings.Split(recovery, "|") {
						if !usedRecovery && validPassword(val, code) {
							usedRecovery = true
							continue
						}
						unused = append(unused, val)
					}
					if usedRecovery {
						_, err = ga.saveIdentity(ctx, account, map[string]interface{}{
							FieldRecoveryCodesID: strings.Join(unused, "|"),
						})
						if err != nil {
							ga.internalError(w, err)
							return
						}
					}
				}
			}
			if !usedRecovery && !totp.Validate(code, totpSecret) {
				ga.validationError(w, FieldCodeID, "invalid")
				return
			}
		}
	} else if uid == "" {
		// new user with passwordless system
		uid, err = ga.saveIdentity(ctx, account, map[string]interface{}{ga.EmailFieldID: identity})
		if err != nil {
			ga.internalError(w, err)
			return
		}
	}

	expire := time.Hour * 24
	if v, ok := req[FieldRememberID].(bool); ok && v {
		expire = time.Hour * 24 * 7
	}
	expiry := time.Now().Add(expire)
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["exp"] = expiry.Unix()
	claims["sub"] = uid

	// a refresh token always have "cid" which either identifies a user
	// generated client id or just "refresh" if it's not implemented
	if cp, ok := ga.AccountProvider.(RefreshTokenProvider); ok {
		cid, err := cp.CreateRefreshToken(ctx, uid)
		if err != nil {
			ga.internalError(w, err)
			return
		}
		claims["cid"] = cid
	} else {
		claims["cid"] = "refresh"
	}
	tok, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		ga.internalError(w, fmt.Errorf("loginHandler: SignedString error %v", err))
		return
	}
	if ga.RefreshTokenCookieName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     ga.RefreshTokenCookieName,
			Value:    tok,
			Expires:  expiry,
			HttpOnly: true,
			Secure:   true,
			MaxAge:   int(expire.Seconds()),
			SameSite: http.SameSiteStrictMode,
			Path:     ga.Path.Base + ga.Path.Refresh,
		})
	}
	ga.writeJSON(http.StatusOK, w, map[string]string{"refresh_token": tok})
}

func (ga *GAuth) refreshHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if r.Method == http.MethodPost {
		if err := ga.bind(r, &req); err != nil {
			ga.badError(w, err)
			return
		}
	} else if (r.Method == http.MethodGet || r.Method == http.MethodDelete) && ga.RefreshTokenCookieName != "" {
		c, err := r.Cookie(ga.RefreshTokenCookieName)
		if err != nil {
			if err == http.ErrNoCookie {
				ga.writeJSON(http.StatusUnauthorized, w, nil)
				return
			}
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

	claims, err := ga.tokenStringClaims(req.Token, "")
	if err != nil {
		ga.log("tokenStringClaims error", err)
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
		return
	}
	cid, ok := claims["cid"]
	if !ok {
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
		return
	}

	if r.Method == http.MethodDelete || r.URL.Query().Get("logout") == "1" {
		if cp, ok := ga.AccountProvider.(RefreshTokenProvider); ok {
			err := cp.DeleteRefreshToken(r.Context(), claims["sub"], cid)
			if err != nil {
				ga.internalError(w, err)
				return
			}
		}

		if ga.RefreshTokenCookieName != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     ga.RefreshTokenCookieName,
				Value:    "",
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   true,
				MaxAge:   -1,
				SameSite: http.SameSiteStrictMode,
				Path:     ga.Path.Base + ga.Path.Refresh,
			})
		}
		return
	}

	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["sub"] = claims["sub"]
	accessClaims["exp"] = time.Now().Add(time.Hour).Unix()
	if cp, ok := ga.AccountProvider.(AccessTokenProvider); ok {
		grants, err := cp.CreateAccessToken(r.Context(), claims["sub"], cid)
		if err != nil {
			ga.internalError(w, err)
			return
		}
		accessClaims["grants"], err = structToMap(grants)
		if err != nil {
			ga.internalError(w, err)
			return
		}
	} else {
		accessClaims["grants"] = "access"
	}

	tok, err := accessToken.SignedString(ga.JwtKey)
	if err != nil {
		ga.internalError(w, fmt.Errorf("refreshHandler: SignedString error %v", err))
		return
	}
	resp := map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   time.Hour.Seconds(),
	}
	if scope, ok := accessClaims["grants"]; ok {
		resp["scope"] = scope
	}
	ga.writeJSON(http.StatusOK, w, resp)
}
