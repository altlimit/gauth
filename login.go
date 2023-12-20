package gauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

	uid, err := ga.IdentityProvider.IdentityUID(ctx, identity)
	if err == ErrIdentityNotFound && !withPW {
		// skip, no user yet
	} else if err != nil {
		if err == ErrIdentityNotActive {
			ga.validationError(w, ga.IdentityFieldID, "inactive")
			return
		}
		if err == ErrIdentityNotFound {
			ga.validationError(w, ga.PasswordFieldID, "invalid")
			return
		}
		if ve, ok := err.(ValidationError); ok {
			ga.validationError(w, ve.Field, ve.Message)
			return
		}
		ga.internalError(w, err)
		return
	}

	id, err := ga.IdentityProvider.IdentityLoad(ctx, uid)
	if err != nil {
		if err != ErrIdentityNotFound || withPW {
			ga.internalError(w, err)
			return
		}
	}
	data := ga.loadIdentity(id)

	if withPW {
		if !validPassword(toString(data[ga.PasswordFieldID]), passwd) {
			ga.validationError(w, ga.PasswordFieldID, "invalid")
			return
		}

		if totpSecret := toString(data[FieldTOTPSecretID]); len(totpSecret) > 0 {
			code, ok := req[FieldCodeID].(string)
			if !ok {
				ga.validationError(w, FieldCodeID, "required")
				return
			}
			usedRecovery := false
			if len(code) == 10 {
				recovery := toString(data[FieldRecoveryCodesID])
				if len(recovery) > 0 {
					var unused []string
					for _, val := range strings.Split(recovery, "|") {
						if !usedRecovery && validPassword(val, code) {
							usedRecovery = true
							continue
						}
						unused = append(unused, val)
					}
					if usedRecovery {
						_, err = ga.saveIdentity(ctx, id, map[string]interface{}{
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
		uid, err = ga.saveIdentity(ctx, id, map[string]interface{}{ga.EmailFieldID: identity})
		if err != nil {
			ga.internalError(w, err)
			return
		}
	}

	expire := ga.Timeout.RefreshToken
	if v, ok := req[FieldRememberID].(bool); ok && v {
		expire = ga.Timeout.RefreshTokenRemember
	}
	expiry := time.Now().Add(expire)
	ctx = context.WithValue(ctx, RequestKey, r)
	if withPW {
		ctx = context.WithValue(ctx, pwHashKey, data[ga.PasswordFieldID])
	}
	cid, err := ga.refreshTokenProvider.CreateRefreshToken(ctx, uid)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	tok, err := ga.CreateRefreshToken(ctx, uid, cid, expiry)
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
			Secure:   !ga.debug,
			MaxAge:   int(expire.Seconds()),
			SameSite: http.SameSiteStrictMode,
			Path:     ga.Path.Base + ga.Path.Refresh,
		})
	}
	ga.writeJSON(http.StatusOK, w, map[string]string{"refresh_token": tok})
}

// CreateRefreshToken you can use this to create custom tokens such as for API keys or anything that has a longer expiration
// than provided configration.
func (ga *GAuth) CreateRefreshToken(ctx context.Context, uid, cid string, expiry time.Time) (string, error) {
	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["exp"] = expiry.Unix()
	claims["sub"] = uid
	claims["cid"] = cid
	token, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		return "", fmt.Errorf("CreateRefreshToken: SignedString error %v", err)
	}
	return token, nil
}

// CreateAccessToken returns an access token
func (ga *GAuth) CreateAccessToken(ctx context.Context, sub string, grants interface{}, expiry time.Time) (string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS256)
	accessClaims := accessToken.Claims.(jwt.MapClaims)
	accessClaims["sub"] = sub
	accessClaims["exp"] = expiry.Unix()
	accessClaims["grants"] = grants
	token, err := accessToken.SignedString(ga.JwtKey)
	if err != nil {
		return "", fmt.Errorf("CreateAccessToken: SignedString error %v", err)
	}
	return token, nil
}

func (ga *GAuth) refreshHandler(w http.ResponseWriter, r *http.Request) {
	var (
		req struct {
			Token string `json:"token"`
		}

		result interface{}
	)
	status := http.StatusOK
	ref := r.URL.Query().Get("ref")
	defer func() {
		err, ok := result.(error)
		if ok || status >= 400 {
			errMsg := http.StatusText(status)
			if ok {
				ga.log(errMsg, err)
			}
			if ref == "" {
				if ga.isJson(r) {
					ga.writeJSON(status, w, errorResponse{Error: errMsg})
				} else {
					http.Error(w, errMsg, status)
				}
			} else {
				http.Redirect(w, r, ga.Path.Base+ga.Path.Login+"?r="+url.QueryEscape(ref), http.StatusTemporaryRedirect)
			}
			return
		}
		if ref != "" {
			http.Redirect(w, r, ref, http.StatusTemporaryRedirect)
			return
		}
		if status == http.StatusTemporaryRedirect {
			http.Redirect(w, r, result.(string), http.StatusTemporaryRedirect)
			return
		}
		ga.writeJSON(status, w, result)
	}()

	if r.Method == http.MethodPost {
		if err := ga.bind(r, &req); err != nil {
			status = http.StatusBadRequest
			result = err
			return
		}
	} else if (r.Method == http.MethodGet || r.Method == http.MethodDelete) && ga.RefreshTokenCookieName != "" {
		c, err := r.Cookie(ga.RefreshTokenCookieName)
		if err != nil {
			if err == http.ErrNoCookie {
				status = http.StatusUnauthorized
				return
			}
			status = http.StatusInternalServerError
			result = err
			return
		}
		req.Token = c.Value
	} else {
		status = http.StatusMethodNotAllowed
		return
	}
	if req.Token == "" {
		status = http.StatusUnauthorized
		return
	}

	claims, err := ga.tokenStringClaims(req.Token, "")
	if err != nil {
		result = err
		status = http.StatusUnauthorized
		return
	}
	cid, ok := claims["cid"]
	if !ok {
		status = http.StatusUnauthorized
		return
	}

	ctx := r.Context()
	isLogout := r.URL.Query().Get("logout") == "1"
	if r.Method == http.MethodDelete || isLogout {
		err := ga.refreshTokenProvider.DeleteRefreshToken(ctx, claims["sub"], cid)
		if err != nil {
			status = http.StatusInternalServerError
			result = err
			return
		}

		if ga.RefreshTokenCookieName != "" {
			http.SetCookie(w, &http.Cookie{
				Name:     ga.RefreshTokenCookieName,
				Value:    "",
				Expires:  time.Unix(0, 0),
				HttpOnly: true,
				Secure:   !ga.debug,
				MaxAge:   -1,
				SameSite: http.SameSiteStrictMode,
				Path:     ga.Path.Base + ga.Path.Refresh,
			})
		}
		if ga.AccessTokenCookieName != "" {
			http.SetCookie(w, &http.Cookie{Name: ga.AccessTokenCookieName, Value: "", Expires: time.Unix(0, 0),
				HttpOnly: true, Secure: true, MaxAge: -1, SameSite: http.SameSiteStrictMode, Path: "/"})
		}
		if isLogout {
			url := ga.Path.Base + ga.Path.Login
			if ref := r.Header.Get("Referer"); ref != "" {
				url = ref
			}
			status = http.StatusTemporaryRedirect
			result = url
		}
		return
	}

	ctx = context.WithValue(ctx, RequestKey, r)
	grants, err := ga.accessTokenProvider.CreateAccessToken(ctx, claims["sub"], cid)
	if err != nil {
		if err == ErrTokenDenied {
			status = http.StatusUnauthorized
			return
		}
		status = http.StatusInternalServerError
		result = err
		return
	}
	tok, err := ga.CreateAccessToken(ctx, claims["sub"], grants, time.Now().Add(ga.Timeout.AccessToken))
	if err != nil {
		status = http.StatusInternalServerError
		result = err
		return
	}

	expire := ga.Timeout.AccessToken
	if ga.AccessTokenCookieName != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     ga.AccessTokenCookieName,
			Value:    tok,
			Expires:  time.Now().Add(expire),
			HttpOnly: true,
			Secure:   !ga.debug,
			MaxAge:   int(expire.Seconds()),
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
		})
	}

	result = map[string]interface{}{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_in":   expire.Seconds(),
		"scope":        grants,
	}
	status = http.StatusOK
}
