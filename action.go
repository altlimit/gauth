package gauth

import (
	"image/png"
	"net/http"
	"strings"

	"github.com/altlimit/gauth/cache"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (ga *GAuth) actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if qr := r.URL.Query().Get("qr"); qr != "" {
			key, err := otp.NewKeyFromURL(qr)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			img, err := key.Image(200, 200)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			png.Encode(w, img)
			return
		}
		ga.writeJSON(http.StatusNotFound, w, nil)
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
	switch req["action"] {
	case "newRecovery":
		recovery := make([]string, 10)
		for i := 0; i < 10; i++ {
			recovery[i] = randSeq(10)
		}
		ga.writeJSON(http.StatusOK, w, recovery)
		return
	case "newTotpKey":
		auth, err := ga.Authorized(ga.headerToken(r))
		if err != nil {
			ga.log("AuthorizedError: ", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
			return
		}

		ctx := r.Context()
		acct, err := ga.AccountProvider.IdentityLoad(ctx, auth.UID)
		if err != nil {
			ga.internalError(w, err)
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      ga.Brand.AppName,
			AccountName: acct[ga.IdentityFieldID],
		})
		if err != nil {
			ga.internalError(w, err)
			return
		}
		ga.writeJSON(http.StatusOK, w, map[string]string{
			"secret": key.Secret(),
			"url":    key.URL(),
		})
		return
	case actionVerify:
		// when you click the verify link from your email, this saves the active to true
		claims, err := ga.tokenStringClaims(req["token"], "")
		if err != nil || claims["act"] != actionVerify {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
			return
		}
		uid := claims["uid"]
		if claims["act"] == actionVerify && len(uid) > 0 {
			data, err := ga.AccountProvider.IdentityLoad(ctx, uid)
			if err == ErrAccountNotFound {
				ga.writeJSON(http.StatusNotFound, w, errorResponse{Error: "account not found"})
				return
			}
			if data[FieldActiveID] != "1" {
				data[FieldActiveID] = "1"
				if _, err := ga.AccountProvider.IdentitySave(ctx, uid, data); err != nil {
					ga.internalError(w, err)
					return
				}
				ga.writeJSON(http.StatusOK, w, "OK")
				return
			}
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
		return
	case "resetlink":
		// sends a password reset link
		identity := req[ga.IdentityFieldID]
		if identity == "" {
			ga.validationError(w, ga.IdentityFieldID, "required")
			return
		}
		if err := ga.rateLimiter.RateLimit(ctx, "resetlink:"+strings.ToLower(identity), ga.RateLimit.ResetLink.Rate, ga.RateLimit.ResetLink.Duration); err != nil {
			if _, ok := err.(cache.RateLimitError); ok {
				ga.validationError(w, ga.IdentityFieldID, "try again later")
				return
			}
			ga.internalError(w, err)
			return
		}
		uid, err := ga.AccountProvider.IdentityUID(ctx, identity)
		if err != nil && err != ErrAccountNotFound && err != ErrAccountNotActive {
			ga.internalError(w, err)
			return
		}
		if uid != "" {
			account, err := ga.AccountProvider.IdentityLoad(ctx, uid)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.sendMail(ctx, actionReset, uid, account); err != nil {
				ga.internalError(w, err)
				return
			}
		}
		ga.writeJSON(http.StatusOK, w, "OK")
		return
	case actionReset:
		// endpoint for password reset
		vErrs := ga.validateFields(ga.resetFields(), req)
		if len(vErrs) > 0 {
			ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
			return
		}
		uclaim, err := unverifiedClaims(req["token"])
		if err != nil || uclaim["act"] != actionReset {
			ga.log("unverified token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
			return
		}
		uid := uclaim["uid"].(string)
		if err := ga.rateLimiter.RateLimit(ctx, "resetlink:"+uid, ga.RateLimit.ResetLink.Rate, ga.RateLimit.ResetLink.Duration); err != nil {
			if _, ok := err.(cache.RateLimitError); ok {
				ga.validationError(w, ga.IdentityFieldID, "try again later")
				return
			}
			ga.internalError(w, err)
			return
		}
		acct, err := ga.AccountProvider.IdentityLoad(ctx, uid)
		if err == ErrAccountNotFound {
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
			return
		}
		claims, err := ga.tokenStringClaims(req["token"], acct[ga.PasswordFieldID])
		if err != nil || uid != claims["uid"] {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
			return
		}
		if claims["act"] == actionReset {
			acct[ga.PasswordFieldID], err = hashPassword(req[ga.PasswordFieldID], ga.BCryptCost)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.AccountProvider.IdentitySave(ctx, uid, acct); err != nil {
				ga.internalError(w, err)
				return
			}
			ga.writeJSON(http.StatusOK, w, "OK")
			return
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
		return
	case "confirmemail":
		// used for resending verification link
		identity := req[ga.IdentityFieldID]
		if identity == "" {
			ga.validationError(w, ga.IdentityFieldID, "required")
			return
		}
		if err := ga.rateLimiter.RateLimit(ctx, "confirmemail:"+strings.ToLower(identity), ga.RateLimit.ConfirmEmail.Rate, ga.RateLimit.ConfirmEmail.Duration); err != nil {
			if _, ok := err.(cache.RateLimitError); ok {
				ga.validationError(w, ga.IdentityFieldID, "try again later")
				return
			}
			ga.internalError(w, err)
			return
		}
		uid, err := ga.AccountProvider.IdentityUID(ctx, identity)
		if err != nil && err != ErrAccountNotActive {
			ga.internalError(w, err)
			return
		}
		if uid != "" {
			account, err := ga.AccountProvider.IdentityLoad(ctx, uid)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.sendMail(ctx, actionVerify, uid, account); err != nil {
				ga.internalError(w, err)
				return
			}
		}
		ga.writeJSON(http.StatusOK, w, "OK")
	case actionEmailUpdate:
		// this is the action when you click the link from your new email
		// this will update your account with the new email, an access token is required
		// to make sure you are logged in before you can trigger an email update
		auth, err := ga.Authorized(ga.headerToken(r))
		if err != nil {
			ga.log("AuthorizedError: ", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
			return
		}
		uclaim, err := unverifiedClaims(req["token"])
		if err != nil || uclaim["act"] != actionEmailUpdate {
			ga.log("unverified token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
			return
		}
		email, ok := uclaim["email"].(string)
		if ok && email != "" {
			acct, err := ga.AccountProvider.IdentityLoad(ctx, auth.UID)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if acct[ga.EmailFieldID] != email {
				acct[ga.EmailFieldID] = email
				if _, err := ga.AccountProvider.IdentitySave(ctx, auth.UID, acct); err != nil {
					ga.internalError(w, err)
					return
				}
				ga.writeJSON(http.StatusOK, w, "OK")
				return
			}
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: "invalid token"})
		return
	default:
		ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "unknown action"})
	}
}

func (ga *GAuth) qrKeyHandler(w http.ResponseWriter, r *http.Request) {
	keyURL := r.URL.Query().Get("k")
	key, err := otp.NewKeyFromURL(keyURL)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	img, err := key.Image(200, 200)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	png.Encode(w, img)
}
