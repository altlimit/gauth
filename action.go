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
		if qr := r.URL.Query().Get("qr"); qr != "" && !ga.disable2FA {
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
		if !ga.disableRecovery {
			recovery := make([]string, 10)
			for i := 0; i < 10; i++ {
				recovery[i] = randSeq(10)
			}
			ga.writeJSON(http.StatusOK, w, recovery)
			return
		}
	case "newTotpKey":
		if !ga.disable2FA {
			auth, err := ga.Authorized(r)
			if err != nil {
				ga.log("AuthorizedError: ", err)
				ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
				return
			}

			ctx := r.Context()
			accoount, err := ga.IdentityProvider.IdentityLoad(ctx, auth.UID)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			data := ga.loadIdentity(accoount)
			issuer := ga.Brand.AppName
			if iss, ok := req["issuer"]; ok && iss != "" {
				issuer = iss
			}
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      issuer,
				AccountName: toString(data[ga.IdentityFieldID]),
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
		}
	case actionVerify:
		// when you click the verify link from your email, this saves the active to true
		claims, err := ga.tokenStringClaims(req["token"], "")
		if err != nil || claims["act"] != actionVerify {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
			return
		}
		uid := claims["uid"]
		if claims["act"] == actionVerify && len(uid) > 0 {
			identity, err := ga.IdentityProvider.IdentityLoad(ctx, uid)
			if err == ErrIdentityNotFound {
				ga.writeJSON(http.StatusNotFound, w, errorResponse{Error: "identity not found"})
				return
			}
			data := ga.loadIdentity(identity)
			if active, ok := data[FieldActiveID].(bool); ok && !active {
				if _, err := ga.saveIdentity(ctx, identity, map[string]interface{}{
					FieldActiveID: true,
				}); err != nil {
					ga.internalError(w, err)
					return
				}
				ga.writeJSON(http.StatusOK, w, nil)
				return
			}
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
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
		uid, err := ga.IdentityProvider.IdentityUID(ctx, identity)
		if err != nil && err != ErrIdentityNotFound && err != ErrIdentityNotActive {
			ga.internalError(w, err)
			return
		}
		if uid != "" {
			identity, err := ga.IdentityProvider.IdentityLoad(ctx, uid)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.sendMail(ctx, actionReset, uid, ga.loadIdentity(identity)); err != nil {
				ga.internalError(w, err)
				return
			}
		}
		ga.writeJSON(http.StatusOK, w, nil)
		return
	case actionReset:
		// endpoint for password reset
		data := make(map[string]interface{})
		for k, v := range req {
			data[k] = v
		}
		vErrs := ga.validateFields(ga.resetFields(), data)
		if len(vErrs) > 0 {
			ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
			return
		}
		uclaim, err := unverifiedClaims(req["token"])
		if err != nil || uclaim["act"] != actionReset {
			ga.log("unverified token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
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
		identity, err := ga.IdentityProvider.IdentityLoad(ctx, uid)
		if err == ErrIdentityNotFound {
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
			return
		}
		acct := ga.loadIdentity(identity)
		pw := toString(acct[ga.PasswordFieldID])
		claims, err := ga.tokenStringClaims(req["token"], pw)
		if err != nil || uid != claims["uid"] {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
			return
		}
		if claims["act"] == actionReset {
			pw, err = hashPassword(req[ga.PasswordFieldID], ga.BCryptCost)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.saveIdentity(ctx, identity, map[string]interface{}{
				ga.PasswordFieldID: pw,
			}); err != nil {
				ga.internalError(w, err)
				return
			}
			ga.writeJSON(http.StatusOK, w, nil)
			return
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
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
		uid, err := ga.IdentityProvider.IdentityUID(ctx, identity)
		if err != nil && err != ErrIdentityNotActive {
			ga.internalError(w, err)
			return
		}
		if uid != "" {
			identity, err := ga.IdentityProvider.IdentityLoad(ctx, uid)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			if _, err := ga.sendMail(ctx, actionVerify, uid, ga.loadIdentity(identity)); err != nil {
				ga.internalError(w, err)
				return
			}
		}
		ga.writeJSON(http.StatusOK, w, nil)
		return
	case actionEmailUpdate:
		// this is the action when you click the link from your new email
		// this will update your identity with the new email, an access token is required
		// to make sure you are logged in before you can trigger an email update
		auth, err := ga.Authorized(r)
		if err != nil {
			ga.log("AuthorizedError: ", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: http.StatusText(http.StatusUnauthorized)})
			return
		}
		uclaim, err := unverifiedClaims(req["token"])
		if err != nil || uclaim["act"] != actionEmailUpdate {
			ga.log("unverified token error", err)
			ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
			return
		}
		email, ok := uclaim["email"].(string)
		if ok && email != "" {
			identity, err := ga.IdentityProvider.IdentityLoad(ctx, auth.UID)
			if err != nil {
				ga.internalError(w, err)
				return
			}
			data := ga.loadIdentity(identity)
			cEmail := toString(data[ga.EmailFieldID])
			if cEmail != email {
				cEmail = email
				if _, err := ga.saveIdentity(ctx, identity, map[string]interface{}{
					ga.EmailFieldID: email,
				}); err != nil {
					ga.internalError(w, err)
					return
				}
				ga.writeJSON(http.StatusOK, w, nil)
				return
			}
		}
		ga.writeJSON(http.StatusForbidden, w, errorResponse{Error: http.StatusText(http.StatusForbidden)})
		return
	}
	ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "unknown action"})
}
