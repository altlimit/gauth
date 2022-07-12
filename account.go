package gauth

import (
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/form"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func (ga *GAuth) accountHandler(w http.ResponseWriter, r *http.Request) {
	fc := ga.formConfig()
	tabs, fields := ga.accountFields()
	var tab string
	if t, ok := r.URL.Query()["tab"]; ok && len(t) > 0 {
		tab = t[0]
	}
	if tab == "" && len(tabs) > 0 {
		tab = tabs[0]
	}
	fc.Title = tab + " Settings"
	fc.Submit = "Save"
	fc.Fields = fields[tab]
	for _, tab := range tabs {
		fc.Tabs = append(fc.Tabs, &form.Link{URL: "?tab=" + tab, Label: tab})
	}

	if r.Method == http.MethodGet {
		if err := form.Render(w, fc); err != nil {
			ga.internalError(w, err)
		}
		return
	} else if r.Method == http.MethodPost {

		return
	}

	ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
}

func (ga *GAuth) qrKeyHandler(w http.ResponseWriter, r *http.Request) {
	var keyURL string
	if k, ok := r.URL.Query()["k"]; ok && len(k) > 0 {
		keyURL = k[0]
	}
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

func (ga *GAuth) actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ga.writeJSON(http.StatusMethodNotAllowed, w, nil)
		return
	}
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}
	ctx := r.Context()
	switch req["action"] {
	case "genKey":
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      ga.Brand.AppURL,
			AccountName: "a@example.com",
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
	case "verify":
		claims, err := ga.tokenStringClaims(req["token"], "")
		if err != nil || claims["act"] != actionVerify {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
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
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
		return
	case "resetlink":
		identity := req[ga.IdentityFieldID]
		if identity == "" {
			ga.validationError(w, ga.IdentityFieldID, "required")
			return
		}
		idKey := "resetlink:" + strings.ToLower(identity)
		if err := ga.rateLimiter.RateLimit(ctx, idKey, 2, time.Hour); err != nil {
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
			if err := ga.sendMail(ctx, actionReset, uid, account); err != nil {
				ga.internalError(w, err)
				return
			}
		}
		ga.writeJSON(http.StatusOK, w, "OK")
		return
	case "reset":
		vErrs := ga.validateFields(ga.resetFields(), req)
		if len(vErrs) > 0 {
			ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
			return
		}
		uclaim, err := unverifiedClaims(req["token"])
		if err != nil || uclaim["act"] != actionReset {
			ga.log("unverified token error", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
			return
		}
		uid := uclaim["uid"].(string)
		idKey := "resetlink:" + uid
		if err := ga.rateLimiter.RateLimit(ctx, idKey, 10, time.Hour); err != nil {
			if _, ok := err.(cache.RateLimitError); ok {
				ga.validationError(w, ga.IdentityFieldID, "try again later")
				return
			}
			ga.internalError(w, err)
			return
		}
		acct, err := ga.AccountProvider.IdentityLoad(ctx, uid)
		if err == ErrAccountNotFound {
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
			return
		}
		claims, err := ga.tokenStringClaims(req["token"], acct[ga.PasswordFieldID])
		if err != nil || uid != claims["uid"] {
			ga.log("verify token error", err)
			ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
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
		ga.writeJSON(http.StatusUnauthorized, w, errorResponse{Error: "invalid token"})
		return
	default:
		ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "unknown action"})
	}
}
