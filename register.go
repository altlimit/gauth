package gauth

import (
	"net/http"
	"time"

	"github.com/altlimit/gauth/form"
)

func (ga *GAuth) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		fc := ga.formConfig()
		fc.Title = "Register"
		fc.Submit = "Register"
		fc.Links = append(fc.Links, &form.Link{
			URL:   ga.Path.Base + ga.Path.Login,
			Label: "Login",
		})
		if ga.Path.Terms != "" {
			fc.Terms = true
		}
		fc.Fields = ga.registerFields()
		if err := form.Render(w, fc); err != nil {
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

	vErrs := ga.validateFields(ga.registerFields(), req)
	if ga.Path.Terms != "" && req[FieldTermsID] != "agree" {
		vErrs[FieldTermsID] = "required"
	}
	if len(vErrs) > 0 {
		ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
		return
	}

	if ga.RecaptchaSecret != "" && ga.RecaptchaSiteKey != "" {
		if err := validRecaptcha(ga.RecaptchaSecret, req["recaptcha"], realIP(r)); err != nil {
			ga.validationError(w, "recaptcha", "verification failed")
			return
		}
	}
	ctx := r.Context()

	// check if identityField is unique
	_, err := ga.AccountProvider.IdentityUID(ctx, req[ga.IdentityFieldID])
	if err == nil || err == ErrAccountNotActive {
		ga.validationError(w, ga.IdentityFieldID, "already registered")
		return
	} else if err != ErrAccountNotFound {
		ga.internalError(w, err)
		return
	}

	if err := ga.rateLimiter.RateLimit(ctx, realIP(r), 3, time.Hour*1); err != nil {
		ga.writeJSON(http.StatusTooManyRequests, w, errorResponse{Error: "Try again later"})
		return
	}

	// we hash the password before we send to save
	req[ga.PasswordFieldID], err = hashPassword(req[ga.PasswordFieldID], ga.BCryptCost)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	uid, err := ga.AccountProvider.IdentitySave(ctx, "", req)
	if err != nil {
		ga.internalError(w, err)
		return
	}

	if err := ga.sendMail(ctx, actionVerify, uid, req); err != nil {
		ga.internalError(w, err)
		return
	}

	ga.writeJSON(http.StatusOK, w, "OK")
}
