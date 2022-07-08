package gauth

import (
	"net/http"
	"time"

	"github.com/altlimit/gauth/form"
)

func (ga *GAuth) registerHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}

	vErrs := make(map[string]string)
	for _, field := range ga.registerFields() {
		if field.Validate != nil {
			err := field.Validate(field.ID, req)
			if err != nil {
				vErrs[field.ID] = err.Error()
			}
		}
	}
	if ga.Path.Terms != "" && req[FieldTermsID] != "agree" {
		vErrs[FieldTermsID] = "required"
	}
	if len(vErrs) > 0 {
		ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: vErrs})
		return
	}

	if ga.RecaptchaSecret != "" {
		if err := ga.validRecaptcha(ga.RecaptchaSecret, req["recaptcha"], ga.realIP(r)); err != nil {
			ga.validationError(w, "recaptcha", "verification failed")
			return
		}
	}
	ctx := r.Context()

	// check if identityField is unique
	_, err := ga.AccountProvider.IdentityLoad(ctx, req[ga.IdentityFieldID])
	if err == nil {
		ga.validationError(w, ga.IdentityFieldID, "already registered")
		return
	} else if err != ErrAccountNotFound {
		ga.internalError(w, err)
		return
	}

	if err := ga.rateLimiter.RateLimit(ctx, ga.realIP(r), 3, time.Hour*1); err != nil {
		ga.writeJSON(http.StatusTooManyRequests, w, errorResponse{Error: "Try again later"})
		return
	}

	// we hash the password before we send to save
	req[ga.PasswordFieldID], err = hashPassword(req[ga.PasswordFieldID], 13) // todo put cost in GAuth config
	if err != nil {
		ga.internalError(w, err)
		return
	}
	if err := ga.AccountProvider.IdentitySave(ctx, req); err != nil {
		ga.internalError(w, err)
		return
	}

	if err := ga.sendMail(ctx, "emailVerifyMessage", req); err != nil {
		ga.internalError(w, err)
		return
	}

	ga.writeJSON(http.StatusOK, w, "OK")
}

func (ga *GAuth) renderRegisterHandler(w http.ResponseWriter, r *http.Request) {
	fc := ga.formConfig()
	fc.Fields = ga.registerFields()
	if err := form.Render(w, "register", fc); err != nil {
		ga.internalError(w, err)
	}
}
