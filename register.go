package gauth

import (
	"errors"
	"net/http"

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
	var req map[string]interface{}
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
		if recaptcha, ok := req["recaptcha"].(string); ok {
			if err := validRecaptcha(ga.RecaptchaSecret, recaptcha, realIP(r)); err != nil {
				ga.validationError(w, "recaptcha", "verification failed")
				return
			}
		}
	}
	ctx := r.Context()

	// check if identityField is unique
	id, ok := req[ga.IdentityFieldID].(string)
	if !ok {
		ga.validationError(w, ga.IdentityFieldID, "required")
		return
	}
	_, err := ga.AccountProvider.IdentityUID(ctx, id)
	if err == nil || err == ErrAccountNotActive {
		ga.validationError(w, ga.IdentityFieldID, "already registered")
		return
	} else if err != ErrAccountNotFound {
		ga.internalError(w, err)
		return
	}

	if err := ga.rateLimiter.RateLimit(ctx, realIP(r), ga.RateLimit.Register.Rate, ga.RateLimit.Register.Duration); err != nil {
		ga.writeJSON(http.StatusTooManyRequests, w, errorResponse{Error: "Try again later"})
		return
	}

	identity, err := ga.AccountProvider.IdentityLoad(ctx, "")
	if err != ErrAccountNotFound {
		ga.internalError(w, errors.New("IdentityLoad with empty uid got a record: "+err.Error()))
	}

	pw, _ := req[ga.PasswordFieldID].(string)
	req[ga.PasswordFieldID], err = hashPassword(pw, ga.BCryptCost)
	if err != nil {
		ga.internalError(w, err)
		return
	}

	uid, err := ga.saveIdentity(ctx, identity, req)
	if err != nil {
		ga.internalError(w, err)
		return
	}

	sent, err := ga.sendMail(ctx, actionVerify, uid, req)
	if err != nil {
		ga.internalError(w, err)
		return
	}
	status := http.StatusOK
	if sent {
		status = http.StatusCreated
	}
	ga.writeJSON(status, w, nil)
}
