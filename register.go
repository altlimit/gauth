package gauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/altlimit/gauth/form"
)

func (ga *GAuth) registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if ga.PasswordFieldID == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		fc := ga.formConfig()
		fc.Recaptcha = ga.RecaptchaSiteKey
		fc.Title = "Register"
		fc.Submit = "Register"
		fc.Links = append(fc.Links, &form.Link{
			URL:   ga.Path.Base + ga.Path.Login,
			Label: "Login",
		})
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
	agree, _ := req[FieldTermsID].(bool)
	if ga.Path.Terms != "" && !agree {
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
	ctx := context.WithValue(r.Context(), RequestKey, r)
	// check if identityField is unique
	id, ok := req[ga.IdentityFieldID].(string)
	if !ok {
		ga.validationError(w, ga.IdentityFieldID, "required")
		return
	}
	_, err := ga.IdentityProvider.IdentityUID(ctx, id)
	if err == nil || err == ErrIdentityNotActive {
		ga.validationError(w, ga.IdentityFieldID, "already registered")
		return
	} else if err != ErrIdentityNotFound {
		ga.internalError(w, err)
		return
	}

	if err := ga.rateLimiter.RateLimit(ctx, realIP(r), ga.RateLimit.Register.Rate, ga.RateLimit.Register.Duration); err != nil {
		ga.writeJSON(http.StatusTooManyRequests, w, errorResponse{Error: "Try again later"})
		return
	}

	identity, err := ga.IdentityProvider.IdentityLoad(ctx, "")
	if err != ErrIdentityNotFound {
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
		if ve, ok := err.(ValidationError); ok {
			ga.validationError(w, ve.Field, ve.Message)
			return
		}
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
