package gauth

import (
	"net/http"
)

func (ga *GAuth) registerHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := ga.bind(r, &req); err != nil {
		ga.internalError(w, err)
		return
	}
	if !ga.validInput(w, req) {
		return
	}
	if ga.RecaptchaSecret != "" {
		if err := ga.validRecaptcha(ga.RecaptchaSecret, req["recaptcha"], ga.realIP(r)); err != nil {
			ga.validationError(w, "recaptcha", "verification failed")
			return
		}
	}
	ctx := r.Context()

	// check if identityField is unique provider
	err := ga.Provider.IdentityExists(ctx, req[ga.Identity.ID])
	if err != nil {
		if err == ErrAccountExists {
			ga.validationError(w, ga.Identity.ID, "exists")
			return
		}
	}

	// todo rate limit for registration

	// todo provider save identity
	if err := ga.Provider.IdentitySave(ctx, req); err != nil {
		ga.internalError(w, err)
		return
	}

	if ga.EmailFieldID != "" {
		if err := ga.Provider.SendEmail(ctx, req[ga.EmailFieldID], "", ""); err != nil {
			ga.internalError(w, err)
			return
		}
	}
	ga.writeJSON(http.StatusOK, w, nil)
}
