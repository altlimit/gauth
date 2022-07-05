package gauth

import (
	"net/http"
	"time"
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
	err := ga.AccountProvider.IdentityExists(ctx, req[ga.IdentityFieldID])
	if err != nil {
		if err == ErrAccountExists {
			ga.validationError(w, ga.IdentityFieldID, "exists")
			return
		}
	}

	if err := ga.rateLimiter.RateLimit(ctx, ga.realIP(r), 3, time.Hour*1); err != nil {
		ga.writeJSON(http.StatusTooManyRequests, w, map[string]string{"message": http.StatusText(http.StatusTooManyRequests)})
		return
	}

	// todo provider save identity
	if err := ga.AccountProvider.IdentitySave(ctx, req); err != nil {
		ga.internalError(w, err)
		return
	}

	if ga.emailSender != nil {
		ed, err := ga.emailVerifyMessage(req)
		if err != nil {
			ga.internalError(w, err)
		}
		if err := ga.emailSender.SendEmail(ctx, req[ga.EmailFieldID], ed.Subject, ed.TextContent, ed.HTMLContent); err != nil {
			ga.internalError(w, err)
			return
		}
	}
	ga.writeJSON(http.StatusOK, w, nil)
}
