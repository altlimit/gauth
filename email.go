package gauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/altlimit/gauth/email"
	"github.com/golang-jwt/jwt/v4"
)

const (
	actionVerify      = "verify"
	actionEmailUpdate = "emailupdate"
	actionReset       = "reset"
	actionLogin       = "login"
)

func (ga *GAuth) emailHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html")

	ed := ga.emailData()
	ed.Data = []email.Part{
		{P: "Click the link below to update your email."},
		{URL: "#", Label: "Verify"},
	}
	if err := ed.Parse(make(map[string]interface{})); err != nil {
		ga.internalError(w, err)
		return
	}
	w.Write([]byte(ed.HTMLContent))
}

func (ga *GAuth) sendMail(ctx context.Context, action string, uid string, req map[string]interface{}) (bool, error) {
	if ga.emailSender != nil && ga.EmailFieldID != "" {
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		actPath := ga.Path.Login

		claims["uid"] = uid
		claims["act"] = action
		toEmail := req[ga.EmailFieldID].(string)
		// updating email will only update record after verifying
		if action == actionEmailUpdate {
			claims["email"] = toEmail
			actPath = ga.Path.Account
		}
		claims["exp"] = time.Now().Add(ga.Timeout.EmailToken).Unix()
		jwtKey := ga.JwtKey
		if action == actionReset {
			// we append password hash for password resets
			jwtKey = append(jwtKey, []byte(req[ga.PasswordFieldID].(string))...)
		}
		tok, err := token.SignedString(jwtKey)
		if err != nil {
			return false, fmt.Errorf("sendMail: SignedString error %v", err)
		}
		link := ga.Brand.AppURL + ga.Path.Base + actPath + "?a=" + action + "&t=" + tok
		ed := ga.emailData()

		switch action {
		case actionLogin:
			ed.Subject = "Login / Register Link"
			ed.Data = []email.Part{
				{P: "Click the link below to login or register"},
				{URL: link, Label: "Login"},
			}

			if evm, ok := ga.AccountProvider.(email.LoginEmail); ok {
				ed.Subject, ed.Data = evm.LoginEmail()
				if ed.Subject != "" {
					ed.ReplaceLink(link)
				}
			}
		case actionVerify:
			ed.Subject = "Verify Your Email"
			ed.Data = []email.Part{
				{P: "Click the link below to verify your email."},
				{URL: link, Label: "Verify"},
			}
			if evm, ok := ga.AccountProvider.(email.ConfirmEmail); ok {
				ed.Subject, ed.Data = evm.ConfirmEmail()
			}
		case actionEmailUpdate:
			ed.Subject = "Confirm Email Update"
			ed.Data = []email.Part{
				{P: "Click the link below to update your email."},
				{URL: link, Label: "Verify"},
			}

			if evm, ok := ga.AccountProvider.(email.UpdateEmail); ok {
				ed.Subject, ed.Data = evm.UpdateEmail()
				if ed.Subject != "" {
					ed.ReplaceLink(link)
				}
			}
		case actionReset:
			ed.Subject = "Password Reset Link"
			ed.Data = []email.Part{
				{P: "Click the link below to reset your password."},
				{URL: link, Label: "Reset Password"},
			}

			if rp, ok := ga.AccountProvider.(email.ResetPassword); ok {
				ed.Subject, ed.Data = rp.ResetPassword()
				if ed.Subject != "" {
					ed.ReplaceLink(link)
				}
			}
		}

		if ed.Subject != "" {
			ed.ReplaceLink(link)
		}

		if err := ed.Parse(req); err != nil {
			return false, fmt.Errorf("ga.sendMail: parse error %v", err)
		}

		if ed.Subject != "" {
			if err := ga.emailSender.SendEmail(ctx, toEmail, ed.Subject, ed.TextContent, ed.HTMLContent); err != nil {
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}
