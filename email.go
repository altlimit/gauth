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
)

func (ga *GAuth) emailHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html")

	ed := ga.emailData()
	ed.Data = []email.Part{
		{P: "Click the link below to update your email."},
		{URL: "#", Label: "Verify"},
	}
	if err := ed.Parse(make(map[string]string)); err != nil {
		ga.internalError(w, err)
		return
	}
	w.Write([]byte(ed.HTMLContent))
}

func (ga *GAuth) sendMail(ctx context.Context, action string, uid string, req map[string]string) error {
	if ga.emailSender != nil && ga.EmailFieldID != "" {
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["uid"] = uid
		claims["act"] = action
		// todo make this configurable
		claims["exp"] = time.Now().Add(time.Hour * 24 * 3).Unix()
		jwtKey := ga.JwtKey
		if action == actionReset {
			// we append password hash for password resets
			jwtKey = append(jwtKey, []byte(req[ga.PasswordFieldID])...)
		}
		tok, err := token.SignedString(jwtKey)
		if err != nil {
			return fmt.Errorf("sendMail: SignedString error %v", err)
		}

		link := ga.Brand.AppURL + ga.Path.Base + ga.Path.Login + "?a=" + action + "&t=" + tok
		ed := ga.emailData()

		switch action {
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
			return fmt.Errorf("ga.sendMail: parse error %v", err)
		}

		if ed.Subject != "" {
			if err := ga.emailSender.SendEmail(ctx, req[ga.EmailFieldID], ed.Subject, ed.TextContent, ed.HTMLContent); err != nil {
				return err
			}
		}
	}
	return nil
}
