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
)

func (ga *GAuth) emailHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html")

	ed, _ := ga.emailVerifyMessage("", map[string]string{})
	w.Write([]byte(ed.HTMLContent))
}

func (ga *GAuth) sendMail(ctx context.Context, t string, uid string, req map[string]string) error {
	if ga.emailSender != nil && ga.EmailFieldID != "" {
		var (
			ed  *email.Data
			err error
		)
		switch t {
		case "emailVerifyMessage":
			ed, err = ga.emailVerifyMessage(uid, req)
		case "emailUpdateMessage":
			ed, err = ga.emailUpdateMessage(uid, req)
		}
		if err != nil {
			return err
		}
		if ed != nil {
			if err := ga.emailSender.SendEmail(ctx, req[ga.EmailFieldID], ed.Subject, ed.TextContent, ed.HTMLContent); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ga *GAuth) emailVerifyMessage(uid string, d map[string]string) (*email.Data, error) {

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["uid"] = uid
	claims["act"] = actionVerify
	// todo make this configurable
	claims["exp"] = time.Now().Add(time.Hour * 24 * 3).Unix()
	tok, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		return nil, fmt.Errorf("emailVerifyMessage: SignedString error %v", err)
	}

	link := ga.Brand.AppURL + ga.Path.Base + ga.Path.Login + "?verify=" + tok
	ed := ga.emailData()
	ed.Subject = "Verify Your Email"
	ed.Data = []email.Part{
		{P: "Click the link below to verify your email."},
		{URL: link, Label: "Verify"},
	}

	if evm, ok := ga.AccountProvider.(email.ConfirmEmail); ok {
		ed.Subject, ed.Data = evm.ConfirmEmail()
		if ed.Subject != "" {
			ed.ReplaceLink(link)
		}
	}

	// empty subject to skip email
	if ed.Subject == "" {
		return nil, nil
	}

	if err := ed.Parse(d); err != nil {
		return nil, fmt.Errorf("ga.emailVerifyMessage: error %v", err)
	}
	return ed, nil
}

func (ga *GAuth) emailUpdateMessage(uid string, d map[string]string) (*email.Data, error) {

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["uid"] = uid
	claims["act"] = actionEmailUpdate
	claims["email"] = d[ga.EmailFieldID]
	// todo make this configurable
	claims["exp"] = time.Now().Add(time.Hour * 24 * 3).Unix()
	tok, err := refreshToken.SignedString(ga.JwtKey)
	if err != nil {
		return nil, fmt.Errorf("emailVerifyMessage: SignedString error %v", err)
	}

	link := ga.Brand.AppURL + ga.Path.Login + "?verify=" + tok
	ed := ga.emailData()
	ed.Subject = "Confirm Email Update"
	ed.Data = []email.Part{
		{P: "Click the link below to verify your email."},
		{URL: link, Label: "Verify"},
	}

	if evm, ok := ga.AccountProvider.(email.UpdateEmail); ok {
		ed.Subject, ed.Data = evm.UpdateEmail()
		if ed.Subject != "" {
			ed.ReplaceLink(link)
		}
	}

	// empty subject to skip email
	if ed.Subject == "" {
		return nil, nil
	}

	if err := ed.Parse(d); err != nil {
		return nil, fmt.Errorf("ga.emailUpdateMessage: error %v", err)
	}
	return ed, nil
}
