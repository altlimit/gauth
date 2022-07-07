package gauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/altlimit/gauth/email"
)

func (ga *GAuth) emailHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html")

	ed, _ := ga.emailVerifyMessage(map[string]string{})
	w.Write([]byte(ed.HTMLContent))
}

func (ga *GAuth) sendMail(ctx context.Context, t string, req map[string]string) error {
	if ga.emailSender != nil && ga.EmailFieldID != "" {
		var (
			ed  *email.Data
			err error
		)
		switch t {
		case "emailVerifyMessage":
			ed, err = ga.emailVerifyMessage(req)
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

func (ga *GAuth) emailVerifyMessage(d map[string]string) (*email.Data, error) {
	ed := &email.Data{
		HeaderLabel:    ga.Brand.EmailHeader,
		HeaderURL:      ga.Brand.EmailHeaderURL,
		FooterLabel:    ga.Brand.EmailFooter,
		FooterURL:      ga.Brand.EmailFooterURL,
		Primary:        ga.Brand.Primary,
		PrimaryInverse: ga.Brand.PrimaryInverse,
		Accent:         ga.Brand.Accent,
		Neutral:        ga.Brand.Neutral,
		Subject:        "Verify Your Email",
		Data: []email.Part{
			{P: "Click the link below to verify your email."},
			{URL: "/verify", Label: "Verify"},
		},
	}

	if evm, ok := ga.AccountProvider.(email.ConfirmEmail); ok {
		ed.Subject, ed.Data = evm.ConfirmEmail()
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
