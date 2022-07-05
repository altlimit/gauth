package main

import (
	"context"
	"log"
	"net/http"

	"github.com/altlimit/gauth"
	"github.com/altlimit/gauth/email"
)

type (
	datastoreProvider struct {
	}
)

func (dp *datastoreProvider) IdentityExists(ctx context.Context, id string) error {
	return nil
}
func (dp *datastoreProvider) IdentitySave(ctx context.Context, data map[string]string) error {
	return nil
}
func (dp *datastoreProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
	return nil
}

func (dp *datastoreProvider) ConfirmEmail() (string, []email.Part) {
	return "Click Verification Link", []email.Part{
		{P: "Test {name}"},
		{URL: "{link}", Label: "BUTTON"},
	}
}

func main() {
	ga := gauth.NewDefault(&datastoreProvider{})
	http.Handle("/auth/", ga)
	port := "8887"
	log.Println("Listening: " + port)
	http.ListenAndServe(":"+port, nil)
}
