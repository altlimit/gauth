package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/altlimit/gauth"
	"github.com/altlimit/gauth/form"
)

type (
	datastoreProvider struct {
	}

	User struct {
		ID       int64
		Name     string
		Password string
		Email    string
		Active   bool
	}
)

var (
	users = make(map[string]User)
	lock  sync.Mutex
)

func (dp *datastoreProvider) IdentityLoad(ctx context.Context, id string) (map[string]string, error) {
	lock.Lock()
	defer lock.Unlock()
	u, ok := users[id]
	if !ok {
		return nil, gauth.ErrAccountNotFound
	}
	data := map[string]string{
		"name":     u.Name,
		"password": u.Password,
		"email":    u.Email,
	}
	return data, nil
}
func (dp *datastoreProvider) IdentitySave(ctx context.Context, data map[string]string) error {
	lock.Lock()
	defer lock.Unlock()
	id := strings.ToLower(data["email"])
	u, ok := users[id]
	if !ok {
		// create user
		u = User{Active: false}
	}
	u.Email = data["email"]
	u.Name = data["name"]
	u.Password = data["password"]
	users[id] = u
	return nil
}
func (dp *datastoreProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
	log.Println("ToEmail", toEmail, "\nSubject", subject, "\nTextBody: ", textBody)
	return nil
}

// func (dp *datastoreProvider) ConfirmEmail() (string, []email.Part) {
// 	return "Click Verification Link", []email.Part{
// 		{P: "Test {name}"},
// 		{URL: "{link}", Label: "BUTTON"},
// 	}
// }

func main() {
	port := "8887"
	ga := gauth.NewDefault(&datastoreProvider{})
	ga.BaseURL = "http://localhost:" + port
	ga.Path.Terms = "/terms"
	ga.AccountFields = append(ga.AccountFields,
		&form.Field{ID: "name", Label: "Name", Type: "text", Validate: gauth.RequiredText, SettingsTab: "Account"},
		&form.Field{ID: "question", Label: "Security Question", Type: "select", Validate: gauth.RequiredText, SettingsTab: "Security,only", Options: []form.Option{
			{Label: "Pick a security question"},
			{ID: "1", Label: "What is the name of your favorite pet?"},
			{ID: "2", Label: "What is your mother's maiden name?<"},
		}},
		&form.Field{ID: "answer", Label: "Answer", Type: "textarea", Validate: gauth.RequiredText, SettingsTab: "Security,only"},
	)
	http.Handle("/auth/", ga.MustInit(true))
	log.Println("Listening: " + port)
	http.ListenAndServe(":"+port, nil)
}
