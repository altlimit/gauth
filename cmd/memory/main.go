package main

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"sync"

	"github.com/altlimit/gauth"
	"github.com/altlimit/gauth/form"
)

type (
	memoryProvider struct {
	}

	User struct {
		Name          string
		Password      string
		Email         string
		Active        bool
		TotpSecretKey string
		RecoveryCodes string
	}
)

var (
	users = make(map[string]*User)
	lock  sync.Mutex
)

func (mp *memoryProvider) IdentityUID(ctx context.Context, id string) (uid string, err error) {
	lock.Lock()
	defer lock.Unlock()
	for k, v := range users {
		if v.Email == id {
			if !v.Active {
				return "", gauth.ErrAccountNotActive
			}
			return k, nil
		}
	}
	return "", gauth.ErrAccountNotFound
}

func (mp *memoryProvider) IdentityLoad(ctx context.Context, uid string) (map[string]string, error) {
	lock.Lock()
	defer lock.Unlock()
	u, ok := users[uid]
	if !ok {
		return nil, gauth.ErrAccountNotFound
	}
	data := map[string]string{
		"name":                     u.Name,
		"password":                 u.Password,
		"email":                    u.Email,
		gauth.FieldActiveID:        "0",
		gauth.FieldTOTPSecretID:    u.TotpSecretKey,
		gauth.FieldRecoveryCodesID: u.RecoveryCodes,
	}
	if u.Active {
		data[gauth.FieldActiveID] = "1"
	}
	return data, nil
}
func (mp *memoryProvider) IdentitySave(ctx context.Context, uid string, data map[string]string) (string, error) {
	lock.Lock()
	defer lock.Unlock()
	var u *User
	if uid == "" {
		// create user
		u = &User{Active: false}
		uid = strconv.Itoa(len(users) + 1)
	} else {
		u = users[uid]
	}
	u.Email = data["email"]
	u.Name = data["name"]
	u.Password = data["password"]
	// check for built-in fields and update
	if v, ok := data[gauth.FieldActiveID]; ok {
		u.Active = v == "1"
	}
	if v, ok := data[gauth.FieldTOTPSecretID]; ok {
		u.TotpSecretKey = v
	}
	if v, ok := data[gauth.FieldRecoveryCodesID]; ok {
		u.RecoveryCodes = v
	}
	users[uid] = u
	return uid, nil
}
func (mp *memoryProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
	log.Println("ToEmail", toEmail, "\nSubject", subject, "\nTextBody: ", textBody)
	return nil
}

func (mp *memoryProvider) CreateRefreshToken(ctx context.Context, uid string) (string, error) {
	// create this clientID in DB and list in user Authorized List
	clientID := "cid123"
	return clientID, nil
}

func (mp *memoryProvider) CreateAccessToken(ctx context.Context, uid string, refresh string) (interface{}, error) {
	// we get refresh = cid123 here which we check against db if it's still a valid client and not yet revoked
	type grants struct {
		Owner bool    `json:"owner"`
		Roles []int64 `json:"role_ids"`
	}

	return grants{
		Owner: false,
		Roles: []int64{1, 2, 3},
	}, nil
}

func main() {
	port := "8887"
	ga := gauth.NewDefault(&memoryProvider{})
	ga.Brand.AppName = "Demo Memory"
	ga.Brand.LogoURL = "https://www.altlimit.com/logo.png"
	ga.Brand.AppURL = "http://localhost:" + port
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
