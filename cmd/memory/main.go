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
		ID            string
		Name          string  `gauth:"name"`
		Password      *string `gauth:"password"`
		Email         string  `gauth:"email"`
		Active        bool    `gauth:"active"`
		TotpSecretKey string  `gauth:"totpsecret"`
		RecoveryCodes *string `gauth:"recoverycodes"`
		Question      string  `gauth:"question"`
		Answer        string  `gauth:"answer"`
	}
)

var (
	users = make(map[string]*User)
	lock  sync.Mutex
)

func (u *User) IdentitySave(ctx context.Context) (uid string, err error) {
	lock.Lock()
	defer lock.Unlock()
	if u.ID == "" {
		u.Active = false
		u.ID = strconv.Itoa(len(users) + 1)
	}
	users[u.ID] = u
	uid = u.ID
	return
}

func (mp *memoryProvider) IdentityUID(ctx context.Context, id string) (uid string, err error) {
	lock.Lock()
	defer lock.Unlock()
	for k, v := range users {
		if v.Email == id {
			if !v.Active {
				return k, gauth.ErrIdentityNotActive
			}
			return k, nil
		}
	}
	return "", gauth.ErrIdentityNotFound
}

func (mp *memoryProvider) IdentityLoad(ctx context.Context, uid string) (gauth.Identity, error) {
	lock.Lock()
	defer lock.Unlock()
	u, ok := users[uid]
	if !ok {
		return &User{}, gauth.ErrIdentityNotFound
	}
	return u, nil
}

func (mp *memoryProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
	log.Println("ToEmail", toEmail, "\nSubject", subject, "\nTextBody: ", textBody)
	return nil
}

func dashboardHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`Dashboard`))
	})
}

func homeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
		<head>
		<title></title>
		</head>
		<body>
			<a href="/auth/login">Login</a>
			<a href="/auth/refresh?logout=1">Logout</a>
			<a href="/dashboard">Dashboard</a>
			<a href="/auth/account">Account</a>
		</body>
		</html>
		`))
	})
}

func main() {
	port := "8887"
	ga := gauth.NewDefault("Demo Memory", "http://localhost:"+port, &memoryProvider{})
	ga.Path.Terms = "/terms"
	ga.Fields = append(ga.Fields,
		&form.Field{ID: "name", Label: "Name", Type: "text", Validate: gauth.RequiredText, SettingsTab: "Account"},
		&form.Field{ID: "question", Label: "Security Question", Type: "select", Validate: gauth.RequiredText, SettingsTab: "Security,only", Options: []form.Option{
			{Label: "Pick a security question"},
			{ID: "1", Label: "What is the name of your favorite pet?"},
			{ID: "2", Label: "What is your mother's maiden name?"},
		}},
		&form.Field{ID: "answer", Label: "Answer", Type: "textarea", Validate: gauth.RequiredText, SettingsTab: "Security,only"},
	)
	ga.AccessTokenCookieName = "atoken"
	http.Handle("/auth/", ga.MustInit(true))
	http.Handle("/dashboard", ga.AuthMiddleware(dashboardHandler()))
	http.Handle("/", homeHandler())

	// passwordless
	ga = gauth.NewPasswordless("Passwordless", "http://localhost:"+port, &memoryProvider{})
	ga.Path.Base = "/pwless"
	ga.Fields = append(ga.Fields,
		&form.Field{ID: "name", Label: "Name", Type: "text", Validate: gauth.RequiredText, SettingsTab: "Account"},
	)
	http.Handle("/pwless/", ga.MustInit(true))

	log.Println("Listening: " + port)
	http.ListenAndServe(":"+port, nil)
}
