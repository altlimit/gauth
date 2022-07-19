package gauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/altlimit/gauth"
	"github.com/altlimit/gauth/form"
)

type (
	memoryProvider struct {
	}

	User struct {
		ID            string
		Name          string `gauth:"name"`
		Password      string `gauth:"password"`
		Email         string `gauth:"email"`
		Active        bool   `gauth:"active"`
		TotpSecretKey string `gauth:"totpsecret"`
		RecoveryCodes string `gauth:"recoverycodes"`
		Question      string `gauth:"question"`
		Answer        string `gauth:"answer"`
	}
)

var (
	users     = make(map[string]*User)
	lock      sync.Mutex
	lastEmail string
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
				return k, gauth.ErrAccountNotActive
			}
			return k, nil
		}
	}
	return "", gauth.ErrAccountNotFound
}

func (mp *memoryProvider) IdentityLoad(ctx context.Context, uid string) (gauth.Identity, error) {
	lock.Lock()
	defer lock.Unlock()
	u, ok := users[uid]
	if !ok {
		return &User{}, gauth.ErrAccountNotFound
	}
	return u, nil
}

func (mp *memoryProvider) SendEmail(ctx context.Context, toEmail, subject, textBody, htmlBody string) error {
	log.Println()
	lastEmail = toEmail + "|" + subject + "|" + textBody
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

func TestGAuth(t *testing.T) {
	ga := gauth.NewDefault(&memoryProvider{})
	ga.Brand.AppName = "Demo Memory"
	ga.Brand.AppURL = "http://localhost:8887"
	ga.Path.Terms = "/terms"
	ga.AccountFields = append(ga.AccountFields,
		&form.Field{ID: "name", Label: "Name", Type: "text", Validate: gauth.RequiredText, SettingsTab: "Account"},
		&form.Field{ID: "question", Label: "Security Question", Type: "select", Validate: gauth.RequiredText, SettingsTab: "Security,only", Options: []form.Option{
			{Label: "Pick a security question"},
			{ID: "1", Label: "What is the name of your favorite pet?"},
			{ID: "2", Label: "What is your mother's maiden name?"},
		}},
		&form.Field{ID: "answer", Label: "Answer", Type: "textarea", Validate: gauth.RequiredText, SettingsTab: "Security,only"},
	)
	ga.MustInit(true)

	tokenRe := regexp.MustCompile(`t=(.+)`)
	var refresh struct {
		Token string `json:"refresh_token"`
	}
	var access struct {
		Token string `json:"access_token"`
	}
	sendReq := func(m, p, b string, headers map[string]string) (*http.Response, string) {
		req := httptest.NewRequest(m, p, strings.NewReader(b))
		w := httptest.NewRecorder()
		for k, v := range headers {
			req.Header.Add(k, v)
		}
		if access.Token != "" {
			req.Header.Add("Authorization", "Bearer "+access.Token)
		}
		ga.ServeHTTP(w, req)

		res := w.Result()
		defer res.Body.Close()
		data, err := ioutil.ReadAll(res.Body)
		if err != nil {
			t.Errorf("ioutil.ReadAll error %v", err)
		}
		return res, strings.TrimRight(string(data), "\n")
	}
	table := []struct {
		method   string
		path     string
		request  string
		headers  map[string]string
		response string
		status   int
		cb       func(string) error
	}{
		{http.MethodGet, "/auth/login", ``, nil, `~<title>Login - Demo Memory</title>`, 200, nil},
		{http.MethodPost, "/auth/login", `{"email": "a@a.a", "password": "P@ssw0rd"}`, nil, `{"error":"validation","data":{"password":"invalid"}}`, 400, nil},
		{http.MethodPost, "/auth/register", `{"email": "a@a.a", "password": "P@ssw0rd"}`, nil, `{"error":"validation","data":{"name":"required","terms":"required"}}`, 400, func(body string) error {
			if len(users) > 0 {
				return fmt.Errorf("expected users to be 0 got %d", len(users))
			}
			return nil
		}},
		{http.MethodPost, "/auth/register", `{"email": "a@a.a", "password": "P@ssw0rd", "terms": true, "name":"A"}`, nil, ``, 201, func(body string) error {
			if len(users) != 1 {
				return fmt.Errorf("expected users to be == 1 got 0")
			}
			if users["1"].Active {
				return fmt.Errorf("expected first user to be inactive")
			}
			parts := strings.Split(lastEmail, "|")
			if parts[0] != "a@a.a" {
				return fmt.Errorf("wanted to email a@a.a got %s", parts[0])
			}
			if parts[1] != "Verify Your Email" {
				return fmt.Errorf("wanted subject 'Verify Your Email' got '%s'", parts[1])
			}
			vTok := tokenRe.FindString(parts[2])
			if vTok == "" {
				return fmt.Errorf("token not found")
			}
			res, _ := sendReq(http.MethodPost, "/auth/action", fmt.Sprintf(`{"action":"verify", "token": "%s"}`, vTok[2:]), nil)
			if res.StatusCode != 200 {
				return fmt.Errorf("Expected status 200 got %d", res.StatusCode)
			}
			if !users["1"].Active {
				return fmt.Errorf("expected first user to be active")
			}
			return nil
		}},
		{http.MethodPost, "/auth/login", `{"email": "a@a.a", "password": "P@ssw0rd"}`, nil, `~{"refresh_token":"`, 200, func(body string) error {
			if err := json.Unmarshal([]byte(body), &refresh); err != nil {
				return err
			}
			res, resp := sendReq(http.MethodPost, "/auth/refresh", fmt.Sprintf(`{"token":"%s"}`, refresh.Token), nil)
			if res.StatusCode != 200 {
				return fmt.Errorf("Expected status 200 got %d", res.StatusCode)
			}
			if err := json.Unmarshal([]byte(resp), &access); err != nil {
				return err
			}
			if access.Token == "" {
				return fmt.Errorf("expecting access token got nothing")
			}
			return nil
		}},
		{http.MethodGet, "/auth/account", ``, map[string]string{"Content-Type": "application/json"}, `{"answer":"","email":"a@a.a","name":"A","question":""}`, 200, func(body string) error {
			account := make(map[string]string)
			if err := json.Unmarshal([]byte(body), &account); err != nil {
				return err
			}
			res, resp := sendReq(http.MethodPost, "/auth/account", body, map[string]string{"Content-Type": "application/json"})
			if resp != `{"error":"validation","data":{"answer":"required","question":"required"}}` {
				t.Fatalf("wanted validation error got %s", resp)
			}
			if res.StatusCode != 400 {
				t.Fatalf("wanted 400 got %d", res.StatusCode)
			}
			account["email"] = "aa@a.a"
			account["answer"] = "Yes"
			account["question"] = "What?"
			b, _ := json.Marshal(account)
			res, resp = sendReq(http.MethodPost, "/auth/account", string(b), map[string]string{"Content-Type": "application/json"})
			if res.StatusCode != 201 {
				t.Fatalf("wanted 201 got %d", res.StatusCode)
			}
			if resp != `{"answer":"Yes","email":"a@a.a","name":"A","question":"What?"}` {
				t.Fatalf("wanted account error got %s", resp)
			}
			if users["1"].Email != "a@a.a" {
				return fmt.Errorf("expected first user to be same email got %v", users["1"].Email)
			}
			parts := strings.Split(lastEmail, "|")
			if parts[0] != "aa@a.a" {
				return fmt.Errorf("wanted to email aa@a.a got %s", parts[0])
			}
			if parts[1] != "Confirm Email Update" {
				return fmt.Errorf("wanted subject 'Confirm Email Update' got '%s'", parts[1])
			}
			vTok := tokenRe.FindString(parts[2])
			if vTok == "" {
				return fmt.Errorf("token not found")
			}
			res, _ = sendReq(http.MethodPost, "/auth/action", fmt.Sprintf(`{"action":"emailupdate", "token": "%s"}`, vTok[2:]), nil)
			if res.StatusCode != 200 {
				return fmt.Errorf("Expected status 200 got %d", res.StatusCode)
			}
			if users["1"].Email == "a@a.a" {
				return fmt.Errorf("expected first user have an updated email got %s", users["1"].Email)
			}
			return nil
		}},
	}

	for _, v := range table {
		res, resp := sendReq(v.method, v.path, v.request, v.headers)
		if !((strings.HasPrefix(v.response, "~") && strings.Contains(resp, v.response[1:]) || resp == v.response) && res.StatusCode == v.status) {
			t.Errorf("path %s wanted %d `%s` got %d `%s`", v.path, v.status, v.response, res.StatusCode, resp)
		}
		if v.cb != nil {
			if err := v.cb(resp); err != nil {
				t.Fatalf("Callback %s error %v", v.request, err)
			}
		}
	}
}
