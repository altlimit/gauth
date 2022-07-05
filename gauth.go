package gauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type (
	GAuth struct {
		Provider AccountProvider
		// Page where you can update account info and add 2fa, etc
		AccountURL    string
		AccountFields []AccountField

		// Link to send you back out of the login, register or account page
		CancelURL string

		// Leave blank to disable email verifications
		EmailFieldID string
		// Main field, email/username/password (no password means it will use email login link)
		Identity AccountField
		Password AccountField

		Logger *log.Logger

		LoginURL  string
		LogoutURL string

		// Provide a secret to activate recaptcha in register/login(only on 3rd try+ for login)
		RecaptchaSecret string

		RegisterURL string
		// Link for terms when logging in
		TermsURL string
		// Page branding
		Theme Theme
	}

	AccountField struct {
		ID       string
		Label    string
		Type     string
		Options  []Option
		Validate func(string) error
	}

	Option struct {
		ID string
	}

	Theme struct {
		Header  string
		LogoURL string
		Primary string
		Accent  string
		Neutral string
	}
)

// New returns a sane default for GAuth
func New(provider AccountProvider) *GAuth {
	ga := &GAuth{
		Provider:   provider,
		AccountURL: "/account",
		AccountFields: []AccountField{
			{ID: "name", Label: "Name", Type: "text", Validate: ValidText},
		},
		CancelURL:    "/",
		EmailFieldID: "email",
		Identity:     AccountField{ID: "email", Label: "Email", Type: "email", Validate: ValidEmail},
		Password:     AccountField{ID: "password", Label: "Password", Type: "password", Validate: ValidPassword},
		Logger:       log.Default(),
		LoginURL:     "/login",
		LogoutURL:    "/logout",
		RegisterURL:  "/register",
		Theme: Theme{
			Primary: "dark-gray",
			Accent:  "light-gray",
			Neutral: "gray",
		},
	}
	return ga
}

func (ga *GAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasSuffix(path, ga.RegisterURL) {
		if r.Method == http.MethodPost {
			ga.registerHandler(w, r)
		} else if r.Method == http.MethodGet {
			// render register page
		}
	}
}

func (ga *GAuth) bind(r *http.Request, out interface{}) error {
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1048576))
	if err != nil {
		return err
	}
	if err := r.Body.Close(); err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}
	return nil
}

func (ga *GAuth) validInput(w http.ResponseWriter, data map[string]string) bool {
	p := make(map[string]string)
	fields := append(ga.AccountFields, ga.Identity)
	for _, field := range fields {
		if field.Validate != nil {
			err := field.Validate(data[field.ID])
			if err != nil {
				p[field.ID] = err.Error()
			}
		}
	}
	if len(p) > 0 {
		ga.writeJSON(http.StatusBadRequest, w, p)
		return false
	}
	return true
}

func (ga *GAuth) writeJSON(status int, w http.ResponseWriter, resp interface{}) {
	if resp == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		panic(err)
	}
}

func (ga *GAuth) validationError(w http.ResponseWriter, params ...string) {
	p := make(map[string]string)
	for i := 0; i < len(params); i += 2 {
		if i+1 < len(params) {
			p[params[i]] = params[i+1]
		}
	}
	ga.writeJSON(http.StatusBadRequest, w, p)
}

func (ga *GAuth) log(args ...interface{}) {
	args = append([]interface{}{"GAuth"}, args...)
	ga.Logger.Println(args...)
}

func (ga *GAuth) internalError(w http.ResponseWriter, err error) {
	ga.log("InternalServerError", err)
	ga.writeJSON(http.StatusInternalServerError, w,
		map[string]string{"error": http.StatusText(http.StatusInternalServerError)})
}

func (ga *GAuth) validRecaptcha(secret string, response string, ip string) error {
	type verify struct {
		Success bool `json:"success"`
	}
	hc := &http.Client{}
	resp, err := hc.PostForm("https://www.google.com/recaptcha/api/siteverify", url.Values{
		"secret":   {secret},
		"response": {response},
		"remoteip": {ip},
	})

	if err != nil {
		return fmt.Errorf("validRecaptcha: PostForm error %v", err)
	}

	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var v verify
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	if !v.Success {
		return errors.New("failed recaptcha")
	}
	return nil
}

func (ga *GAuth) realIP(r *http.Request) string {
	if ip := r.Header.Get("X-Appengine-User-Ip"); ip != "" {
		return ip
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ", ")[0]
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	ra, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ra
}
