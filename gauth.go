package gauth

import (
	"bytes"
	"encoding/base64"
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

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/email"
	"github.com/altlimit/gauth/form"
)

type (
	// GAuth is an HTTPServer which handles login, registration, settings, 2fa, etc.
	GAuth struct {
		// AccountProvider must be implemented for saving your user and notifications
		AccountProvider AccountProvider
		// Customize your access token claims
		TokenProvider TokenProvider

		// Login/register/settings page fields
		AccountFields []form.Field

		// Field for email verifications
		EmailFieldID string
		// Identity field is the field for logging in
		IdentityFieldID string
		// Leave blank to use email link for login
		PasswordFieldID string

		// Defaults to /auth/
		BasePath string

		// Paths for post and renderer
		AccountPath  string
		CancelPath   string
		LoginPath    string
		LogoutPath   string
		RefreshPath  string
		RegisterPath string
		TermsPath    string

		Logger *log.Logger

		// By default this uses embedded alpineJS
		AlpineJSURL string
		// Provide a secret to activate recaptcha in register/login(only on 3rd try+ for login)
		RecaptchaSecret string
		// JwtKey used for registration and token login
		JwtKey []byte

		// Page branding
		Brand form.Brand

		rateLimiter cache.RateLimiter
		emailSender email.Sender
	}

	errorResponse struct {
		Error string            `json:"error"`
		Data  map[string]string `json:"data,omitempty"`
	}
)

// NewDefault returns a sane default for GAuth, you can override properties
func NewDefault(ap AccountProvider) *GAuth {
	ga := &GAuth{
		AccountProvider: ap,

		EmailFieldID:    "email",
		IdentityFieldID: "email",
		PasswordFieldID: "password",
		AccountFields: []form.Field{
			{ID: "email", Label: "Email", Type: "email", Validate: RequiredEmail, InSettings: true},
			{ID: "password", Label: "Password", Type: "password", Validate: RequiredPassword, InSettings: true},
		},
		Logger: log.Default(),

		AccountPath:  "/account",
		LoginPath:    "/login",
		LogoutPath:   "/logout",
		RegisterPath: "/register",
		RefreshPath:  "/refresh",

		Brand: form.Brand{
			Primary:        "#121111",
			PrimaryInverse: "#fefefe",
			Accent:         "#BDBBBB",
			Neutral:        "#555454",
			NeutralInverse: "#f1f1f1",
		},
	}
	return ga
}

func (ga *GAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[len(ga.BasePath):]
	switch path {
	case ga.LoginPath:
		if r.Method == http.MethodPost {
			ga.loginHandler(w, r)
		} else if r.Method == http.MethodGet {
			ga.renderLoginHandler(w, r)
		}
	case ga.RegisterPath:
		if r.Method == http.MethodPost {
			ga.registerHandler(w, r)
		} else if r.Method == http.MethodGet {
			// render register page
		}
	case ga.RefreshPath:
		if r.Method == http.MethodGet {
			ga.refreshHandler(w, r)
		}
	case "/email-template":
		ga.emailHandler(w, r)
	case "/alpine.js":
		form.RenderAlpineJS(w, r)
	case "/client.js":
		form.RenderClientJS(w, r)
	}
}

func (ga *GAuth) fieldByID(id string) *form.Field {
	for i, f := range ga.AccountFields {
		if f.ID == id {
			return &ga.AccountFields[i]
		}
	}
	return nil
}

func (ga *GAuth) MustInit(showInfo bool) *GAuth {
	var buf bytes.Buffer
	buf.WriteString("Settings")
	if ga.JwtKey == nil {
		key, err := randomJWTKey()
		if err != nil {
			panic("failed to generated random jwt key")
		}
		ga.JwtKey = key
		buf.WriteString("\n > Random JwtKey: " + base64.StdEncoding.EncodeToString(key))
	}
	if ga.AlpineJSURL == "" {
		ga.AlpineJSURL = "/alpine.js"
	}
	if ga.BasePath == "" {
		ga.BasePath = "/auth"
	} else if len(ga.BasePath) > 1 {
		ga.BasePath = "/" + strings.Trim(ga.BasePath, "/")
	}
	buf.WriteString("\n > BasePath: " + ga.BasePath)

	buf.WriteString("\n > TokenProvider: ")
	if ga.TokenProvider == nil {
		buf.WriteString("Built-In")
		ga.TokenProvider = &DefaultTokenProvider{}
	} else {
		buf.WriteString("Custom")
	}
	buf.WriteString("\n > Send Email: ")
	if es, ok := ga.AccountProvider.(email.Sender); ok {
		ga.emailSender = es
		buf.WriteString("Yes")
	} else {
		buf.WriteString("No")
	}

	buf.WriteString("\n > EmailField: ")
	if ga.EmailFieldID != "" {
		if ga.fieldByID(ga.EmailFieldID) == nil {
			panic("EmailFieldID not found in AccountFields")
		}
		buf.WriteString(ga.EmailFieldID)
	} else {
		buf.WriteString("(Not Provided)")
	}
	buf.WriteString("\n > Password: ")
	if ga.PasswordFieldID == "" {
		if ga.emailSender == nil {
			panic("you must implement email.Sender to send email")
		}
		buf.WriteString("No (link login)")
	} else {
		if ga.fieldByID(ga.PasswordFieldID) == nil {
			panic("PasswordFieldID not found in AccountFields")
		}
		buf.WriteString(ga.PasswordFieldID)
	}
	buf.WriteString("\n > RateLimiter: ")
	if rl, ok := ga.AccountProvider.(cache.RateLimiter); ok {
		ga.rateLimiter = rl
		buf.WriteString("Custom")
	} else {
		ga.rateLimiter = cache.NewMemoryRateLimit()
		buf.WriteString("InMemory (implement cache.RateLimiter)")
	}

	if showInfo {
		ga.log(buf.String())
	}
	return ga
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
	for _, field := range ga.AccountFields {
		if field.Validate != nil {
			err := field.Validate(data[field.ID])
			if err != nil {
				p[field.ID] = err.Error()
			}
		}
	}
	if len(p) > 0 {
		ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: p})
		return false
	}
	return true
}

func (ga *GAuth) writeJSON(status int, w http.ResponseWriter, resp interface{}) {
	if resp == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(status)
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
	ga.writeJSON(http.StatusBadRequest, w, errorResponse{Error: "validation", Data: p})
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
