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
	"net/http"
	"regexp"
	"strings"

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/email"
	"github.com/altlimit/gauth/form"
	"github.com/golang-jwt/jwt/v4"
)

const (
	FieldActiveID        = "active"
	FieldCodeID          = "code"
	FieldTOTPSecretID    = "totpsecret"
	FieldRecoveryCodesID = "recoverycodes"
	FieldRememberID      = "remember"
	FieldTermsID         = "terms"
)

type (
	// GAuth is an HTTPServer which handles login, registration, settings, 2fa, etc.
	GAuth struct {
		// AccountProvider must be implemented for saving your user and notifications
		AccountProvider AccountProvider

		// Login/register/settings page fields
		AccountFields []*form.Field

		// Field for email verifications
		EmailFieldID string
		// Identity field is the field for logging in
		IdentityFieldID string
		// Leave blank to use email link for login
		PasswordFieldID string

		// Path for login, register, etc
		Path   form.Path
		Logger *log.Logger

		// By default this uses embedded alpineJS
		AlpineJSURL string
		// Provide a secret to activate recaptcha in register
		RecaptchaSiteKey string
		RecaptchaSecret  string
		// JwtKey used for registration and token login
		JwtKey []byte
		// AesKey will encrypt/decrypt your totpsecret
		AesKey     []byte
		BCryptCost int

		// Defaults to rtoken with NewDefault(), set to blank to not set a cookie
		RefreshTokenCookieName string

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

var (
	validIDRe = regexp.MustCompile(`^[\w]+$`)
)

// NewDefault returns a sane default for GAuth, you can override properties
func NewDefault(ap AccountProvider) *GAuth {
	var ga *GAuth
	ga = &GAuth{
		AccountProvider: ap,
		EmailFieldID:    "email",
		IdentityFieldID: "email",
		PasswordFieldID: "password",
		AccountFields: []*form.Field{
			{ID: "email", Label: "Email", Type: "email", Validate: RequiredEmail, SettingsTab: "Account"},
			{ID: "password", Label: "Password", Type: "password", Validate: RequiredPassword, SettingsTab: "Password"},
		},
		Path: form.Path{
			Account:  "/account",
			Login:    "/login",
			Logout:   "/logout",
			Register: "/register",
			Refresh:  "/refresh",
		},
		Brand: form.Brand{
			Primary:        "#121111",
			PrimaryInverse: "#fefefe",
			Accent:         "#BDBBBB",
			Neutral:        "#555454",
			NeutralInverse: "#f1f1f1",
		},
		RefreshTokenCookieName: "rtoken",
	}
	ga.AccountFields = append(ga.AccountFields, &form.Field{ID: "repassword", Label: "Re-Type Password", Type: "password", Validate: ga.confirmPass, SettingsTab: "Password"})
	return ga
}

func (ga *GAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path[len(ga.Path.Base):]
	switch path {
	case ga.Path.Login:
		ga.loginHandler(w, r)
	case ga.Path.Register:
		ga.registerHandler(w, r)
	case ga.Path.Refresh:
		ga.refreshHandler(w, r)
	case ga.Path.Account:
		ga.accountHandler(w, r)
	case "/action":
		ga.actionHandler(w, r)
	case "/email-template":
		ga.emailHandler(w, r)
	case "/alpine.js":
		form.RenderAlpineJS(w, r)
	case "/client.js":
		form.RenderClientJS(w, r)
	}
}

func (ga *GAuth) Authorized(t string) (*Auth, error) {
	claims, err := ga.tokenClaims(t, "")
	if err != nil {
		return nil, fmt.Errorf("tokenAuth: %v", err)
	}
	auth := &Auth{
		UID: claims["sub"].(string),
	}
	if grants, ok := claims["grants"]; ok {
		if g, ok := grants.(string); ok && g == "access" {
			return auth, nil
		}
		auth.Grants, err = json.Marshal(grants)
		if err != nil {
			return nil, fmt.Errorf("tokenAuth: marshal error %v", err)
		}
		return auth, nil
	}
	return nil, errors.New("invalid access token")
}

func (ga *GAuth) emailData() *email.Data {
	return &email.Data{
		HeaderLabel:    ga.Brand.AppName,
		HeaderURL:      ga.Brand.AppURL,
		FooterLabel:    ga.Brand.AppName,
		FooterURL:      ga.Brand.AppURL,
		Primary:        ga.Brand.Primary,
		PrimaryInverse: ga.Brand.PrimaryInverse,
		Accent:         ga.Brand.Accent,
		Neutral:        ga.Brand.Neutral,
	}
}

func (ga *GAuth) formConfig() *form.Config {
	return &form.Config{
		Brand:       ga.Brand,
		Path:        ga.Path,
		AlpineJSURL: ga.AlpineJSURL,
		Recaptcha:   ga.RecaptchaSiteKey,
		Flags:       make(map[string]interface{}),
	}
}

func (ga *GAuth) fieldByID(id string) *form.Field {
	for i, f := range ga.AccountFields {
		if f.ID == id {
			return ga.AccountFields[i]
		}
	}
	return nil
}

func (ga *GAuth) registerFields() (fields []*form.Field) {
	for _, f := range ga.AccountFields {
		// Accounts,only <-- meaning not included in register form
		if !strings.Contains(f.SettingsTab, ",only") {
			fields = append(fields, f)
		}
	}
	return
}

func (ga *GAuth) confirmPass(fID string, d map[string]string) error {
	s := d[fID]
	if s != d[ga.PasswordFieldID] {
		return errors.New("password do not match")
	}
	return nil
}

func (ga *GAuth) resetFields() (fields []*form.Field) {
	pwField := ga.fieldByID(ga.PasswordFieldID)
	confPw := &form.Field{ID: pwField.ID + "_confirm", Label: "Confirm " + pwField.Label, Type: pwField.Type, Validate: ga.confirmPass}
	fields = append(fields, pwField, confPw)
	return
}

func (ga *GAuth) validateFields(fields []*form.Field, input map[string]string) map[string]string {
	vErrs := make(map[string]string)
	for _, field := range fields {
		if field.Validate != nil {
			err := field.Validate(field.ID, input)
			if err != nil {
				vErrs[field.ID] = err.Error()
			}
		}
	}
	return vErrs
}

func (ga *GAuth) MustInit(showInfo bool) *GAuth {
	var buf bytes.Buffer

	// check for required stuff
	if ga.Brand.AppName == "" {
		panic("AppName brand missing")
	}
	if ga.Brand.AppURL == "" {
		panic("AppURL brand missing")
	}
	if ga.Path.Account == "" {
		panic("Account path missing")
	}
	if ga.Path.Login == "" {
		panic("Login path missing")
	}
	if ga.Path.Register == "" {
		panic("Register path missing")
	}
	if ga.Path.Logout == "" {
		panic("Logout path missing")
	}
	if ga.Path.Refresh == "" {
		panic("Refresh path missing")
	}

	// check if all fields are valid
	for _, f := range ga.AccountFields {
		if !validIDRe.MatchString(f.ID) {
			panic("invalid field " + f.ID + " must be alphanumeric/_")
		}
		if f.ID == FieldActiveID || f.ID == FieldTOTPSecretID || f.ID == FieldRecoveryCodesID || f.ID == FieldTermsID {
			panic("field " + f.ID + " is built-in")
		}
	}

	// Set defaults
	if ga.Logger == nil {
		ga.Logger = log.Default()
	}
	if ga.BCryptCost == 0 {
		ga.BCryptCost = 13
	}

	buf.WriteString("Settings")
	if ga.JwtKey == nil {
		key, err := randomJWTKey()
		if err != nil {
			panic("failed to generated random jwt key")
		}
		ga.JwtKey = key
		buf.WriteString("\n > JwtKey: RANDOM " + base64.StdEncoding.EncodeToString(key))
	}
	buf.WriteString("\n > AesKey: ")
	if len(ga.AesKey) == 0 {
		buf.WriteString("None (TOTPSecretKey will not be encrypted)")
	} else {
		buf.WriteString("Yes")
	}
	if ga.AlpineJSURL == "" {
		ga.AlpineJSURL = "/alpine.js"
	}
	if ga.Path.Base == "" {
		ga.Path.Base = "/auth"
	} else if len(ga.Path.Base) > 1 {
		ga.Path.Base = "/" + strings.Trim(ga.Path.Base, "/")
	}
	if ga.Path.Home == "" {
		ga.Path.Home = "/"
	}
	buf.WriteString("\n > BasePath: " + ga.Path.Base)
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
	buf.WriteString("\n > Recaptcha: ")
	if ga.RecaptchaSecret != "" && ga.RecaptchaSiteKey != "" {
		buf.WriteString("Enabled")
	} else {
		buf.WriteString("Disabled")
	}
	buf.WriteString("\n > RefreshToken Set-Cookie: ")
	if ga.RefreshTokenCookieName != "" {
		buf.WriteString("Yes")
	} else {
		buf.WriteString("No")
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

func (ga *GAuth) badError(w http.ResponseWriter, err error) {
	ga.log("BadRequestError", err)
	ga.writeJSON(http.StatusBadRequest, w,
		map[string]string{"error": http.StatusText(http.StatusBadRequest)})
}

func (ga *GAuth) headerToken(r *http.Request) string {
	auth := strings.Split(r.Header.Get("Authorization"), " ")
	if len(auth) == 2 && strings.ToLower(auth[0]) == "bearer" {
		return auth[1]
	}
	return ""
}

func (ga *GAuth) tokenStringClaims(tok, key string) (map[string]string, error) {
	claims, err := ga.tokenClaims(tok, key)
	if err != nil {
		return nil, fmt.Errorf("tokenStringClaims: %v", err)
	}
	result := make(map[string]string)
	for k, v := range claims {
		if vs, ok := v.(string); ok {
			result[k] = vs
		}
	}
	return result, nil
}

func (ga *GAuth) tokenClaims(tok, key string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		jwtKey := ga.JwtKey
		if len(key) > 0 {
			jwtKey = append(jwtKey, []byte(key)...)
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("gauth.tokenClaims parse error %v", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("gauth.tokenClaims not valid")
}
