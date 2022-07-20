package gauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/altlimit/gauth/cache"
	"github.com/altlimit/gauth/email"
	"github.com/altlimit/gauth/form"
	"github.com/altlimit/gauth/structtag"
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
		// defaults to /login /register /account /refresh
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
		Disable2FA             bool

		// Page branding
		Brand form.Brand

		RateLimit RateLimit
		// defaults to "gauth"
		StructTag string

		rateLimiter cache.RateLimiter
		emailSender email.Sender
	}

	RateLimit struct {
		Login        cache.Rate
		Register     cache.Rate
		ResetLink    cache.Rate
		ConfirmEmail cache.Rate
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
func NewDefault(appName string, appURL string, ap AccountProvider) *GAuth {
	ga := &GAuth{
		AccountProvider: ap,
		EmailFieldID:    "email",
		IdentityFieldID: "email",
		PasswordFieldID: "password",
		AccountFields: []*form.Field{
			{ID: "email", Label: "Email", Type: "email", Validate: RequiredEmail, SettingsTab: "Account"},
			{ID: "password", Label: "Password", Type: "password", Validate: RequiredPassword, SettingsTab: "Password"},
		},
		Brand: form.Brand{
			AppName:        appName,
			AppURL:         appURL,
			Primary:        "#121111",
			PrimaryInverse: "#fefefe",
			Accent:         "#BDBBBB",
			Neutral:        "#555454",
			NeutralInverse: "#f1f1f1",
		},
		RefreshTokenCookieName: "rtoken",
	}
	return ga
}

// NewPasswordless returns a passwordless login settings
func NewPasswordless(appName string, appURL string, ap AccountProvider) *GAuth {
	ga := &GAuth{
		AccountProvider: ap,
		EmailFieldID:    "email",
		IdentityFieldID: "email",
		AccountFields: []*form.Field{
			{ID: "email", Label: "Email", Type: "email", Validate: RequiredEmail, SettingsTab: "Account"},
		},
		Brand: form.Brand{
			AppName:        appName,
			AppURL:         appURL,
			Primary:        "#121111",
			PrimaryInverse: "#fefefe",
			Accent:         "#BDBBBB",
			Neutral:        "#555454",
			NeutralInverse: "#f1f1f1",
		},
		RefreshTokenCookieName: "rtoken",
	}
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
	default:
		notFound := http.StatusText(http.StatusNotFound)
		if ga.isJson(r) {
			ga.writeJSON(http.StatusNotFound, w, errorResponse{Error: notFound})
			return
		}
		http.Error(w, notFound, http.StatusNotFound)
	}
}

func (ga *GAuth) Authorized(r *http.Request) (*Auth, error) {
	t := ga.headerToken(r)
	if t == "" {
		return nil, errors.New("no token")
	}
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

func (ga *GAuth) accountFields() ([]string, []*form.Field) {
	var tabs []string
	mapFields := make(map[string]bool)
	var fields []*form.Field

	tab := "2FA"
	if ga.PasswordFieldID != "" && !ga.Disable2FA {
		tabs = append(tabs, tab)
		fields = append(fields, &form.Field{ID: FieldTOTPSecretID, Type: "2fa", SettingsTab: tab})
		fields = append(fields, &form.Field{ID: FieldCodeID, Type: "text", Label: "Enter Code", SettingsTab: tab})
		fields = append(fields, &form.Field{ID: FieldRecoveryCodesID, Type: "recovery", Label: "Generate Recovery Codes", SettingsTab: tab})
	}

	for _, f := range ga.AccountFields {
		tab = strings.Split(f.SettingsTab, ",")[0]
		if tab != "" {
			_, ok := mapFields[tab]
			if !ok {
				mapFields[tab] = true
				tabs = append(tabs, tab)
			}
			fields = append(fields, f)

			if f.ID == ga.PasswordFieldID {
				fields = append(fields, &form.Field{ID: f.ID + "_confirm", Label: "Re-Type " + f.Label, Type: f.Type, SettingsTab: f.SettingsTab})
			}
		}
	}
	sort.Strings(tabs)
	return tabs, fields
}

func (ga *GAuth) registerFields() (fields []*form.Field) {
	for _, f := range ga.AccountFields {
		// Accounts,only <-- meaning not included in register form
		if !strings.Contains(f.SettingsTab, ",only") {
			fields = append(fields, f)

			if f.ID == ga.PasswordFieldID {
				fields = append(fields, &form.Field{ID: f.ID + "_confirm", Label: "Re-Type " + f.Label, Type: f.Type, SettingsTab: f.SettingsTab})
			}
		}
	}
	if ga.Path.Terms != "" {
		fields = append(fields, &form.Field{
			ID:        FieldTermsID,
			Type:      "checkbox",
			LabelHtml: template.HTML(fmt.Sprintf(`I agree to the <a href="%s">terms and agreement</a>.`, ga.Path.Terms)),
		})
	}
	return
}

func (ga *GAuth) resetFields() (fields []*form.Field) {
	pwField := ga.fieldByID(ga.PasswordFieldID)
	confPw := &form.Field{ID: pwField.ID + "_confirm", Label: "Confirm " + pwField.Label, Type: pwField.Type}
	fields = append(fields, pwField, confPw)
	return
}

func (ga *GAuth) validateFields(fields []*form.Field, input map[string]interface{}) map[string]string {
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
	if ga.PasswordFieldID == "" {
		if ga.IdentityFieldID != ga.EmailFieldID {
			panic("IdentityFieldID must be same as EmailFieldID for passwordless")
		}
		emailField := ga.fieldByID(ga.IdentityFieldID)
		if emailField == nil {
			panic("identity field not found")
		} else if emailField.Type != "email" {
			panic("identity field must be of type email")
		}
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
	if ga.Path.Account == "" {
		ga.Path.Account = "/account"
	}
	if ga.Path.Login == "" {
		ga.Path.Login = "/login"
	}
	if ga.PasswordFieldID != "" && ga.Path.Register == "" {
		ga.Path.Register = "/register"
	}
	if ga.Path.Refresh == "" {
		ga.Path.Refresh = "/refresh"
	}

	if ga.StructTag == "" {
		ga.StructTag = "gauth"
	}
	if ga.Logger == nil {
		ga.Logger = log.Default()
	}
	if ga.BCryptCost == 0 {
		ga.BCryptCost = 13
	}
	if ga.RateLimit.Login.Rate == 0 {
		ga.RateLimit.Login = cache.Rate{
			Rate:     10,
			Duration: time.Hour,
		}
	}
	if ga.RateLimit.Register.Rate == 0 {
		ga.RateLimit.Register = cache.Rate{
			Rate:     5,
			Duration: time.Hour,
		}
	}
	if ga.RateLimit.ConfirmEmail.Rate == 0 {
		ga.RateLimit.ConfirmEmail = cache.Rate{
			Rate:     5,
			Duration: time.Hour,
		}
	}
	if ga.RateLimit.ResetLink.Rate == 0 {
		ga.RateLimit.ResetLink = cache.Rate{
			Rate:     5,
			Duration: time.Hour,
		}
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

func (ga *GAuth) isJson(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Accept"), "application/json") ||
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
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

func (ga *GAuth) saveIdentity(ctx context.Context, id Identity, req map[string]interface{}) (string, error) {
	v := reflect.ValueOf(id)
	if v.Type().Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for tag, field := range structtag.GetFieldsByTag(id, ga.StructTag) {
		val, ok := req[tag]
		if ok {
			vt := reflect.TypeOf(val)
			vv := reflect.ValueOf(val)
			fv := v.Field(field.Index)
			ft := fv.Type()
			if vt == ft {
				fv.Set(vv)
			} else {
				ga.log("WARN field not mapped: ", tag, "type is", ft, "got", vt, "value", val)
			}
		}
	}

	return id.IdentitySave(ctx)
}

func (ga *GAuth) loadIdentity(id Identity) map[string]interface{} {
	data := make(map[string]interface{})

	v := reflect.ValueOf(id)
	if v.Type().Kind() == reflect.Ptr {
		v = v.Elem()
	}

	for tag, field := range structtag.GetFieldsByTag(id, ga.StructTag) {
		fv := v.Field(field.Index)
		data[tag] = fv.Interface()
	}

	return data
}
