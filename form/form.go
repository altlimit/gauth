package form

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"html/template"
	"net/http"
	"strings"
)

var (
	formTpl map[string]*template.Template

	layouts = []string{layout, nav}
	forms   = map[string]string{
		"login":    login,
		"register": register,
		"account":  account,
	}

	alpineHash  string
	clientHash  string
	clientCache []byte
)

type (
	ValidateFunc func(fieldID string, data map[string]string) error
	Config       struct {
		AlpineJSURL string
		Brand       Brand
		Path        Path

		Title       string
		Description string

		Fields []*Field
	}

	Field struct {
		ID          string
		Label       string
		Type        string
		Options     []Option
		Validate    ValidateFunc
		SettingsTab string
	}

	Option struct {
		ID    string
		Label string
	}

	Brand struct {
		LogoURL string
		AppName string
		AppURL  string

		RegisterLabel  string
		RegisterButton string
		LoginLabel     string
		LoginButton    string

		Primary        string
		PrimaryInverse string
		Accent         string
		Neutral        string
		NeutralInverse string
	}

	Path struct {
		// Defaults to /auth/
		Base string
		// Defaults to / provide where you want it to link back to
		Home string

		// paths for post and renderer
		Account  string
		Login    string
		Logout   string
		Refresh  string
		Register string
		Terms    string
	}
)

func init() {
	formTpl = make(map[string]*template.Template)
	for k, v := range forms {
		tpl := template.New(k)
		for _, vv := range append(layouts, v) {
			if _, err := tpl.Parse(vv); err != nil {
				panic(err)
			}
		}
		formTpl[k] = tpl
	}

	hasher := md5.New()
	hasher.Write(AlpineJS)
	alpineHash = hex.EncodeToString(hasher.Sum(nil))
}

func Render(w http.ResponseWriter, page string, c *Config) error {
	return formTpl[page].ExecuteTemplate(w, "layout", c)
}

func RenderAlpineJS(w http.ResponseWriter, r *http.Request) {
	// todo maybe check accept encoding?
	h := w.Header()
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", "application/javascript")
	h.Set("Etag", alpineHash)
	h.Set("Cache-Control", "max-age=86400")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, alpineHash) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Write(AlpineJS)
}

func RenderClientJS(w http.ResponseWriter, r *http.Request) {
	// todo maybe check accept encoding?

	if clientCache == nil {
		var b bytes.Buffer
		gz := gzip.NewWriter(&b)
		if _, err := gz.Write([]byte(clientJS)); err != nil {
			panic(err)
		}
		if err := gz.Close(); err != nil {
			panic(err)
		}
		clientCache = b.Bytes()
		hasher := md5.New()
		hasher.Write(clientCache)
		clientHash = hex.EncodeToString(hasher.Sum(nil))
	}

	h := w.Header()
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", "application/javascript")
	h.Set("Etag", clientHash)
	h.Set("Cache-Control", "max-age=86400")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, clientHash) {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Write(clientCache)
}
