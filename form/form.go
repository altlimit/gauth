package form

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"html/template"
	"net/http"
	"strings"
)

//go:generate go run gen_templates.go

var (
	formTpl *template.Template

	alpineHash  string
	clientHash  string
	clientCache []byte
)

type (
	ValidateFunc func(fieldID string, data map[string]interface{}) error
	Config       struct {
		AlpineJSURL string
		Recaptcha   string
		Brand       Brand
		Path        Path

		Title       string
		Description string

		Tab  string
		Tabs []string

		Links  []*Link
		Fields []*Field

		Submit string
	}

	Link struct {
		URL   string
		Label string
	}

	Field struct {
		ID          string
		Label       string
		LabelHtml   template.HTML
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
		Refresh  string
		Register string
		Terms    string
	}
)

func Render(w http.ResponseWriter, c *Config) (err error) {
	if formTpl == nil {
		formTpl, err = template.New("form").Parse(FormTemplate)
		if err != nil {
			return fmt.Errorf("form.Render: template parse error %v", err)
		}
		if _, err := formTpl.Parse(Layout); err != nil {
			return fmt.Errorf("form.Render: formTpl parse error %v", err)
		}
	}
	return formTpl.ExecuteTemplate(w, "layout", c)
}

func RenderAlpineJS(w http.ResponseWriter, r *http.Request) {
	if alpineHash == "" {
		hasher := md5.New()
		hasher.Write(AlpineJS)
		alpineHash = hex.EncodeToString(hasher.Sum(nil))
	}

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
		if _, err := gz.Write([]byte(ClientJS)); err != nil {
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
