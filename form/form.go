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

//go:generate go run ../cmd/assets/main.go
//go:generate go run ../cmd/assets/main.go -asset alpine

var (
	formTpl *template.Template

	rawHash  = make(map[string]string)
	gzHash   = make(map[string]string)
	rawCache = make(map[string][]byte)
	gzCache  = make(map[string][]byte)
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

func eTag(b []byte) string {
	hasher := md5.New()
	hasher.Write(b)
	return hex.EncodeToString(hasher.Sum(nil))
}

func RenderAsset(w http.ResponseWriter, r *http.Request, path string) {
	var (
		rawAsset string
	)
	cType := "application/javascript"
	switch path {
	case "/client.css":
		rawAsset = ClientCSS
		cType = "text/css"
	case "/client.js":
		rawAsset = ClientJS
	case "/alpine.js":
		rawAsset = AlpineJS
	default:
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	hs, ok := rawHash[path]
	if !ok {
		rawCache[path] = []byte(rawAsset)
		rawHash[path] = eTag(rawCache[path])
		hs = rawHash[path]
	}
	body := rawCache[path]
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		hs, ok = gzHash[path]
		if !ok {
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			if _, err := gz.Write([]byte(rawAsset)); err != nil {
				panic(err)
			}
			if err := gz.Close(); err != nil {
				panic(err)
			}
			gzCache[path] = b.Bytes()
			gzHash[path] = eTag(gzCache[path])
			hs = gzHash[path]
		}
		body = gzCache[path]
	}

	h := w.Header()
	h.Set("Content-Encoding", "gzip")
	h.Set("Content-Type", cType)
	h.Set("Etag", hs)
	h.Set("Cache-Control", "max-age=86400")

	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, hs) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(body)
}
