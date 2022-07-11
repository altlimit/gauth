package email

import (
	"bytes"
	"html/template"
	"strings"
)

type (
	Part struct {
		P     string
		URL   string
		Label string
	}
	Data struct {
		Subject     string
		TextContent string
		HTMLContent string
		Data        []Part

		LogoURL     string
		HeaderURL   string
		HeaderLabel string

		FooterURL   string
		FooterLabel string

		// Theme
		Primary        string
		PrimaryInverse string
		Accent         string
		Neutral        string
		NeutralInverse string
	}
)

var (
	emailTpl *template.Template
)

func init() {
	tpl, err := template.New("email").Parse(htmlTemplate)
	if err != nil {
		panic(err)
	}
	emailTpl = tpl
}

// Parse populates Text & HTML Content returning an error
func (e *Data) Parse(data map[string]string) error {
	var texts []string
	buf := bytes.NewBufferString("")

	for k, v := range data {
		for i, d := range e.Data {
			e.Data[i].Label = strings.ReplaceAll(d.Label, "{"+k+"}", v)
			e.Data[i].P = strings.ReplaceAll(d.P, "{"+k+"}", v)
			e.Data[i].URL = strings.ReplaceAll(d.URL, "{"+k+"}", v)
		}
	}

	if err := emailTpl.Execute(buf, e); err != nil {
		return err
	}
	for _, d := range e.Data {
		var t string
		if d.P != "" {
			t = d.P
		} else if d.URL != "" {
			t = d.URL
		}
		texts = append(texts, t)
	}
	e.TextContent = strings.Join(texts, "\n\n")
	e.HTMLContent = buf.String()
	return nil
}

func (e *Data) ReplaceLink(link string) {
	for k, v := range e.Data {
		if v.URL == "{link}" {
			e.Data[k].URL = link
		}
	}
}
