package email

import (
	"bytes"
	"fmt"
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

// Parse populates Text & HTML Content returning an error
func (e *Data) Parse(data map[string]interface{}) error {
	if emailTpl == nil {
		tpl, err := template.New("email").Parse(Template)
		if err != nil {
			return fmt.Errorf("emailData.Parse error %v", err)
		}
		emailTpl = tpl
	}
	var texts []string
	buf := bytes.NewBufferString("")

	for k, v := range data {
		vs := fmt.Sprint(v)
		for i, d := range e.Data {
			e.Data[i].Label = strings.ReplaceAll(d.Label, "{"+k+"}", vs)
			e.Data[i].P = strings.ReplaceAll(d.P, "{"+k+"}", vs)
			e.Data[i].URL = strings.ReplaceAll(d.URL, "{"+k+"}", vs)
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
