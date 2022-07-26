//go:build ignore

// This program generates form.Template, form.Layout, form.Client & form.AlpineJS
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"
)

func main() {
	fmt.Println("Updating templates.go")
	f, err := os.Create("templates.go")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	packageTemplate.Execute(f, struct {
		Timestamp time.Time
		AlpineJS  string
		Form      string
		Layout    string
		ClientJS  string
	}{
		Timestamp: time.Now(),
		AlpineJS:  loadAlpineJS(),
		Form:      loadAsset("form.html"),
		Layout:    loadAsset("layout.html"),
		ClientJS:  loadAsset("client.js"),
	})
}

var packageTemplate = template.Must(template.New("").Parse(`// Code generated by go generate; DO NOT EDIT.
// This file was generated by form/gen_templates.go
// {{ .Timestamp }}
package form

{{ .AlpineJS }}

var FormTemplate = {{ .Form }}

var Layout = {{ .Layout }}

var ClientJS = {{ .ClientJS }}
`))

func loadAsset(fname string) string {
	b, err := ioutil.ReadFile("assets/" + fname)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("`%s`", b)
}

func loadAlpineJS() string {
	url := "https://unpkg.com/alpinejs@3.10.2/dist/cdn.min.js"
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	if _, err := gz.Write(body); err != nil {
		panic(err)
	}
	if err := gz.Close(); err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	buf.WriteString("var AlpineJS = []byte{")
	bb := b.Bytes()
	bt := len(bb)
	for i, v := range bb {
		buf.WriteString(strconv.Itoa(int(v)))
		if i < bt-1 {
			buf.WriteRune(',')
		}
		if i > 0 && i%50 == 0 {
			buf.WriteRune('\n')
		}
	}
	buf.WriteRune('}')
	return buf.String()
}
