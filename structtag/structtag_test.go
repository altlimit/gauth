package structtag

import (
	"testing"
)

func TestGetFieldsByTag(t *testing.T) {
	type hello struct {
		World string `json:"world" marshal:"f1"`
		X     string `json:"X"`
		Y     string `marshal:"f2,noindex=x"`
	}
	h := &hello{World: "123"}
	for k, f := range GetFieldsByTag(h, "marshal") {
		if f.Index == 0 {
			if k != "f1" {
				t.Errorf("wanted f1 got %s", k)
			}
			if _, ok := f.Value("noindex"); ok {
				t.Errorf("wanted noindex not found but found")
			}
		} else if f.Index == 2 {
			if k != "f2" {
				t.Errorf("wanted f2 got %s", k)
			}
			if _, ok := f.Value("noindex"); !ok {
				t.Errorf("wanted noindex but found")
			}
		}
	}
	if _, ok := structTagsCache["structtag.hello:marshal"]; !ok {
		t.Errorf("No cache found")
	}
	z := &hello{World: "1235"}
	for _, f := range GetFieldsByTag(z, "marshal") {
		if f.Index == 0 {
			if _, ok := f.Value("noindex"); ok {
				t.Errorf("wanted noindex not found but found")
			}
		} else if f.Index == 2 {
			if v, ok := f.Value("noindex"); !ok {
				t.Errorf("wanted noindex but found")
			} else if v != "x" {
				t.Errorf("wanted x value found %s", v)
			}
		}
	}
}
