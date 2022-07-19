package structtag

import (
	"crypto/sha1"
	"encoding/hex"
	"reflect"
	"strings"
)

var (
	structTagsCache = make(map[string]map[string]*StructField)
)

type StructField struct {
	Index int
	tags  map[string]string
}

func (sf *StructField) Value(tag string) (v string, ok bool) {
	v, ok = sf.tags[tag]
	return
}

func NewStructField(index int, tag string) (string, *StructField) {
	tags := strings.Split(tag, ",")
	sf := &StructField{Index: index, tags: make(map[string]string)}
	if len(tags) > 1 {
		for i := 1; i < len(tags); i++ {
			t := strings.Split(tags[i], "=")
			var val string
			if len(t) > 1 {
				val = t[1]
			}
			sf.tags[t[0]] = val
		}
	}
	return tags[0], sf
}

func GetFieldsByTag(i interface{}, tag string) map[string]*StructField {
	t := reflect.TypeOf(i)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	cKey := t.String() + ":" + tag
	if len(cKey) > 50 {
		h := sha1.New()
		h.Write([]byte(cKey))
		cKey = hex.EncodeToString(h.Sum(nil))
	}
	fields, ok := structTagsCache[cKey]
	if !ok {
		fields = make(map[string]*StructField)
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			m := f.Tag.Get(tag)
			if m != "" {
				tag, sf := NewStructField(i, m)
				fields[tag] = sf
			}
		}
		structTagsCache[cKey] = fields
	}

	return fields
}
