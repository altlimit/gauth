package cache_test

import (
	"testing"
	"time"

	"github.com/altlimit/gauth/cache"
)

func TestNewLRUCache2(t *testing.T) {
	c := cache.NewLRUCache(2)
	c.Put(1, 1, time.Millisecond*3)
	c.Put(2, 2, 0)
	v, ok := c.Get(1)
	if !ok {
		t.Errorf("wanted ok got !ok")
	}
	val, _ := v.(int)
	if val != 1 {
		t.Errorf("wanted 1 got %v", val)
	}
	time.Sleep(time.Millisecond * 11)
	_, ok = c.Get(1)
	if ok {
		t.Errorf("wanted !ok got ok")
	}
	c.Put(1, 1, 0)
	c.Put(3, 3, 0)
	_, ok = c.Get(2)
	if ok {
		t.Error("wanted !ok got ok")
	}
	c.Put(4, 4, 0)
	_, ok = c.Get(1)
	if ok {
		t.Error("wanted !ok got ok")
	}
	v, ok = c.Get(3)
	if !ok {
		t.Errorf("wanted ok got !ok")
	}
	val, _ = v.(int)
	if val != 3 {
		t.Errorf("wanted 3 got %v", val)
	}

	v, ok = c.Get(4)
	if !ok {
		t.Errorf("wanted ok got !ok")
	}
	val, _ = v.(int)
	if val != 4 {
		t.Errorf("wanted 4 got %v", val)
	}
	if v := c.Delete(5); v {
		t.Errorf("wanted false got true")
	}
	if c.Len() == 1 {
		t.Errorf("wanted cap 2 got 1")
	}
	if v := c.Delete(4); !v {
		t.Errorf("wanted true got false")
	}
	v, ok = c.Get(4)
	if ok {
		t.Errorf("wanted deleted key got val %v", v)
	}
}
