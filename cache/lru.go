package cache

import (
	"sync"
	"time"
)

type node struct {
	key        interface{}
	val        *lruItem
	prev, next *node
}

type (
	LRUCache struct {
		size       int
		capacity   int
		cache      sync.Map
		head, tail *node
		lock       sync.Mutex
	}

	lruItem struct {
		Expire time.Time
		Value  interface{}
	}
)

func initNode(key interface{}, val *lruItem) *node {
	return &node{
		key: key,
		val: val,
	}
}

func NewLRUCache(capacity int) *LRUCache {
	c := &LRUCache{
		capacity: capacity,
		head:     initNode(nil, nil),
		tail:     initNode(nil, nil),
	}
	c.head.next = c.tail
	c.tail.prev = c.head
	return c
}

func (c *LRUCache) Get(key interface{}) (interface{}, bool) {
	if v, ok := c.cache.Load(key); ok {
		n, _ := v.(*node)
		item := n.val
		if !item.Expire.IsZero() && item.Expire.Before(time.Now()) {
			c.removeNode(n)
			c.cache.Delete(n.key)
			c.size--
		} else {
			c.moveToHead(n)
			return item.Value, true
		}
	}
	return nil, false
}

func (c *LRUCache) Put(key, val interface{}, expire time.Duration) {
	if v, ok := c.cache.Load(key); ok {
		n, _ := v.(*node)
		n.val.Value = val
		c.moveToHead(n)
	} else {
		item := &lruItem{Value: val}
		if expire > 0 {
			item.Expire = time.Now().Add(expire)
		}
		n := initNode(key, item)
		c.cache.Store(n.key, n)
		c.addToHead(n)
		c.size++
		if c.size > c.capacity {
			n = c.removeTail()
			c.cache.Delete(n.key)
			c.size--
		}
	}
}

func (c *LRUCache) Len() int {
	return c.size
}

func (c *LRUCache) Cap() int {
	return c.capacity
}

func (c *LRUCache) LoadFactor() float64 {
	return float64(c.size) / float64(c.capacity)
}

func (c *LRUCache) addToHead(n *node) {
	c.lock.Lock()
	defer c.lock.Unlock()
	n.prev = c.head
	n.next = c.head.next
	c.head.next.prev = n
	c.head.next = n
}

func (c *LRUCache) removeNode(n *node) {
	c.lock.Lock()
	defer c.lock.Unlock()
	n.prev.next = n.next
	n.next.prev = n.prev
}

func (c *LRUCache) moveToHead(n *node) {
	c.removeNode(n)
	c.addToHead(n)
}

func (c *LRUCache) removeTail() *node {
	n := c.tail.prev
	c.removeNode(n)
	return n
}
