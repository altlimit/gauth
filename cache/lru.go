package cache

import (
	"sync"
)

type node struct {
	key, val   interface{}
	prev, next *node
}

type LRUCache struct {
	size       int
	capacity   int
	cache      sync.Map
	head, tail *node
	lock       sync.Mutex
}

func initNode(key, val interface{}) *node {
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
		c.moveToHead(n)
		return n.val, true
	}
	return nil, false
}

func (c *LRUCache) Put(key, val interface{}) {
	if v, ok := c.cache.Load(key); ok {
		n, _ := v.(*node)
		n.val = val
		c.moveToHead(n)
	} else {
		n := initNode(key, val)
		c.cache.Store(key, n)
		c.addToHead(n)
		c.size++
		if c.size > c.capacity {
			evictedNode := c.removeTail()
			c.cache.Delete(evictedNode.key)
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
