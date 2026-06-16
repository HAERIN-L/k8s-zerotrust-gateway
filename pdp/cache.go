package main

import (
	"fmt"
	"sync"
)

type Cache struct {
	mu    sync.RWMutex
	store map[string]AuthResponse
}

func newCache() *Cache {
	return &Cache{store: make(map[string]AuthResponse)}
}

func cacheKey(req AuthRequest) string {
	return fmt.Sprintf("%s|%s|%s|%.0f", req.Subject, req.Resource, req.Action, req.RiskScore)
}

func (c *Cache) get(req AuthRequest) (AuthResponse, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	resp, ok := c.store[cacheKey(req)]
	return resp, ok
}

func (c *Cache) set(req AuthRequest, resp AuthResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[cacheKey(req)] = resp
}
