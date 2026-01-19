// Package middleware provides HTTP middleware for the API Gateway.
package middleware

import (
	"github.com/gin-gonic/gin"
)

// Chain represents a chain of middleware handlers.
type Chain struct {
	middlewares []gin.HandlerFunc
}

// NewChain creates a new middleware chain.
func NewChain() *Chain {
	return &Chain{
		middlewares: make([]gin.HandlerFunc, 0),
	}
}

// Use adds middleware to the chain.
func (c *Chain) Use(middleware gin.HandlerFunc) *Chain {
	c.middlewares = append(c.middlewares, middleware)
	return c
}

// UseMultiple adds multiple middlewares to the chain.
func (c *Chain) UseMultiple(middlewares ...gin.HandlerFunc) *Chain {
	c.middlewares = append(c.middlewares, middlewares...)
	return c
}

// Build returns a single handler that executes all middlewares in the chain.
func (c *Chain) Build() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Create a copy of middlewares to avoid race conditions
		handlers := make([]gin.HandlerFunc, len(c.middlewares))
		copy(handlers, c.middlewares)

		// Execute each middleware
		for _, handler := range handlers {
			handler(ctx)
			if ctx.IsAborted() {
				return
			}
		}
	}
}

// Handlers returns the list of middleware handlers.
func (c *Chain) Handlers() []gin.HandlerFunc {
	handlers := make([]gin.HandlerFunc, len(c.middlewares))
	copy(handlers, c.middlewares)
	return handlers
}

// Len returns the number of middlewares in the chain.
func (c *Chain) Len() int {
	return len(c.middlewares)
}

// Clear removes all middlewares from the chain.
func (c *Chain) Clear() *Chain {
	c.middlewares = make([]gin.HandlerFunc, 0)
	return c
}

// Clone creates a copy of the chain.
func (c *Chain) Clone() *Chain {
	newChain := NewChain()
	newChain.middlewares = make([]gin.HandlerFunc, len(c.middlewares))
	copy(newChain.middlewares, c.middlewares)
	return newChain
}

// Prepend adds middleware to the beginning of the chain.
func (c *Chain) Prepend(middleware gin.HandlerFunc) *Chain {
	c.middlewares = append([]gin.HandlerFunc{middleware}, c.middlewares...)
	return c
}

// Insert adds middleware at a specific position in the chain.
func (c *Chain) Insert(index int, middleware gin.HandlerFunc) *Chain {
	if index < 0 {
		index = 0
	}
	if index >= len(c.middlewares) {
		return c.Use(middleware)
	}

	c.middlewares = append(c.middlewares[:index], append([]gin.HandlerFunc{middleware}, c.middlewares[index:]...)...)
	return c
}

// Then wraps a final handler with the middleware chain.
func (c *Chain) Then(handler gin.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		// Execute middlewares
		for _, middleware := range c.middlewares {
			middleware(ctx)
			if ctx.IsAborted() {
				return
			}
		}
		// Execute final handler
		handler(ctx)
	}
}

// ThenFunc wraps a final handler function with the middleware chain.
func (c *Chain) ThenFunc(handler func(*gin.Context)) gin.HandlerFunc {
	return c.Then(gin.HandlerFunc(handler))
}
