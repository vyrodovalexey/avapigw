package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestNewChain(t *testing.T) {
	chain := NewChain()
	assert.NotNil(t, chain)
	assert.Equal(t, 0, chain.Len())
}

func TestChain_Use(t *testing.T) {
	chain := NewChain()

	middleware1 := func(c *gin.Context) { c.Set("m1", true); c.Next() }
	middleware2 := func(c *gin.Context) { c.Set("m2", true); c.Next() }

	chain.Use(middleware1)
	assert.Equal(t, 1, chain.Len())

	chain.Use(middleware2)
	assert.Equal(t, 2, chain.Len())
}

func TestChain_UseMultiple(t *testing.T) {
	chain := NewChain()

	middleware1 := func(c *gin.Context) { c.Set("m1", true); c.Next() }
	middleware2 := func(c *gin.Context) { c.Set("m2", true); c.Next() }
	middleware3 := func(c *gin.Context) { c.Set("m3", true); c.Next() }

	chain.UseMultiple(middleware1, middleware2, middleware3)
	assert.Equal(t, 3, chain.Len())
}

func TestChain_Build(t *testing.T) {
	tests := []struct {
		name           string
		middlewares    []gin.HandlerFunc
		expectedValues map[string]bool
	}{
		{
			name:           "empty chain",
			middlewares:    nil,
			expectedValues: map[string]bool{},
		},
		{
			name: "single middleware",
			middlewares: []gin.HandlerFunc{
				func(c *gin.Context) { c.Set("m1", true); c.Next() },
			},
			expectedValues: map[string]bool{"m1": true},
		},
		{
			name: "multiple middlewares",
			middlewares: []gin.HandlerFunc{
				func(c *gin.Context) { c.Set("m1", true); c.Next() },
				func(c *gin.Context) { c.Set("m2", true); c.Next() },
				func(c *gin.Context) { c.Set("m3", true); c.Next() },
			},
			expectedValues: map[string]bool{"m1": true, "m2": true, "m3": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewChain()
			for _, m := range tt.middlewares {
				chain.Use(m)
			}

			handler := chain.Build()
			require.NotNil(t, handler)

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

			handler(c)

			for key, expected := range tt.expectedValues {
				val, exists := c.Get(key)
				assert.True(t, exists, "expected key %s to exist", key)
				assert.Equal(t, expected, val)
			}
		})
	}
}

func TestChain_Build_ExecutionOrder(t *testing.T) {
	chain := NewChain()
	order := make([]int, 0)

	chain.Use(func(c *gin.Context) { order = append(order, 1); c.Next() })
	chain.Use(func(c *gin.Context) { order = append(order, 2); c.Next() })
	chain.Use(func(c *gin.Context) { order = append(order, 3); c.Next() })

	handler := chain.Build()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2, 3}, order)
}

func TestChain_Build_Abort(t *testing.T) {
	chain := NewChain()
	executed := make([]int, 0)

	chain.Use(func(c *gin.Context) { executed = append(executed, 1); c.Next() })
	chain.Use(func(c *gin.Context) { executed = append(executed, 2); c.Abort() })
	chain.Use(func(c *gin.Context) { executed = append(executed, 3); c.Next() })

	handler := chain.Build()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2}, executed)
	assert.True(t, c.IsAborted())
}

func TestChain_Handlers(t *testing.T) {
	chain := NewChain()

	middleware1 := func(c *gin.Context) { c.Next() }
	middleware2 := func(c *gin.Context) { c.Next() }

	chain.Use(middleware1)
	chain.Use(middleware2)

	handlers := chain.Handlers()
	assert.Len(t, handlers, 2)
}

func TestChain_Len(t *testing.T) {
	chain := NewChain()
	assert.Equal(t, 0, chain.Len())

	chain.Use(func(c *gin.Context) { c.Next() })
	assert.Equal(t, 1, chain.Len())

	chain.Use(func(c *gin.Context) { c.Next() })
	assert.Equal(t, 2, chain.Len())
}

func TestChain_Clear(t *testing.T) {
	chain := NewChain()

	chain.Use(func(c *gin.Context) { c.Next() })
	chain.Use(func(c *gin.Context) { c.Next() })
	assert.Equal(t, 2, chain.Len())

	chain.Clear()
	assert.Equal(t, 0, chain.Len())
}

func TestChain_Clone(t *testing.T) {
	chain := NewChain()

	chain.Use(func(c *gin.Context) { c.Set("m1", true); c.Next() })
	chain.Use(func(c *gin.Context) { c.Set("m2", true); c.Next() })

	cloned := chain.Clone()
	assert.Equal(t, chain.Len(), cloned.Len())

	// Modify original, cloned should not be affected
	chain.Use(func(c *gin.Context) { c.Next() })
	assert.Equal(t, 3, chain.Len())
	assert.Equal(t, 2, cloned.Len())
}

func TestChain_Prepend(t *testing.T) {
	chain := NewChain()
	order := make([]int, 0)

	chain.Use(func(c *gin.Context) { order = append(order, 2); c.Next() })
	chain.Use(func(c *gin.Context) { order = append(order, 3); c.Next() })
	chain.Prepend(func(c *gin.Context) { order = append(order, 1); c.Next() })

	handler := chain.Build()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2, 3}, order)
}

func TestChain_Insert(t *testing.T) {
	tests := []struct {
		name          string
		index         int
		expectedOrder []int
	}{
		{
			name:          "insert at beginning",
			index:         0,
			expectedOrder: []int{0, 1, 2},
		},
		{
			name:          "insert in middle",
			index:         1,
			expectedOrder: []int{1, 0, 2},
		},
		{
			name:          "insert at end (beyond length)",
			index:         10,
			expectedOrder: []int{1, 2, 0},
		},
		{
			name:          "insert with negative index",
			index:         -1,
			expectedOrder: []int{0, 1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain := NewChain()
			order := make([]int, 0)

			chain.Use(func(c *gin.Context) { order = append(order, 1); c.Next() })
			chain.Use(func(c *gin.Context) { order = append(order, 2); c.Next() })
			chain.Insert(tt.index, func(c *gin.Context) { order = append(order, 0); c.Next() })

			handler := chain.Build()

			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

			handler(c)

			assert.Equal(t, tt.expectedOrder, order)
		})
	}
}

func TestChain_Then(t *testing.T) {
	chain := NewChain()
	order := make([]int, 0)

	chain.Use(func(c *gin.Context) { order = append(order, 1); c.Next() })
	chain.Use(func(c *gin.Context) { order = append(order, 2); c.Next() })

	finalHandler := func(c *gin.Context) { order = append(order, 3) }
	handler := chain.Then(finalHandler)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2, 3}, order)
}

func TestChain_Then_Abort(t *testing.T) {
	chain := NewChain()
	order := make([]int, 0)

	chain.Use(func(c *gin.Context) { order = append(order, 1); c.Abort() })
	chain.Use(func(c *gin.Context) { order = append(order, 2); c.Next() })

	finalHandler := func(c *gin.Context) { order = append(order, 3) }
	handler := chain.Then(finalHandler)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1}, order)
}

func TestChain_ThenFunc(t *testing.T) {
	chain := NewChain()
	order := make([]int, 0)

	chain.Use(func(c *gin.Context) { order = append(order, 1); c.Next() })

	handler := chain.ThenFunc(func(c *gin.Context) { order = append(order, 2) })

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2}, order)
}

func TestChain_Fluent(t *testing.T) {
	order := make([]int, 0)

	handler := NewChain().
		Use(func(c *gin.Context) { order = append(order, 1); c.Next() }).
		Use(func(c *gin.Context) { order = append(order, 2); c.Next() }).
		Use(func(c *gin.Context) { order = append(order, 3); c.Next() }).
		Build()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)

	handler(c)

	assert.Equal(t, []int{1, 2, 3}, order)
}
