package transform

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// =============================================================================
// NewRequestTransformer Tests
// =============================================================================

func TestNewRequestTransformer(t *testing.T) {
	t.Run("creates transformer with initialized components", func(t *testing.T) {
		transformer := NewRequestTransformer()

		assert.NotNil(t, transformer)
		assert.NotNil(t, transformer.urlRewriter)
		assert.NotNil(t, transformer.urlRewriter.rules)
		assert.Empty(t, transformer.urlRewriter.rules)
		assert.NotNil(t, transformer.headerModifier)
		assert.NotNil(t, transformer.headerModifier.set)
		assert.NotNil(t, transformer.headerModifier.add)
		assert.NotNil(t, transformer.queryModifier)
		assert.NotNil(t, transformer.queryModifier.set)
		assert.NotNil(t, transformer.queryModifier.add)
	})
}

// =============================================================================
// RequestTransformer.Transform Tests
// =============================================================================

func TestRequestTransformer_Transform(t *testing.T) {
	t.Run("applies URL rewriting", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetURLRewriteRules([]*URLRewriteRule{
			{
				Type:            URLRewriteReplaceFullPath,
				ReplaceFullPath: "/new/path",
			},
		})

		req := httptest.NewRequest(http.MethodGet, "http://example.com/old/path", nil)
		err := transformer.Transform(req)

		assert.NoError(t, err)
		assert.Equal(t, "/new/path", req.URL.Path)
	})

	t.Run("applies header modifications", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetHeaderModifications(
			map[string]string{"X-Custom": "value"},
			map[string]string{"X-Added": "added-value"},
			[]string{"X-Remove"},
		)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
		req.Header.Set("X-Remove", "to-be-removed")
		err := transformer.Transform(req)

		assert.NoError(t, err)
		assert.Equal(t, "value", req.Header.Get("X-Custom"))
		assert.Equal(t, "added-value", req.Header.Get("X-Added"))
		assert.Empty(t, req.Header.Get("X-Remove"))
	})

	t.Run("applies query modifications", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetQueryModifications(
			map[string]string{"set-param": "set-value"},
			map[string]string{"add-param": "add-value"},
			[]string{"remove-param"},
		)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api?remove-param=old", nil)
		err := transformer.Transform(req)

		assert.NoError(t, err)
		assert.Equal(t, "set-value", req.URL.Query().Get("set-param"))
		assert.Equal(t, "add-value", req.URL.Query().Get("add-param"))
		assert.Empty(t, req.URL.Query().Get("remove-param"))
	})

	t.Run("applies all transformations together", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetURLRewriteRules([]*URLRewriteRule{
			{
				Type:            URLRewriteReplaceFullPath,
				ReplaceFullPath: "/api/v2/users",
			},
		})
		transformer.SetHeaderModifications(
			map[string]string{"Content-Type": "application/json"},
			map[string]string{"X-Request-ID": "12345"},
			[]string{"X-Old-Header"},
		)
		transformer.SetQueryModifications(
			map[string]string{"version": "2"},
			map[string]string{"format": "json"},
			[]string{"old-param"},
		)

		req := httptest.NewRequest(http.MethodGet, "http://example.com/old/path?old-param=value", nil)
		req.Header.Set("X-Old-Header", "old-value")
		err := transformer.Transform(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/v2/users", req.URL.Path)
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		assert.Equal(t, "12345", req.Header.Get("X-Request-ID"))
		assert.Empty(t, req.Header.Get("X-Old-Header"))
		assert.Equal(t, "2", req.URL.Query().Get("version"))
		assert.Equal(t, "json", req.URL.Query().Get("format"))
		assert.Empty(t, req.URL.Query().Get("old-param"))
	})

	t.Run("returns no error with empty transformations", func(t *testing.T) {
		transformer := NewRequestTransformer()
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)

		err := transformer.Transform(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api", req.URL.Path)
	})
}

// =============================================================================
// RequestTransformer.SetURLRewriteRules Tests
// =============================================================================

func TestRequestTransformer_SetURLRewriteRules(t *testing.T) {
	t.Run("sets rules", func(t *testing.T) {
		transformer := NewRequestTransformer()
		rules := []*URLRewriteRule{
			{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/new"},
			{Type: URLRewriteReplacePrefixMatch, PrefixToMatch: "/old", ReplacePrefixMatch: "/new"},
		}

		transformer.SetURLRewriteRules(rules)

		assert.Len(t, transformer.urlRewriter.rules, 2)
		assert.Equal(t, URLRewriteReplaceFullPath, transformer.urlRewriter.rules[0].Type)
		assert.Equal(t, URLRewriteReplacePrefixMatch, transformer.urlRewriter.rules[1].Type)
	})

	t.Run("sets empty rules", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetURLRewriteRules([]*URLRewriteRule{
			{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/new"},
		})

		transformer.SetURLRewriteRules([]*URLRewriteRule{})

		assert.Empty(t, transformer.urlRewriter.rules)
	})

	t.Run("sets nil rules", func(t *testing.T) {
		transformer := NewRequestTransformer()
		transformer.SetURLRewriteRules([]*URLRewriteRule{
			{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/new"},
		})

		transformer.SetURLRewriteRules(nil)

		assert.Nil(t, transformer.urlRewriter.rules)
	})
}

// =============================================================================
// RequestTransformer.SetHeaderModifications Tests
// =============================================================================

func TestRequestTransformer_SetHeaderModifications(t *testing.T) {
	t.Run("sets header modifications", func(t *testing.T) {
		transformer := NewRequestTransformer()
		set := map[string]string{"X-Set": "value"}
		add := map[string]string{"X-Add": "value"}
		remove := []string{"X-Remove"}

		transformer.SetHeaderModifications(set, add, remove)

		assert.Equal(t, set, transformer.headerModifier.set)
		assert.Equal(t, add, transformer.headerModifier.add)
		assert.Equal(t, remove, transformer.headerModifier.remove)
	})

	t.Run("sets nil values", func(t *testing.T) {
		transformer := NewRequestTransformer()

		transformer.SetHeaderModifications(nil, nil, nil)

		assert.Nil(t, transformer.headerModifier.set)
		assert.Nil(t, transformer.headerModifier.add)
		assert.Nil(t, transformer.headerModifier.remove)
	})
}

// =============================================================================
// RequestTransformer.SetQueryModifications Tests
// =============================================================================

func TestRequestTransformer_SetQueryModifications(t *testing.T) {
	t.Run("sets query modifications", func(t *testing.T) {
		transformer := NewRequestTransformer()
		set := map[string]string{"set-param": "value"}
		add := map[string]string{"add-param": "value"}
		remove := []string{"remove-param"}

		transformer.SetQueryModifications(set, add, remove)

		assert.Equal(t, set, transformer.queryModifier.set)
		assert.Equal(t, add, transformer.queryModifier.add)
		assert.Equal(t, remove, transformer.queryModifier.remove)
	})

	t.Run("sets nil values", func(t *testing.T) {
		transformer := NewRequestTransformer()

		transformer.SetQueryModifications(nil, nil, nil)

		assert.Nil(t, transformer.queryModifier.set)
		assert.Nil(t, transformer.queryModifier.add)
		assert.Nil(t, transformer.queryModifier.remove)
	})
}

// =============================================================================
// URLRewriter.Rewrite Tests
// =============================================================================

func TestURLRewriter_Rewrite(t *testing.T) {
	t.Run("ReplaceFullPath", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:            URLRewriteReplaceFullPath,
					ReplaceFullPath: "/api/v2/users",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/old/path", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/v2/users", req.URL.Path)
	})

	t.Run("ReplacePrefixMatch - matching prefix", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:               URLRewriteReplacePrefixMatch,
					PrefixToMatch:      "/api/v1",
					ReplacePrefixMatch: "/api/v2",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/v2/users", req.URL.Path)
	})

	t.Run("ReplacePrefixMatch - non-matching prefix", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:               URLRewriteReplacePrefixMatch,
					PrefixToMatch:      "/api/v1",
					ReplacePrefixMatch: "/api/v2",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/other/path", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/other/path", req.URL.Path)
	})

	t.Run("Regex replacement", func(t *testing.T) {
		pattern := regexp.MustCompile(`/users/(\d+)`)
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:        URLRewriteRegex,
					Pattern:     pattern,
					Replacement: "/api/users/$1",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/users/123", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/users/123", req.URL.Path)
	})

	t.Run("Regex replacement with nil pattern", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:        URLRewriteRegex,
					Pattern:     nil,
					Replacement: "/api/users/$1",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/users/123", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/users/123", req.URL.Path)
	})

	t.Run("multiple rules", func(t *testing.T) {
		pattern := regexp.MustCompile(`/v1/`)
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:               URLRewriteReplacePrefixMatch,
					PrefixToMatch:      "/api",
					ReplacePrefixMatch: "/service",
				},
				{
					Type:        URLRewriteRegex,
					Pattern:     pattern,
					Replacement: "/v2/",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/service/v2/users", req.URL.Path)
	})

	t.Run("empty rules", func(t *testing.T) {
		rewriter := &URLRewriter{rules: []*URLRewriteRule{}}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/users", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/users", req.URL.Path)
	})

	t.Run("unknown rule type", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type: URLRewriteType("Unknown"),
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/users", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/api/users", req.URL.Path)
	})
}

// =============================================================================
// URLRewriter.AddRule Tests
// =============================================================================

func TestURLRewriter_AddRule(t *testing.T) {
	t.Run("adds rule", func(t *testing.T) {
		rewriter := &URLRewriter{rules: make([]*URLRewriteRule, 0)}
		rule := &URLRewriteRule{
			Type:            URLRewriteReplaceFullPath,
			ReplaceFullPath: "/new/path",
		}

		rewriter.AddRule(rule)

		assert.Len(t, rewriter.rules, 1)
		assert.Equal(t, rule, rewriter.rules[0])
	})

	t.Run("adds multiple rules", func(t *testing.T) {
		rewriter := &URLRewriter{rules: make([]*URLRewriteRule, 0)}
		rule1 := &URLRewriteRule{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/path1"}
		rule2 := &URLRewriteRule{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/path2"}

		rewriter.AddRule(rule1)
		rewriter.AddRule(rule2)

		assert.Len(t, rewriter.rules, 2)
		assert.Equal(t, rule1, rewriter.rules[0])
		assert.Equal(t, rule2, rewriter.rules[1])
	})
}

// =============================================================================
// URLRewriter.ClearRules Tests
// =============================================================================

func TestURLRewriter_ClearRules(t *testing.T) {
	t.Run("clears all rules", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/path1"},
				{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/path2"},
			},
		}

		rewriter.ClearRules()

		assert.NotNil(t, rewriter.rules)
		assert.Empty(t, rewriter.rules)
	})

	t.Run("clears empty rules", func(t *testing.T) {
		rewriter := &URLRewriter{rules: []*URLRewriteRule{}}

		rewriter.ClearRules()

		assert.NotNil(t, rewriter.rules)
		assert.Empty(t, rewriter.rules)
	})
}

// =============================================================================
// HeaderModifier.Modify Tests
// =============================================================================

func TestHeaderModifier_Modify(t *testing.T) {
	t.Run("removes headers first", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{"X-Remove-Me"},
		}

		header := http.Header{}
		header.Set("X-Remove-Me", "value")
		header.Set("X-Keep-Me", "value")

		modifier.Modify(header)

		assert.Empty(t, header.Get("X-Remove-Me"))
		assert.Equal(t, "value", header.Get("X-Keep-Me"))
	})

	t.Run("sets headers - overwrites existing", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{"X-Custom": "new-value"},
			add:    map[string]string{},
			remove: []string{},
		}

		header := http.Header{}
		header.Set("X-Custom", "old-value")

		modifier.Modify(header)

		assert.Equal(t, "new-value", header.Get("X-Custom"))
	})

	t.Run("adds headers", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{},
			add:    map[string]string{"X-Added": "added-value"},
			remove: []string{},
		}

		header := http.Header{}
		header.Set("X-Added", "existing-value")

		modifier.Modify(header)

		values := header.Values("X-Added")
		assert.Len(t, values, 2)
		assert.Contains(t, values, "existing-value")
		assert.Contains(t, values, "added-value")
	})

	t.Run("all operations together", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{"X-Set": "set-value"},
			add:    map[string]string{"X-Add": "add-value"},
			remove: []string{"X-Remove"},
		}

		header := http.Header{}
		header.Set("X-Remove", "to-remove")
		header.Set("X-Set", "old-value")
		header.Set("X-Add", "existing")

		modifier.Modify(header)

		assert.Empty(t, header.Get("X-Remove"))
		assert.Equal(t, "set-value", header.Get("X-Set"))
		values := header.Values("X-Add")
		assert.Len(t, values, 2)
	})

	t.Run("empty modifier does nothing", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{},
		}

		header := http.Header{}
		header.Set("X-Existing", "value")

		modifier.Modify(header)

		assert.Equal(t, "value", header.Get("X-Existing"))
	})

	t.Run("nil maps are handled", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    nil,
			add:    nil,
			remove: nil,
		}

		header := http.Header{}
		header.Set("X-Existing", "value")

		modifier.Modify(header)

		assert.Equal(t, "value", header.Get("X-Existing"))
	})
}

// =============================================================================
// HeaderModifier.SetHeader Tests
// =============================================================================

func TestHeaderModifier_SetHeader(t *testing.T) {
	t.Run("sets header to be set", func(t *testing.T) {
		modifier := &HeaderModifier{
			set: make(map[string]string),
			add: make(map[string]string),
		}

		modifier.SetHeader("X-Custom", "value")

		assert.Equal(t, "value", modifier.set["X-Custom"])
	})

	t.Run("overwrites existing set header", func(t *testing.T) {
		modifier := &HeaderModifier{
			set: map[string]string{"X-Custom": "old-value"},
			add: make(map[string]string),
		}

		modifier.SetHeader("X-Custom", "new-value")

		assert.Equal(t, "new-value", modifier.set["X-Custom"])
	})
}

// =============================================================================
// HeaderModifier.AddHeader Tests
// =============================================================================

func TestHeaderModifier_AddHeader(t *testing.T) {
	t.Run("adds header to be added", func(t *testing.T) {
		modifier := &HeaderModifier{
			set: make(map[string]string),
			add: make(map[string]string),
		}

		modifier.AddHeader("X-Custom", "value")

		assert.Equal(t, "value", modifier.add["X-Custom"])
	})

	t.Run("overwrites existing add header", func(t *testing.T) {
		modifier := &HeaderModifier{
			set: make(map[string]string),
			add: map[string]string{"X-Custom": "old-value"},
		}

		modifier.AddHeader("X-Custom", "new-value")

		assert.Equal(t, "new-value", modifier.add["X-Custom"])
	})
}

// =============================================================================
// HeaderModifier.RemoveHeader Tests
// =============================================================================

func TestHeaderModifier_RemoveHeader(t *testing.T) {
	t.Run("adds header to be removed", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    make(map[string]string),
			add:    make(map[string]string),
			remove: []string{},
		}

		modifier.RemoveHeader("X-Remove")

		assert.Contains(t, modifier.remove, "X-Remove")
	})

	t.Run("adds multiple headers to be removed", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    make(map[string]string),
			add:    make(map[string]string),
			remove: []string{},
		}

		modifier.RemoveHeader("X-Remove-1")
		modifier.RemoveHeader("X-Remove-2")

		assert.Len(t, modifier.remove, 2)
		assert.Contains(t, modifier.remove, "X-Remove-1")
		assert.Contains(t, modifier.remove, "X-Remove-2")
	})
}

// =============================================================================
// HeaderModifier.Clear Tests
// =============================================================================

func TestHeaderModifier_Clear(t *testing.T) {
	t.Run("clears all modifications", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{"X-Set": "value"},
			add:    map[string]string{"X-Add": "value"},
			remove: []string{"X-Remove"},
		}

		modifier.Clear()

		assert.NotNil(t, modifier.set)
		assert.Empty(t, modifier.set)
		assert.NotNil(t, modifier.add)
		assert.Empty(t, modifier.add)
		assert.Nil(t, modifier.remove)
	})

	t.Run("clears empty modifier", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{},
		}

		modifier.Clear()

		assert.NotNil(t, modifier.set)
		assert.Empty(t, modifier.set)
		assert.NotNil(t, modifier.add)
		assert.Empty(t, modifier.add)
		assert.Nil(t, modifier.remove)
	})
}

// =============================================================================
// QueryModifier.Modify Tests
// =============================================================================

func TestQueryModifier_Modify(t *testing.T) {
	t.Run("removes parameters first", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{"remove-param"},
		}

		u, _ := url.Parse("http://example.com/api?remove-param=value&keep-param=value")

		modifier.Modify(u)

		assert.Empty(t, u.Query().Get("remove-param"))
		assert.Equal(t, "value", u.Query().Get("keep-param"))
	})

	t.Run("sets parameters - overwrites existing", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{"param": "new-value"},
			add:    map[string]string{},
			remove: []string{},
		}

		u, _ := url.Parse("http://example.com/api?param=old-value")

		modifier.Modify(u)

		assert.Equal(t, "new-value", u.Query().Get("param"))
	})

	t.Run("adds parameters", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{},
			add:    map[string]string{"add-param": "add-value"},
			remove: []string{},
		}

		u, _ := url.Parse("http://example.com/api?add-param=existing")

		modifier.Modify(u)

		values := u.Query()["add-param"]
		assert.Len(t, values, 2)
		assert.Contains(t, values, "existing")
		assert.Contains(t, values, "add-value")
	})

	t.Run("all operations together", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{"set-param": "set-value"},
			add:    map[string]string{"add-param": "add-value"},
			remove: []string{"remove-param"},
		}

		u, _ := url.Parse("http://example.com/api?remove-param=old&set-param=old&add-param=existing")

		modifier.Modify(u)

		assert.Empty(t, u.Query().Get("remove-param"))
		assert.Equal(t, "set-value", u.Query().Get("set-param"))
		values := u.Query()["add-param"]
		assert.Len(t, values, 2)
	})

	t.Run("empty modifier does nothing", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{},
		}

		u, _ := url.Parse("http://example.com/api?existing=value")

		modifier.Modify(u)

		assert.Equal(t, "value", u.Query().Get("existing"))
	})

	t.Run("nil maps are handled", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    nil,
			add:    nil,
			remove: nil,
		}

		u, _ := url.Parse("http://example.com/api?existing=value")

		modifier.Modify(u)

		assert.Equal(t, "value", u.Query().Get("existing"))
	})
}

// =============================================================================
// QueryModifier.SetParam Tests
// =============================================================================

func TestQueryModifier_SetParam(t *testing.T) {
	t.Run("sets parameter to be set", func(t *testing.T) {
		modifier := &QueryModifier{
			set: make(map[string]string),
			add: make(map[string]string),
		}

		modifier.SetParam("param", "value")

		assert.Equal(t, "value", modifier.set["param"])
	})

	t.Run("overwrites existing set parameter", func(t *testing.T) {
		modifier := &QueryModifier{
			set: map[string]string{"param": "old-value"},
			add: make(map[string]string),
		}

		modifier.SetParam("param", "new-value")

		assert.Equal(t, "new-value", modifier.set["param"])
	})
}

// =============================================================================
// QueryModifier.AddParam Tests
// =============================================================================

func TestQueryModifier_AddParam(t *testing.T) {
	t.Run("adds parameter to be added", func(t *testing.T) {
		modifier := &QueryModifier{
			set: make(map[string]string),
			add: make(map[string]string),
		}

		modifier.AddParam("param", "value")

		assert.Equal(t, "value", modifier.add["param"])
	})

	t.Run("overwrites existing add parameter", func(t *testing.T) {
		modifier := &QueryModifier{
			set: make(map[string]string),
			add: map[string]string{"param": "old-value"},
		}

		modifier.AddParam("param", "new-value")

		assert.Equal(t, "new-value", modifier.add["param"])
	})
}

// =============================================================================
// QueryModifier.RemoveParam Tests
// =============================================================================

func TestQueryModifier_RemoveParam(t *testing.T) {
	t.Run("adds parameter to be removed", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    make(map[string]string),
			add:    make(map[string]string),
			remove: []string{},
		}

		modifier.RemoveParam("remove-param")

		assert.Contains(t, modifier.remove, "remove-param")
	})

	t.Run("adds multiple parameters to be removed", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    make(map[string]string),
			add:    make(map[string]string),
			remove: []string{},
		}

		modifier.RemoveParam("remove-1")
		modifier.RemoveParam("remove-2")

		assert.Len(t, modifier.remove, 2)
		assert.Contains(t, modifier.remove, "remove-1")
		assert.Contains(t, modifier.remove, "remove-2")
	})
}

// =============================================================================
// QueryModifier.Clear Tests
// =============================================================================

func TestQueryModifier_Clear(t *testing.T) {
	t.Run("clears all modifications", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{"set-param": "value"},
			add:    map[string]string{"add-param": "value"},
			remove: []string{"remove-param"},
		}

		modifier.Clear()

		assert.NotNil(t, modifier.set)
		assert.Empty(t, modifier.set)
		assert.NotNil(t, modifier.add)
		assert.Empty(t, modifier.add)
		assert.Nil(t, modifier.remove)
	})

	t.Run("clears empty modifier", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{},
			add:    map[string]string{},
			remove: []string{},
		}

		modifier.Clear()

		assert.NotNil(t, modifier.set)
		assert.Empty(t, modifier.set)
		assert.NotNil(t, modifier.add)
		assert.Empty(t, modifier.add)
		assert.Nil(t, modifier.remove)
	})
}

// =============================================================================
// RewritePath Tests
// =============================================================================

func TestRewritePath(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		rewriteType   URLRewriteType
		fullPath      string
		prefixMatch   string
		prefixToMatch string
		expected      string
	}{
		{
			name:        "ReplaceFullPath",
			path:        "/old/path",
			rewriteType: URLRewriteReplaceFullPath,
			fullPath:    "/new/path",
			expected:    "/new/path",
		},
		{
			name:          "ReplacePrefixMatch - matching",
			path:          "/api/v1/users",
			rewriteType:   URLRewriteReplacePrefixMatch,
			prefixMatch:   "/api/v2",
			prefixToMatch: "/api/v1",
			expected:      "/api/v2/users",
		},
		{
			name:          "ReplacePrefixMatch - non-matching",
			path:          "/other/path",
			rewriteType:   URLRewriteReplacePrefixMatch,
			prefixMatch:   "/api/v2",
			prefixToMatch: "/api/v1",
			expected:      "/other/path",
		},
		{
			name:        "unknown type returns original",
			path:        "/original/path",
			rewriteType: URLRewriteType("Unknown"),
			expected:    "/original/path",
		},
		{
			name:        "ReplaceFullPath with empty fullPath",
			path:        "/old/path",
			rewriteType: URLRewriteReplaceFullPath,
			fullPath:    "",
			expected:    "",
		},
		{
			name:          "ReplacePrefixMatch with empty prefix",
			path:          "/api/v1/users",
			rewriteType:   URLRewriteReplacePrefixMatch,
			prefixMatch:   "",
			prefixToMatch: "/api/v1",
			expected:      "/users",
		},
		{
			name:          "ReplacePrefixMatch - exact match",
			path:          "/api/v1",
			rewriteType:   URLRewriteReplacePrefixMatch,
			prefixMatch:   "/api/v2",
			prefixToMatch: "/api/v1",
			expected:      "/api/v2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RewritePath(tt.path, tt.rewriteType, tt.fullPath, tt.prefixMatch, tt.prefixToMatch)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// StripPrefix Tests
// =============================================================================

func TestStripPrefix(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected string
	}{
		{
			name:     "strips matching prefix",
			path:     "/api/v1/users",
			prefix:   "/api/v1",
			expected: "/users",
		},
		{
			name:     "returns / for empty result",
			path:     "/api",
			prefix:   "/api",
			expected: "/",
		},
		{
			name:     "adds leading slash if missing",
			path:     "/api/users",
			prefix:   "/api/",
			expected: "/users",
		},
		{
			name:     "non-matching prefix returns original",
			path:     "/other/path",
			prefix:   "/api",
			expected: "/other/path",
		},
		{
			name:     "empty prefix returns original",
			path:     "/api/users",
			prefix:   "",
			expected: "/api/users",
		},
		{
			name:     "empty path with matching prefix",
			path:     "",
			prefix:   "",
			expected: "/",
		},
		{
			name:     "path equals prefix",
			path:     "/api",
			prefix:   "/api",
			expected: "/",
		},
		{
			name:     "prefix longer than path",
			path:     "/api",
			prefix:   "/api/v1/users",
			expected: "/api",
		},
		{
			name:     "strips prefix and adds slash",
			path:     "/prefix/path",
			prefix:   "/prefix/",
			expected: "/path",
		},
		{
			name:     "strips prefix without trailing slash",
			path:     "/prefixpath",
			prefix:   "/prefix",
			expected: "/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripPrefix(tt.path, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// AddPrefix Tests
// =============================================================================

func TestAddPrefix(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		prefix   string
		expected string
	}{
		{
			name:     "empty prefix returns original",
			path:     "/users",
			prefix:   "",
			expected: "/users",
		},
		{
			name:     "handles trailing/leading slashes correctly - both have slash",
			path:     "/users",
			prefix:   "/api/",
			expected: "/api/users",
		},
		{
			name:     "adds slash between prefix and path - neither has slash",
			path:     "users",
			prefix:   "/api",
			expected: "/api/users",
		},
		{
			name:     "prefix with trailing slash, path without leading slash",
			path:     "users",
			prefix:   "/api/",
			expected: "/api/users",
		},
		{
			name:     "prefix without trailing slash, path with leading slash",
			path:     "/users",
			prefix:   "/api",
			expected: "/api/users",
		},
		{
			name:     "empty path with prefix",
			path:     "",
			prefix:   "/api",
			expected: "/api/",
		},
		{
			name:     "root path with prefix",
			path:     "/",
			prefix:   "/api",
			expected: "/api/",
		},
		{
			name:     "prefix with trailing slash and root path",
			path:     "/",
			prefix:   "/api/",
			expected: "/api/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AddPrefix(tt.path, tt.prefix)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// URLRewriteType Constants Tests
// =============================================================================

func TestURLRewriteTypeConstants(t *testing.T) {
	t.Run("constants have expected values", func(t *testing.T) {
		assert.Equal(t, URLRewriteType("ReplaceFullPath"), URLRewriteReplaceFullPath)
		assert.Equal(t, URLRewriteType("ReplacePrefixMatch"), URLRewriteReplacePrefixMatch)
		assert.Equal(t, URLRewriteType("Regex"), URLRewriteRegex)
	})
}

// =============================================================================
// Edge Cases Tests
// =============================================================================

func TestEdgeCases(t *testing.T) {
	t.Run("transform with nil URL", func(t *testing.T) {
		transformer := NewRequestTransformer()
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)

		err := transformer.Transform(req)

		assert.NoError(t, err)
	})

	t.Run("header modifier with case-insensitive headers", func(t *testing.T) {
		modifier := &HeaderModifier{
			set:    map[string]string{"content-type": "application/json"},
			add:    map[string]string{},
			remove: []string{"X-REMOVE"},
		}

		header := http.Header{}
		header.Set("Content-Type", "text/html")
		header.Set("x-remove", "value")

		modifier.Modify(header)

		// HTTP headers are case-insensitive
		assert.Equal(t, "application/json", header.Get("Content-Type"))
		assert.Empty(t, header.Get("X-Remove"))
	})

	t.Run("query modifier with special characters", func(t *testing.T) {
		modifier := &QueryModifier{
			set:    map[string]string{"param": "value with spaces"},
			add:    map[string]string{"special": "a=b&c=d"},
			remove: []string{},
		}

		u, _ := url.Parse("http://example.com/api")

		modifier.Modify(u)

		assert.Equal(t, "value with spaces", u.Query().Get("param"))
		assert.Equal(t, "a=b&c=d", u.Query().Get("special"))
	})

	t.Run("URL rewriter with complex regex", func(t *testing.T) {
		pattern := regexp.MustCompile(`/api/v(\d+)/users/(\d+)/posts/(\d+)`)
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:        URLRewriteRegex,
					Pattern:     pattern,
					Replacement: "/v$1/u/$2/p/$3",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v2/users/123/posts/456", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/v2/u/123/p/456", req.URL.Path)
	})

	t.Run("multiple prefix replacements", func(t *testing.T) {
		rewriter := &URLRewriter{
			rules: []*URLRewriteRule{
				{
					Type:               URLRewriteReplacePrefixMatch,
					PrefixToMatch:      "/api",
					ReplacePrefixMatch: "/service",
				},
				{
					Type:               URLRewriteReplacePrefixMatch,
					PrefixToMatch:      "/service/v1",
					ReplacePrefixMatch: "/service/v2",
				},
			},
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/v1/users", nil)
		err := rewriter.Rewrite(req)

		assert.NoError(t, err)
		assert.Equal(t, "/service/v2/users", req.URL.Path)
	})
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkRequestTransformer_Transform(b *testing.B) {
	transformer := NewRequestTransformer()
	transformer.SetURLRewriteRules([]*URLRewriteRule{
		{Type: URLRewriteReplaceFullPath, ReplaceFullPath: "/api/v2/users"},
	})
	transformer.SetHeaderModifications(
		map[string]string{"Content-Type": "application/json"},
		map[string]string{"X-Request-ID": "12345"},
		[]string{"X-Old-Header"},
	)
	transformer.SetQueryModifications(
		map[string]string{"version": "2"},
		map[string]string{"format": "json"},
		[]string{"old-param"},
	)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/old/path?old-param=value", nil)
		req.Header.Set("X-Old-Header", "old-value")
		_ = transformer.Transform(req)
	}
}

func BenchmarkURLRewriter_Rewrite_Regex(b *testing.B) {
	pattern := regexp.MustCompile(`/users/(\d+)`)
	rewriter := &URLRewriter{
		rules: []*URLRewriteRule{
			{
				Type:        URLRewriteRegex,
				Pattern:     pattern,
				Replacement: "/api/users/$1",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/users/123", nil)
		_ = rewriter.Rewrite(req)
	}
}

func BenchmarkHeaderModifier_Modify(b *testing.B) {
	modifier := &HeaderModifier{
		set:    map[string]string{"X-Set-1": "v1", "X-Set-2": "v2", "X-Set-3": "v3"},
		add:    map[string]string{"X-Add-1": "v1", "X-Add-2": "v2"},
		remove: []string{"X-Remove-1", "X-Remove-2"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := http.Header{}
		header.Set("X-Remove-1", "value")
		header.Set("X-Remove-2", "value")
		modifier.Modify(header)
	}
}

func BenchmarkQueryModifier_Modify(b *testing.B) {
	modifier := &QueryModifier{
		set:    map[string]string{"set1": "v1", "set2": "v2", "set3": "v3"},
		add:    map[string]string{"add1": "v1", "add2": "v2"},
		remove: []string{"remove1", "remove2"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		u, _ := url.Parse("http://example.com/api?remove1=v&remove2=v&existing=v")
		modifier.Modify(u)
	}
}

func BenchmarkStripPrefix(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StripPrefix("/api/v1/users/123/posts", "/api/v1")
	}
}

func BenchmarkAddPrefix(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AddPrefix("/users/123/posts", "/api/v2")
	}
}

func BenchmarkRewritePath(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RewritePath("/api/v1/users", URLRewriteReplacePrefixMatch, "", "/api/v2", "/api/v1")
	}
}
