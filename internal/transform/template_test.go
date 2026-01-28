// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

func TestNewTemplateEngine(t *testing.T) {
	tests := []struct {
		name   string
		logger observability.Logger
		opts   []TemplateEngineOption
	}{
		{
			name:   "with nil logger",
			logger: nil,
		},
		{
			name:   "with nop logger",
			logger: observability.NopLogger(),
		},
		{
			name:   "with cache option",
			logger: observability.NopLogger(),
			opts:   []TemplateEngineOption{WithTemplateCache(500)},
		},
		{
			name:   "with custom funcs",
			logger: observability.NopLogger(),
			opts: []TemplateEngineOption{
				WithTemplateFuncs(template.FuncMap{
					"custom": func() string { return "custom" },
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewTemplateEngine(tt.logger, tt.opts...)
			require.NotNil(t, engine)
		})
	}
}

func TestTemplateEngine_Execute(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		expectErr   bool
		checkString bool
	}{
		{
			name:     "empty template returns data",
			template: "",
			data:     map[string]interface{}{"name": "test"},
			expected: map[string]interface{}{"name": "test"},
		},
		{
			name:        "simple string template",
			template:    "Hello, {{.name}}!",
			data:        map[string]interface{}{"name": "World"},
			expected:    "Hello, World!",
			checkString: true,
		},
		{
			name:     "JSON output template",
			template: `{"greeting": "Hello, {{.name}}!"}`,
			data:     map[string]interface{}{"name": "World"},
			expected: map[string]interface{}{"greeting": "Hello, World!"},
		},
		{
			name:     "template with nested data",
			template: `{"user": "{{.user.name}}"}`,
			data: map[string]interface{}{
				"user": map[string]interface{}{
					"name": "John",
				},
			},
			expected: map[string]interface{}{"user": "John"},
		},
		{
			name:      "invalid template syntax",
			template:  "{{.name",
			data:      map[string]interface{}{"name": "test"},
			expectErr: true,
		},
		{
			name:        "template with missing field",
			template:    "Hello, {{.missing}}!",
			data:        map[string]interface{}{"name": "test"},
			expected:    "Hello, <no value>!",
			checkString: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			} else {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTemplateEngine_BuiltInFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		checkString bool
	}{
		{
			name:        "upper function",
			template:    `{{upper .name}}`,
			data:        map[string]interface{}{"name": "test"},
			expected:    "TEST",
			checkString: true,
		},
		{
			name:        "lower function",
			template:    `{{lower .name}}`,
			data:        map[string]interface{}{"name": "TEST"},
			expected:    "test",
			checkString: true,
		},
		{
			name:        "trim function",
			template:    `{{trim .name}}`,
			data:        map[string]interface{}{"name": "  test  "},
			expected:    "test",
			checkString: true,
		},
		{
			name:        "replace function",
			template:    `{{replace .name "old" "new"}}`,
			data:        map[string]interface{}{"name": "old value"},
			expected:    "new value",
			checkString: true,
		},
		{
			name:        "contains function",
			template:    `{{if contains .name "test"}}yes{{else}}no{{end}}`,
			data:        map[string]interface{}{"name": "test value"},
			expected:    "yes",
			checkString: true,
		},
		{
			name:        "hasPrefix function",
			template:    `{{if hasPrefix .name "test"}}yes{{else}}no{{end}}`,
			data:        map[string]interface{}{"name": "test value"},
			expected:    "yes",
			checkString: true,
		},
		{
			name:        "hasSuffix function",
			template:    `{{if hasSuffix .name "value"}}yes{{else}}no{{end}}`,
			data:        map[string]interface{}{"name": "test value"},
			expected:    "yes",
			checkString: true,
		},
		{
			name:        "toString function",
			template:    `{{toString .num}}`,
			data:        map[string]interface{}{"num": 123},
			expected:    float64(123), // JSON unmarshaling converts "123" to float64
			checkString: false,
		},
		{
			name:        "default function",
			template:    `{{default "default" .missing}}`,
			data:        map[string]interface{}{},
			expected:    "default",
			checkString: true,
		},
		{
			name:        "default function with value",
			template:    `{{default "default" .name}}`,
			data:        map[string]interface{}{"name": "actual"},
			expected:    "actual",
			checkString: true,
		},
		{
			name:        "ternary function true",
			template:    `{{ternary true "yes" "no"}}`,
			data:        map[string]interface{}{},
			expected:    "yes",
			checkString: true,
		},
		{
			name:        "ternary function false",
			template:    `{{ternary false "yes" "no"}}`,
			data:        map[string]interface{}{},
			expected:    "no",
			checkString: true,
		},
		{
			name:        "eq function true",
			template:    `{{if eq .a .b}}equal{{else}}not equal{{end}}`,
			data:        map[string]interface{}{"a": "test", "b": "test"},
			expected:    "equal",
			checkString: true,
		},
		{
			name:        "eq function false",
			template:    `{{if eq .a .b}}equal{{else}}not equal{{end}}`,
			data:        map[string]interface{}{"a": "test", "b": "other"},
			expected:    "not equal",
			checkString: true,
		},
		{
			name:        "ne function",
			template:    `{{if ne .a .b}}different{{else}}same{{end}}`,
			data:        map[string]interface{}{"a": "test", "b": "other"},
			expected:    "different",
			checkString: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)

			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			} else if tt.expected != nil {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTemplateEngine_JSONFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		contains    string
		checkString bool
	}{
		{
			name:        "json function",
			template:    `{{json .data}}`,
			data:        map[string]interface{}{"data": map[string]interface{}{"key": "value"}},
			contains:    `"key":"value"`,
			checkString: true,
		},
		{
			name:        "jsonPretty function",
			template:    `{{jsonPretty .data}}`,
			data:        map[string]interface{}{"data": map[string]interface{}{"key": "value"}},
			contains:    "key",
			checkString: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)

			if tt.checkString {
				// Result could be a string or a parsed JSON object
				switch v := result.(type) {
				case string:
					assert.Contains(t, v, tt.contains)
				case map[string]interface{}:
					// jsonPretty returns valid JSON which gets parsed back
					// Check that the expected key exists
					assert.Contains(t, v, "key")
				default:
					t.Errorf("unexpected result type: %T", result)
				}
			}
		})
	}
}

func TestTemplateEngine_CollectionFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		checkString bool
	}{
		{
			name:        "get function",
			template:    `{{get .data "key"}}`,
			data:        map[string]interface{}{"data": map[string]interface{}{"key": "value"}},
			expected:    "value",
			checkString: true,
		},
		{
			name:        "first function",
			template:    `{{first .items}}`,
			data:        map[string]interface{}{"items": []interface{}{"a", "b", "c"}},
			expected:    "a",
			checkString: true,
		},
		{
			name:        "last function",
			template:    `{{last .items}}`,
			data:        map[string]interface{}{"items": []interface{}{"a", "b", "c"}},
			expected:    "c",
			checkString: true,
		},
		{
			name:        "len function with array",
			template:    `{{len .items}}`,
			data:        map[string]interface{}{"items": []interface{}{"a", "b", "c"}},
			expected:    float64(3), // JSON unmarshaling converts numbers to float64
			checkString: false,
		},
		{
			name:        "len function with string",
			template:    `{{len .name}}`,
			data:        map[string]interface{}{"name": "test"},
			expected:    float64(4), // JSON unmarshaling converts numbers to float64
			checkString: false,
		},
		{
			name:        "len function with map",
			template:    `{{len .data}}`,
			data:        map[string]interface{}{"data": map[string]interface{}{"a": 1, "b": 2}},
			expected:    float64(2), // JSON unmarshaling converts numbers to float64
			checkString: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)

			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			} else if tt.expected != nil {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTemplateEngine_DictAndListFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name     string
		template string
		data     interface{}
	}{
		{
			name:     "dict function",
			template: `{{$d := dict "key1" "value1" "key2" "value2"}}{{get $d "key1"}}`,
			data:     map[string]interface{}{},
		},
		{
			name:     "list function",
			template: `{{$l := list "a" "b" "c"}}{{first $l}}`,
			data:     map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func TestTemplateEngine_ConversionFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name     string
		template string
		data     interface{}
	}{
		{
			name:     "toInt from int",
			template: `{{toInt .num}}`,
			data:     map[string]interface{}{"num": 123},
		},
		{
			name:     "toInt from int64",
			template: `{{toInt .num}}`,
			data:     map[string]interface{}{"num": int64(123)},
		},
		{
			name:     "toInt from float64",
			template: `{{toInt .num}}`,
			data:     map[string]interface{}{"num": 123.5},
		},
		{
			name:     "toInt from string",
			template: `{{toInt .num}}`,
			data:     map[string]interface{}{"num": "123"},
		},
		{
			name:     "toFloat from float64",
			template: `{{toFloat .num}}`,
			data:     map[string]interface{}{"num": 123.5},
		},
		{
			name:     "toFloat from int",
			template: `{{toFloat .num}}`,
			data:     map[string]interface{}{"num": 123},
		},
		{
			name:     "toFloat from string",
			template: `{{toFloat .num}}`,
			data:     map[string]interface{}{"num": "123.5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func TestTemplateEngine_Caching(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger(), WithTemplateCache(10))

	template := `Hello, {{.name}}!`
	data := map[string]interface{}{"name": "World"}

	// Execute multiple times - should use cache
	for i := 0; i < 5; i++ {
		result, err := engine.Execute(template, data)
		require.NoError(t, err)
		assert.Equal(t, "Hello, World!", result)
	}
}

func TestTemplateEngine_CacheLimit(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger(), WithTemplateCache(2))

	data := map[string]interface{}{"name": "World"}

	// Execute with different templates to exceed cache limit
	templates := []string{
		`Template 1: {{.name}}`,
		`Template 2: {{.name}}`,
		`Template 3: {{.name}}`,
	}

	for _, tmpl := range templates {
		result, err := engine.Execute(tmpl, data)
		require.NoError(t, err)
		assert.Contains(t, result, "World")
	}
}

func TestExecuteTemplate(t *testing.T) {
	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		expectErr   bool
		checkString bool
	}{
		{
			name:        "simple template",
			template:    "Hello, {{.name}}!",
			data:        map[string]interface{}{"name": "World"},
			expected:    "Hello, World!",
			checkString: true,
		},
		{
			name:      "invalid template",
			template:  "{{.name",
			data:      map[string]interface{}{"name": "test"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ExecuteTemplate(tt.template, tt.data, observability.NopLogger())

			if tt.expectErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestCoalesceFunction(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		checkString bool
	}{
		{
			name:        "coalesce returns first non-nil",
			template:    `{{coalesce .a .b .c}}`,
			data:        map[string]interface{}{"a": nil, "b": "value", "c": "other"},
			expected:    "value",
			checkString: true,
		},
		{
			name:        "coalesce skips empty strings",
			template:    `{{coalesce .a .b .c}}`,
			data:        map[string]interface{}{"a": "", "b": "", "c": "value"},
			expected:    "value",
			checkString: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestStringFunctions(t *testing.T) {
	engine := NewTemplateEngine(observability.NopLogger())

	tests := []struct {
		name        string
		template    string
		data        interface{}
		expected    interface{}
		checkString bool
	}{
		{
			name:        "split function",
			template:    `{{index (split .str ",") 0}}`,
			data:        map[string]interface{}{"str": "a,b,c"},
			expected:    "a",
			checkString: true,
		},
		{
			name:        "join function",
			template:    `{{join .items ","}}`,
			data:        map[string]interface{}{"items": []string{"a", "b", "c"}},
			expected:    "a,b,c",
			checkString: true,
		},
		{
			name:        "trimPrefix function",
			template:    `{{trimPrefix .str "prefix_"}}`,
			data:        map[string]interface{}{"str": "prefix_value"},
			expected:    "value",
			checkString: true,
		},
		{
			name:        "trimSuffix function",
			template:    `{{trimSuffix .str "_suffix"}}`,
			data:        map[string]interface{}{"str": "value_suffix"},
			expected:    "value",
			checkString: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Execute(tt.template, tt.data)
			require.NoError(t, err)
			if tt.checkString {
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestSetMapValueFunction(t *testing.T) {
	result := setMapValue(
		map[string]interface{}{"existing": "value"},
		"new",
		"newValue",
	)

	assert.Equal(t, "value", result["existing"])
	assert.Equal(t, "newValue", result["new"])
}

func TestGetMapKeysFunction(t *testing.T) {
	keys := getMapKeys(map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	})

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, "a")
	assert.Contains(t, keys, "b")
	assert.Contains(t, keys, "c")
}

func TestGetMapValuesFunction(t *testing.T) {
	values := getMapValues(map[string]interface{}{
		"a": 1,
		"b": 2,
		"c": 3,
	})

	assert.Len(t, values, 3)
	assert.Contains(t, values, 1)
	assert.Contains(t, values, 2)
	assert.Contains(t, values, 3)
}

func TestGetFirstFunction(t *testing.T) {
	tests := []struct {
		name     string
		arr      []interface{}
		expected interface{}
	}{
		{
			name:     "non-empty array",
			arr:      []interface{}{"a", "b", "c"},
			expected: "a",
		},
		{
			name:     "empty array",
			arr:      []interface{}{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFirst(tt.arr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetLastFunction(t *testing.T) {
	tests := []struct {
		name     string
		arr      []interface{}
		expected interface{}
	}{
		{
			name:     "non-empty array",
			arr:      []interface{}{"a", "b", "c"},
			expected: "c",
		},
		{
			name:     "empty array",
			arr:      []interface{}{},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLast(tt.arr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetLenFunction(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected int
	}{
		{
			name:     "string",
			value:    "test",
			expected: 4,
		},
		{
			name:     "array",
			value:    []interface{}{"a", "b", "c"},
			expected: 3,
		},
		{
			name:     "map",
			value:    map[string]interface{}{"a": 1, "b": 2},
			expected: 2,
		},
		{
			name:     "unsupported type",
			value:    123,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getLen(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMakeDictFunction(t *testing.T) {
	tests := []struct {
		name     string
		pairs    []interface{}
		expected map[string]interface{}
	}{
		{
			name:  "simple dict",
			pairs: []interface{}{"key1", "value1", "key2", "value2"},
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name:     "empty dict",
			pairs:    []interface{}{},
			expected: map[string]interface{}{},
		},
		{
			name:     "odd number of pairs - last ignored",
			pairs:    []interface{}{"key1", "value1", "key2"},
			expected: map[string]interface{}{"key1": "value1"},
		},
		{
			name:     "non-string key - ignored",
			pairs:    []interface{}{123, "value1", "key2", "value2"},
			expected: map[string]interface{}{"key2": "value2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := makeDict(tt.pairs...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToIntFunction(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected int
	}{
		{name: "int", value: 123, expected: 123},
		{name: "int64", value: int64(456), expected: 456},
		{name: "float64", value: 78.9, expected: 78},
		{name: "string", value: "42", expected: 42},
		{name: "invalid string", value: "abc", expected: 0},
		{name: "unsupported type", value: true, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toInt(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestToFloatFunction(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected float64
	}{
		{name: "float64", value: 123.45, expected: 123.45},
		{name: "int", value: 123, expected: 123.0},
		{name: "int64", value: int64(456), expected: 456.0},
		{name: "string", value: "78.9", expected: 78.9},
		{name: "invalid string", value: "abc", expected: 0},
		{name: "unsupported type", value: true, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toFloat(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultValueFunction(t *testing.T) {
	tests := []struct {
		name       string
		defaultVal interface{}
		val        interface{}
		expected   interface{}
	}{
		{name: "nil value", defaultVal: "default", val: nil, expected: "default"},
		{name: "empty string", defaultVal: "default", val: "", expected: "default"},
		{name: "non-empty value", defaultVal: "default", val: "actual", expected: "actual"},
		{name: "zero int", defaultVal: 10, val: 0, expected: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := defaultValue(tt.defaultVal, tt.val)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTernaryFunction(t *testing.T) {
	tests := []struct {
		name      string
		condition bool
		trueVal   interface{}
		falseVal  interface{}
		expected  interface{}
	}{
		{name: "true condition", condition: true, trueVal: "yes", falseVal: "no", expected: "yes"},
		{name: "false condition", condition: false, trueVal: "yes", falseVal: "no", expected: "no"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ternary(tt.condition, tt.trueVal, tt.falseVal)
			assert.Equal(t, tt.expected, result)
		})
	}
}
