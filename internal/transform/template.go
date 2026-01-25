// Package transform provides data transformation capabilities for the API Gateway.
package transform

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/vyrodovalexey/avapigw/internal/observability"
)

// templateEngine implements the TemplateEngine interface.
type templateEngine struct {
	logger    observability.Logger
	cache     map[string]*template.Template
	cacheMu   sync.RWMutex
	funcMap   template.FuncMap
	maxCached int
}

// TemplateEngineOption is a functional option for configuring the template engine.
type TemplateEngineOption func(*templateEngine)

// WithTemplateCache sets the maximum number of cached templates.
func WithTemplateCache(maxCached int) TemplateEngineOption {
	return func(te *templateEngine) {
		te.maxCached = maxCached
	}
}

// WithTemplateFuncs adds custom template functions.
func WithTemplateFuncs(funcs template.FuncMap) TemplateEngineOption {
	return func(te *templateEngine) {
		for k, v := range funcs {
			te.funcMap[k] = v
		}
	}
}

// NewTemplateEngine creates a new TemplateEngine instance.
func NewTemplateEngine(logger observability.Logger, opts ...TemplateEngineOption) TemplateEngine {
	if logger == nil {
		logger = observability.NopLogger()
	}

	te := &templateEngine{
		logger:    logger,
		cache:     make(map[string]*template.Template),
		funcMap:   defaultTemplateFuncs(),
		maxCached: 1000,
	}

	for _, opt := range opts {
		opt(te)
	}

	return te
}

// Execute executes a template with the given data.
func (te *templateEngine) Execute(templateStr string, data interface{}) (interface{}, error) {
	if templateStr == "" {
		return data, nil
	}

	// Get or create the template
	tmpl, err := te.getOrCreateTemplate(templateStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTemplateExecution, err)
	}

	// Execute the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		te.logger.Error("template execution failed",
			observability.Error(err))
		return nil, fmt.Errorf("%w: %w", ErrTemplateExecution, err)
	}

	// Try to parse the result as JSON
	result := buf.String()
	var parsed interface{}
	if err := json.Unmarshal([]byte(result), &parsed); err == nil {
		te.logger.Debug("template executed successfully",
			observability.Int("outputLength", len(result)))
		return parsed, nil
	}

	// Return as string if not valid JSON (this is expected behavior, not an error)
	return result, nil
}

// getOrCreateTemplate gets a cached template or creates a new one.
func (te *templateEngine) getOrCreateTemplate(templateStr string) (*template.Template, error) {
	// Check cache first
	te.cacheMu.RLock()
	if tmpl, exists := te.cache[templateStr]; exists {
		te.cacheMu.RUnlock()
		return tmpl, nil
	}
	te.cacheMu.RUnlock()

	// Create new template
	tmpl, err := template.New("transform").Funcs(te.funcMap).Parse(templateStr)
	if err != nil {
		return nil, err
	}

	// Cache the template
	te.cacheMu.Lock()
	if len(te.cache) < te.maxCached {
		te.cache[templateStr] = tmpl
	}
	te.cacheMu.Unlock()

	return tmpl, nil
}

// defaultTemplateFuncs returns the default template functions.
func defaultTemplateFuncs() template.FuncMap {
	funcs := make(template.FuncMap)

	// Add all function groups
	addJSONFuncs(funcs)
	addStringFuncs(funcs)
	addConversionFuncs(funcs)
	addCollectionFuncs(funcs)
	addConditionalFuncs(funcs)
	addComparisonFuncs(funcs)
	addUtilityFuncs(funcs)

	return funcs
}

// addJSONFuncs adds JSON-related template functions.
func addJSONFuncs(funcs template.FuncMap) {
	funcs["json"] = func(v interface{}) string {
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
	funcs["jsonPretty"] = func(v interface{}) string {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// addStringFuncs adds string manipulation template functions.
func addStringFuncs(funcs template.FuncMap) {
	funcs["upper"] = strings.ToUpper
	funcs["lower"] = strings.ToLower
	funcs["title"] = cases.Title(language.English).String
	funcs["trim"] = strings.TrimSpace
	funcs["trimPrefix"] = strings.TrimPrefix
	funcs["trimSuffix"] = strings.TrimSuffix
	funcs["replace"] = strings.ReplaceAll
	funcs["split"] = strings.Split
	funcs["join"] = strings.Join
	funcs["contains"] = strings.Contains
	funcs["hasPrefix"] = strings.HasPrefix
	funcs["hasSuffix"] = strings.HasSuffix
}

// addConversionFuncs adds type conversion template functions.
func addConversionFuncs(funcs template.FuncMap) {
	funcs["toString"] = func(v interface{}) string {
		return fmt.Sprintf("%v", v)
	}
	funcs["toInt"] = toInt
	funcs["toFloat"] = toFloat
}

// toInt converts a value to int.
func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	case string:
		i, _ := strconv.Atoi(val)
		return i
	default:
		return 0
	}
}

// toFloat converts a value to float64.
func toFloat(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

// addCollectionFuncs adds collection manipulation template functions.
func addCollectionFuncs(funcs template.FuncMap) {
	funcs["get"] = func(m map[string]interface{}, key string) interface{} {
		return m[key]
	}
	funcs["set"] = setMapValue
	funcs["keys"] = getMapKeys
	funcs["values"] = getMapValues
	funcs["first"] = getFirst
	funcs["last"] = getLast
	funcs["len"] = getLen
}

func setMapValue(m map[string]interface{}, key string, value interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	result[key] = value
	return result
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func getMapValues(m map[string]interface{}) []interface{} {
	values := make([]interface{}, 0, len(m))
	for _, v := range m {
		values = append(values, v)
	}
	return values
}

func getFirst(arr []interface{}) interface{} {
	if len(arr) > 0 {
		return arr[0]
	}
	return nil
}

func getLast(arr []interface{}) interface{} {
	if len(arr) > 0 {
		return arr[len(arr)-1]
	}
	return nil
}

func getLen(v interface{}) int {
	switch val := v.(type) {
	case string:
		return len(val)
	case []interface{}:
		return len(val)
	case map[string]interface{}:
		return len(val)
	default:
		return 0
	}
}

// addConditionalFuncs adds conditional template functions.
func addConditionalFuncs(funcs template.FuncMap) {
	funcs["default"] = defaultValue
	funcs["coalesce"] = coalesce
	funcs["ternary"] = ternary
}

func defaultValue(defaultVal, val interface{}) interface{} {
	if val == nil {
		return defaultVal
	}
	if s, ok := val.(string); ok && s == "" {
		return defaultVal
	}
	return val
}

func coalesce(vals ...interface{}) interface{} {
	for _, v := range vals {
		if v != nil {
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			return v
		}
	}
	return nil
}

func ternary(condition bool, trueVal, falseVal interface{}) interface{} {
	if condition {
		return trueVal
	}
	return falseVal
}

// addComparisonFuncs adds comparison template functions.
func addComparisonFuncs(funcs template.FuncMap) {
	funcs["eq"] = func(a, b interface{}) bool {
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
	funcs["ne"] = func(a, b interface{}) bool {
		return fmt.Sprintf("%v", a) != fmt.Sprintf("%v", b)
	}
}

// addUtilityFuncs adds utility template functions.
func addUtilityFuncs(funcs template.FuncMap) {
	funcs["dict"] = makeDict
	funcs["list"] = func(items ...interface{}) []interface{} {
		return items
	}
}

func makeDict(pairs ...interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for i := 0; i < len(pairs)-1; i += 2 {
		key, ok := pairs[i].(string)
		if ok {
			result[key] = pairs[i+1]
		}
	}
	return result
}

// ExecuteTemplate is a convenience function for executing a template.
func ExecuteTemplate(templateStr string, data interface{}, logger observability.Logger) (interface{}, error) {
	engine := NewTemplateEngine(logger)
	return engine.Execute(templateStr, data)
}
