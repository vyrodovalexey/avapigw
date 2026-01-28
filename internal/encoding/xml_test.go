// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"encoding/xml"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

func TestNewXMLCodec(t *testing.T) {
	codec := NewXMLCodec()
	assert.NotNil(t, codec)
}

func TestXMLCodec_Encode(t *testing.T) {
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}

	tests := []struct {
		name        string
		value       interface{}
		wantErr     bool
		errType     error
		checkResult func(t *testing.T, data []byte)
	}{
		{
			name:  "encode struct",
			value: Person{Name: "John", Age: 30},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "<person>")
				assert.Contains(t, string(data), "<name>John</name>")
				assert.Contains(t, string(data), "<age>30</age>")
				assert.Contains(t, string(data), "</person>")
			},
		},
		{
			name:  "encode with XML header",
			value: Person{Name: "John", Age: 30},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "<?xml version=")
			},
		},
		{
			name:    "encode nil",
			value:   nil,
			wantErr: true,
			errType: ErrNilValue,
		},
		{
			name: "encode nested struct",
			value: struct {
				XMLName xml.Name `xml:"root"`
				Child   struct {
					Value string `xml:"value"`
				} `xml:"child"`
			}{
				Child: struct {
					Value string `xml:"value"`
				}{Value: "test"},
			},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "<root>")
				assert.Contains(t, string(data), "<child>")
				assert.Contains(t, string(data), "<value>test</value>")
			},
		},
		{
			name: "encode with attributes",
			value: struct {
				XMLName xml.Name `xml:"element"`
				Attr    string   `xml:"attr,attr"`
				Value   string   `xml:",chardata"`
			}{
				Attr:  "attribute-value",
				Value: "content",
			},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), `attr="attribute-value"`)
				assert.Contains(t, string(data), "content")
			},
		},
		{
			name: "encode empty struct",
			value: struct {
				XMLName xml.Name `xml:"empty"`
			}{},
			checkResult: func(t *testing.T, data []byte) {
				assert.Contains(t, string(data), "<empty>")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewXMLCodec()
			data, err := codec.Encode(tt.value)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errType != nil {
					assert.ErrorIs(t, err, tt.errType)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
				if tt.checkResult != nil {
					tt.checkResult(t, data)
				}
			}
		})
	}
}

func TestXMLCodec_Decode(t *testing.T) {
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}

	tests := []struct {
		name        string
		data        []byte
		target      interface{}
		wantErr     bool
		checkResult func(t *testing.T, target interface{})
	}{
		{
			name:   "decode to struct",
			data:   []byte(`<person><name>John</name><age>30</age></person>`),
			target: &Person{},
			checkResult: func(t *testing.T, target interface{}) {
				p := target.(*Person)
				assert.Equal(t, "John", p.Name)
				assert.Equal(t, 30, p.Age)
			},
		},
		{
			name:   "decode with XML header",
			data:   []byte(`<?xml version="1.0" encoding="UTF-8"?><person><name>John</name><age>30</age></person>`),
			target: &Person{},
			checkResult: func(t *testing.T, target interface{}) {
				p := target.(*Person)
				assert.Equal(t, "John", p.Name)
			},
		},
		{
			name:    "decode empty data",
			data:    []byte{},
			target:  &Person{},
			wantErr: false,
		},
		{
			name:    "decode invalid XML",
			data:    []byte(`<person><name>John</name>`), // Missing closing tag
			target:  &Person{},
			wantErr: true,
		},
		{
			name: "decode with attributes",
			data: []byte(`<element attr="value">content</element>`),
			target: &struct {
				XMLName xml.Name `xml:"element"`
				Attr    string   `xml:"attr,attr"`
				Value   string   `xml:",chardata"`
			}{},
			checkResult: func(t *testing.T, target interface{}) {
				e := target.(*struct {
					XMLName xml.Name `xml:"element"`
					Attr    string   `xml:"attr,attr"`
					Value   string   `xml:",chardata"`
				})
				assert.Equal(t, "value", e.Attr)
				assert.Equal(t, "content", e.Value)
			},
		},
		{
			name: "decode nested structure",
			data: []byte(`<root><child><value>test</value></child></root>`),
			target: &struct {
				XMLName xml.Name `xml:"root"`
				Child   struct {
					Value string `xml:"value"`
				} `xml:"child"`
			}{},
			checkResult: func(t *testing.T, target interface{}) {
				r := target.(*struct {
					XMLName xml.Name `xml:"root"`
					Child   struct {
						Value string `xml:"value"`
					} `xml:"child"`
				})
				assert.Equal(t, "test", r.Child.Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := NewXMLCodec()
			err := codec.Decode(tt.data, tt.target)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrDecodingFailed)
			} else {
				require.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(t, tt.target)
				}
			}
		})
	}
}

func TestXMLCodec_ContentType(t *testing.T) {
	codec := NewXMLCodec()
	assert.Equal(t, config.ContentTypeXML, codec.ContentType())
}

func TestMarshalXML(t *testing.T) {
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
	}

	tests := []struct {
		name    string
		value   interface{}
		wantErr bool
	}{
		{
			name:    "marshal struct",
			value:   Person{Name: "John"},
			wantErr: false,
		},
		{
			name:    "marshal nil",
			value:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalXML(tt.value)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

func TestUnmarshalXML(t *testing.T) {
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
	}

	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "unmarshal valid XML",
			data:    []byte(`<person><name>John</name></person>`),
			wantErr: false,
		},
		{
			name:    "unmarshal empty data",
			data:    []byte{},
			wantErr: false,
		},
		{
			name:    "unmarshal invalid XML",
			data:    []byte(`<person><name>John`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result Person
			err := UnmarshalXML(tt.data, &result)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestXMLToMap(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		check   func(t *testing.T, result map[string]interface{})
	}{
		{
			name:    "simple XML",
			data:    []byte(`<root><name>test</name></root>`),
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.NotNil(t, result)
			},
		},
		{
			name:    "XML with content",
			data:    []byte(`<root>content</root>`),
			wantErr: false,
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Contains(t, result, "_content")
			},
		},
		{
			name:    "invalid XML",
			data:    []byte(`<root><name>test`),
			wantErr: true,
		},
		{
			name:    "empty XML",
			data:    []byte{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := XMLToMap(tt.data)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, result)
				}
			}
		})
	}
}

func TestXMLElement(t *testing.T) {
	// Test XMLElement struct
	elem := XMLElement{
		XMLName: xml.Name{Local: "test"},
		Content: "content",
		Attrs:   []xml.Attr{{Name: xml.Name{Local: "attr"}, Value: "value"}},
		Children: []XMLElement{
			{XMLName: xml.Name{Local: "child"}, Content: "child content"},
		},
	}

	assert.Equal(t, "test", elem.XMLName.Local)
	assert.Equal(t, "content", elem.Content)
	assert.Len(t, elem.Attrs, 1)
	assert.Len(t, elem.Children, 1)
}

func TestXmlElementToMap(t *testing.T) {
	tests := []struct {
		name  string
		elem  *XMLElement
		check func(t *testing.T, result map[string]interface{})
	}{
		{
			name: "element with content",
			elem: &XMLElement{
				XMLName: xml.Name{Local: "root"},
				Content: "content",
			},
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "content", result["_content"])
			},
		},
		{
			name: "element with attributes",
			elem: &XMLElement{
				XMLName: xml.Name{Local: "root"},
				Attrs:   []xml.Attr{{Name: xml.Name{Local: "attr"}, Value: "value"}},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Equal(t, "value", result["@attr"])
			},
		},
		{
			name: "element with children",
			elem: &XMLElement{
				XMLName: xml.Name{Local: "root"},
				Children: []XMLElement{
					{XMLName: xml.Name{Local: "child"}, Content: "child content"},
				},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				assert.Contains(t, result, "child")
			},
		},
		{
			name: "element with multiple children same name",
			elem: &XMLElement{
				XMLName: xml.Name{Local: "root"},
				Children: []XMLElement{
					{XMLName: xml.Name{Local: "item"}, Content: "item1"},
					{XMLName: xml.Name{Local: "item"}, Content: "item2"},
				},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				items, ok := result["item"].([]interface{})
				assert.True(t, ok, "should be a slice")
				assert.Len(t, items, 2)
			},
		},
		{
			name: "empty element",
			elem: &XMLElement{
				XMLName: xml.Name{Local: "root"},
			},
			check: func(t *testing.T, result map[string]interface{}) {
				assert.NotNil(t, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := xmlElementToMap(tt.elem)
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

func TestXMLCodec_RoundTrip(t *testing.T) {
	type Person struct {
		XMLName xml.Name `xml:"person"`
		Name    string   `xml:"name"`
		Age     int      `xml:"age"`
	}

	codec := NewXMLCodec()

	original := Person{Name: "John", Age: 30}

	// Encode
	data, err := codec.Encode(original)
	require.NoError(t, err)

	// Decode
	var decoded Person
	err = codec.Decode(data, &decoded)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Age, decoded.Age)
}
