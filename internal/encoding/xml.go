// Package encoding provides encoding/decoding capabilities for the API Gateway.
package encoding

import (
	"bytes"
	"encoding/xml"
	"fmt"

	"github.com/vyrodovalexey/avapigw/internal/config"
)

// xmlCodec implements Codec for XML encoding.
type xmlCodec struct{}

// NewXMLCodec creates a new XML codec.
func NewXMLCodec() Codec {
	return &xmlCodec{}
}

// Encode encodes the value to XML bytes.
func (c *xmlCodec) Encode(v interface{}) ([]byte, error) {
	if v == nil {
		return nil, ErrNilValue
	}

	var buf bytes.Buffer

	// Add XML header
	buf.WriteString(xml.Header)

	encoder := xml.NewEncoder(&buf)
	encoder.Indent("", "  ")

	if err := encoder.Encode(v); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEncodingFailed, err)
	}

	return buf.Bytes(), nil
}

// Decode decodes XML bytes into the value.
func (c *xmlCodec) Decode(data []byte, v interface{}) error {
	if len(data) == 0 {
		return nil
	}

	decoder := xml.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(v); err != nil {
		return fmt.Errorf("%w: %w", ErrDecodingFailed, err)
	}

	return nil
}

// ContentType returns the XML content type.
func (c *xmlCodec) ContentType() string {
	return config.ContentTypeXML
}

// XMLElement represents a generic XML element for dynamic XML handling.
type XMLElement struct {
	XMLName  xml.Name
	Attrs    []xml.Attr   `xml:",any,attr"`
	Content  string       `xml:",chardata"`
	Children []XMLElement `xml:",any"`
}

// MarshalXML is a convenience function for XML marshaling.
func MarshalXML(v interface{}) ([]byte, error) {
	codec := NewXMLCodec()
	return codec.Encode(v)
}

// UnmarshalXML is a convenience function for XML unmarshaling.
func UnmarshalXML(data []byte, v interface{}) error {
	codec := NewXMLCodec()
	return codec.Decode(data, v)
}

// XMLToMap converts XML bytes to a map.
// Note: This is a simplified implementation that may not handle all XML structures.
func XMLToMap(data []byte) (map[string]interface{}, error) {
	var elem XMLElement
	if err := UnmarshalXML(data, &elem); err != nil {
		return nil, err
	}
	return xmlElementToMap(&elem), nil
}

// xmlElementToMap converts an XMLElement to a map.
func xmlElementToMap(elem *XMLElement) map[string]interface{} {
	result := make(map[string]interface{})

	// Add content if present
	if elem.Content != "" {
		result["_content"] = elem.Content
	}

	// Add attributes
	for _, attr := range elem.Attrs {
		result["@"+attr.Name.Local] = attr.Value
	}

	// Add children
	for _, child := range elem.Children {
		childMap := xmlElementToMap(&child)
		name := child.XMLName.Local

		// Handle multiple children with same name
		if existing, ok := result[name]; ok {
			switch v := existing.(type) {
			case []interface{}:
				result[name] = append(v, childMap)
			default:
				result[name] = []interface{}{v, childMap}
			}
		} else {
			result[name] = childMap
		}
	}

	return result
}
