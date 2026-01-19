// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// SNIResult contains the result of SNI extraction.
type SNIResult struct {
	ServerName  string
	ClientHello []byte
}

// ExtractSNI extracts the SNI (Server Name Indication) from a TLS ClientHello message.
// It returns the server name and the raw ClientHello bytes that were read.
func ExtractSNI(conn net.Conn) (serverName string, clientHello []byte, err error) {
	return ExtractSNIWithTimeout(conn, 5*time.Second)
}

// ExtractSNIWithTimeout extracts SNI with a custom timeout.
// Returns the server name, raw ClientHello bytes, and any error.
func ExtractSNIWithTimeout(conn net.Conn, timeout time.Duration) (serverName string, clientHello []byte, err error) {
	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{}) // Clear deadline, ignore error
	}()

	// Read the TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", nil, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	// Validate TLS record type (should be Handshake = 22)
	// G602: header is guaranteed to be 5 bytes from io.ReadFull above
	if len(header) < 1 || header[0] != 22 {
		recordType := byte(0)
		if len(header) > 0 {
			recordType = header[0]
		}
		return "", header, fmt.Errorf("not a TLS handshake record: type=%d", recordType)
	}

	// Get the record length
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > 16384 { // Max TLS record size
		return "", header, fmt.Errorf("TLS record too large: %d", recordLength)
	}

	// Read the handshake message
	handshake := make([]byte, recordLength)
	if _, err := io.ReadFull(conn, handshake); err != nil {
		return "", header, fmt.Errorf("failed to read handshake message: %w", err)
	}

	// Combine header and handshake for the full ClientHello
	clientHello = make([]byte, 0, len(header)+len(handshake))
	clientHello = append(clientHello, header...)
	clientHello = append(clientHello, handshake...)

	// Parse the ClientHello to extract SNI
	serverName, err = parseClientHello(handshake)
	if err != nil {
		return "", clientHello, err
	}

	return serverName, clientHello, nil
}

// PeekClientHello reads the ClientHello without consuming it by using a buffered reader.
// This is useful when you need to inspect the ClientHello but still pass it to the TLS stack.
// Returns the server name, raw ClientHello bytes, and any error.
func PeekClientHello(conn net.Conn) (serverName string, clientHello []byte, err error) {
	return PeekClientHelloWithTimeout(conn, 5*time.Second)
}

// PeekClientHelloWithTimeout peeks at the ClientHello with a custom timeout.
// Returns the server name, raw ClientHello bytes, and any error.
func PeekClientHelloWithTimeout(
	conn net.Conn,
	timeout time.Duration,
) (serverName string, clientHello []byte, err error) {
	// For peeking, we need to use a buffered connection
	// Since we can't truly "peek" on a raw net.Conn, we read and return the data
	// The caller is responsible for prepending this data when forwarding
	return ExtractSNIWithTimeout(conn, timeout)
}

// parseClientHello parses a TLS ClientHello message and extracts the SNI.
func parseClientHello(data []byte) (string, error) {
	if err := validateClientHelloHeader(data); err != nil {
		return "", err
	}

	// Skip to extensions
	pos, err := skipToExtensions(data)
	if err != nil {
		return "", err
	}

	// No extensions present
	if pos < 0 {
		return "", nil
	}

	return findSNIInExtensions(data, pos)
}

// validateClientHelloHeader validates the ClientHello message header.
func validateClientHelloHeader(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("handshake message too short")
	}

	// Check handshake type (should be ClientHello = 1)
	if data[0] != 1 {
		return fmt.Errorf("not a ClientHello message: type=%d", data[0])
	}

	// Get handshake length
	handshakeLength := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+handshakeLength {
		return fmt.Errorf("handshake message truncated")
	}

	return nil
}

// skipToExtensions skips the fixed fields in ClientHello and returns the position of extensions.
// Returns -1 if no extensions are present.
func skipToExtensions(data []byte) (int, error) {
	pos := 4 // Start after handshake header

	// Skip client version (2 bytes) and random (32 bytes)
	pos, err := skipFixedFields(data, pos)
	if err != nil {
		return 0, err
	}

	// Skip variable-length fields
	pos, err = skipVariableFields(data, pos)
	if err != nil {
		return 0, err
	}

	// Check if there are extensions
	if pos+2 > len(data) {
		return -1, nil // No extensions, no SNI
	}

	extensionsLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+extensionsLength > len(data) {
		return 0, fmt.Errorf("ClientHello too short: missing extensions")
	}

	return pos, nil
}

// skipFixedFields skips the version and random fields.
func skipFixedFields(data []byte, pos int) (int, error) {
	// Skip client version (2 bytes)
	if pos+2 > len(data) {
		return 0, fmt.Errorf("ClientHello too short: missing version")
	}
	pos += 2

	// Skip random (32 bytes)
	if pos+32 > len(data) {
		return 0, fmt.Errorf("ClientHello too short: missing random")
	}
	pos += 32

	return pos, nil
}

// skipVariableFields skips session ID, cipher suites, and compression methods.
func skipVariableFields(data []byte, pos int) (int, error) {
	var err error

	// Skip session ID
	pos, err = skipLengthPrefixedField(data, pos, 1, "session ID")
	if err != nil {
		return 0, err
	}

	// Skip cipher suites
	pos, err = skipLengthPrefixedField(data, pos, 2, "cipher suites")
	if err != nil {
		return 0, err
	}

	// Skip compression methods
	pos, err = skipLengthPrefixedField(data, pos, 1, "compression methods")
	if err != nil {
		return 0, err
	}

	return pos, nil
}

// skipLengthPrefixedField skips a field with a length prefix.
func skipLengthPrefixedField(data []byte, pos, lengthBytes int, fieldName string) (int, error) {
	if pos+lengthBytes > len(data) {
		return 0, fmt.Errorf("ClientHello too short: missing %s length", fieldName)
	}

	var fieldLength int
	if lengthBytes == 1 {
		fieldLength = int(data[pos])
	} else {
		fieldLength = int(binary.BigEndian.Uint16(data[pos : pos+lengthBytes]))
	}
	pos += lengthBytes

	if pos+fieldLength > len(data) {
		return 0, fmt.Errorf("ClientHello too short: missing %s", fieldName)
	}
	pos += fieldLength

	return pos, nil
}

// findSNIInExtensions searches for the SNI extension in the extensions block.
func findSNIInExtensions(data []byte, pos int) (string, error) {
	// Calculate extensions end position
	extensionsLength := int(binary.BigEndian.Uint16(data[pos-2 : pos]))
	extensionsEnd := pos + extensionsLength

	for pos < extensionsEnd {
		if pos+4 > len(data) {
			break
		}

		extensionType := binary.BigEndian.Uint16(data[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if pos+extensionLength > len(data) {
			break
		}

		// SNI extension type is 0
		if extensionType == 0 {
			return parseSNIExtension(data[pos : pos+extensionLength])
		}

		pos += extensionLength
	}

	return "", nil // No SNI extension found
}

// parseSNIExtension parses the SNI extension data.
func parseSNIExtension(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("SNI extension too short")
	}

	// Get SNI list length
	sniListLength := int(binary.BigEndian.Uint16(data[0:2]))
	if len(data) < 2+sniListLength {
		return "", fmt.Errorf("SNI extension truncated")
	}

	pos := 2
	for pos < 2+sniListLength {
		if pos+3 > len(data) {
			break
		}

		nameType := data[pos]
		nameLength := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3

		if pos+nameLength > len(data) {
			break
		}

		// Name type 0 is host_name
		if nameType == 0 {
			return string(data[pos : pos+nameLength]), nil
		}

		pos += nameLength
	}

	return "", nil // No host_name found
}

// BufferedConn wraps a net.Conn with a buffer for prepending data.
type BufferedConn struct {
	net.Conn
	buffer *bytes.Buffer
}

// NewBufferedConn creates a new buffered connection.
func NewBufferedConn(conn net.Conn, prependData []byte) *BufferedConn {
	return &BufferedConn{
		Conn:   conn,
		buffer: bytes.NewBuffer(prependData),
	}
}

// Read reads from the buffer first, then from the underlying connection.
func (c *BufferedConn) Read(b []byte) (int, error) {
	if c.buffer.Len() > 0 {
		return c.buffer.Read(b)
	}
	return c.Conn.Read(b)
}

// GetSNIFromConn is a convenience function that extracts SNI and returns a buffered connection.
func GetSNIFromConn(conn net.Conn) (string, net.Conn, error) {
	serverName, clientHello, err := ExtractSNI(conn)
	if err != nil {
		return "", nil, err
	}

	// Return a buffered connection that will replay the ClientHello
	bufferedConn := NewBufferedConn(conn, clientHello)
	return serverName, bufferedConn, nil
}
