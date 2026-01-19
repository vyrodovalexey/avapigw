// Package tls provides the TLS server implementation for the API Gateway.
package tls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildClientHello builds a TLS ClientHello message with the given SNI.
func buildClientHello(serverName string) []byte {
	// Build SNI extension
	sniExtension := buildSNIExtension(serverName)

	// Build extensions
	extensions := make([]byte, 2+len(sniExtension))
	binary.BigEndian.PutUint16(extensions[0:2], uint16(len(sniExtension)))
	copy(extensions[2:], sniExtension)

	// Build ClientHello body
	// Version (2) + Random (32) + Session ID length (1) + Cipher suites length (2) +
	// Cipher suites (2) + Compression methods length (1) + Compression method (1) + Extensions
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1+len(extensions))

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// Extensions
	clientHelloBody = append(clientHelloBody, extensions...)

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Build TLS record
	recordLength := len(handshake)
	record := make([]byte, 5+recordLength)
	record[0] = 22 // Handshake
	record[1] = 0x03
	record[2] = 0x01 // TLS 1.0 for record layer
	binary.BigEndian.PutUint16(record[3:5], uint16(recordLength))
	copy(record[5:], handshake)

	return record
}

// buildSNIExtension builds an SNI extension with the given server name.
func buildSNIExtension(serverName string) []byte {
	if serverName == "" {
		return nil
	}

	nameBytes := []byte(serverName)
	nameLength := len(nameBytes)

	// SNI extension structure:
	// Extension type (2) + Extension length (2) + SNI list length (2) +
	// Name type (1) + Name length (2) + Name
	extension := make([]byte, 0, 2+2+2+1+2+nameLength)

	// Extension type (0 = SNI)
	extension = append(extension, 0x00, 0x00)

	// Extension length
	extensionDataLength := 2 + 1 + 2 + nameLength
	extension = append(extension, byte(extensionDataLength>>8), byte(extensionDataLength))

	// SNI list length
	sniListLength := 1 + 2 + nameLength
	extension = append(extension, byte(sniListLength>>8), byte(sniListLength))

	// Name type (0 = host_name)
	extension = append(extension, 0x00)

	// Name length
	extension = append(extension, byte(nameLength>>8), byte(nameLength))

	// Name
	extension = append(extension, nameBytes...)

	return extension
}

// buildInvalidTLSRecord builds an invalid TLS record for testing.
func buildInvalidTLSRecord(recordType byte) []byte {
	record := make([]byte, 5)
	record[0] = recordType // Invalid record type
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], 0)
	return record
}

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name          string
		clientHello   []byte
		expectedSNI   string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid ClientHello with SNI",
			clientHello: buildClientHello("example.com"),
			expectedSNI: "example.com",
			expectError: false,
		},
		{
			name:        "valid ClientHello with subdomain SNI",
			clientHello: buildClientHello("api.example.com"),
			expectedSNI: "api.example.com",
			expectError: false,
		},
		{
			name:          "invalid TLS record type",
			clientHello:   buildInvalidTLSRecord(23), // Application data
			expectedSNI:   "",
			expectError:   true,
			errorContains: "not a TLS handshake record",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			// Write ClientHello in a goroutine
			go func() {
				_, _ = clientConn.Write(tt.clientHello)
			}()

			// Extract SNI
			sni, clientHelloBytes, err := ExtractSNI(serverConn)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSNI, sni)
				assert.NotEmpty(t, clientHelloBytes)
			}
		})
	}
}

func TestExtractSNIWithTimeout(t *testing.T) {
	tests := []struct {
		name          string
		timeout       time.Duration
		writeDelay    time.Duration
		expectError   bool
		errorContains string
	}{
		{
			name:        "successful extraction within timeout",
			timeout:     5 * time.Second,
			writeDelay:  0,
			expectError: false,
		},
		{
			name:          "timeout before data",
			timeout:       10 * time.Millisecond,
			writeDelay:    100 * time.Millisecond,
			expectError:   true,
			errorContains: "failed to read TLS record header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			clientHello := buildClientHello("example.com")

			// Write ClientHello in a goroutine with optional delay
			go func() {
				if tt.writeDelay > 0 {
					time.Sleep(tt.writeDelay)
				}
				_, _ = clientConn.Write(clientHello)
			}()

			// Extract SNI with timeout
			sni, _, err := ExtractSNIWithTimeout(serverConn, tt.timeout)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "example.com", sni)
			}
		})
	}
}

func TestParseClientHello(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expectedSNI   string
		expectError   bool
		errorContains string
	}{
		{
			name:          "too short data",
			data:          []byte{0x01, 0x00},
			expectedSNI:   "",
			expectError:   true,
			errorContains: "handshake message too short",
		},
		{
			name:          "not a ClientHello",
			data:          []byte{0x02, 0x00, 0x00, 0x00}, // ServerHello type
			expectedSNI:   "",
			expectError:   true,
			errorContains: "not a ClientHello message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, err := parseClientHello(tt.data)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSNI, sni)
			}
		})
	}
}

func TestParseSNIExtension(t *testing.T) {
	tests := []struct {
		name          string
		data          []byte
		expectedSNI   string
		expectError   bool
		errorContains string
	}{
		{
			name:          "too short data",
			data:          []byte{0x00},
			expectedSNI:   "",
			expectError:   true,
			errorContains: "SNI extension too short",
		},
		{
			name:          "truncated extension",
			data:          []byte{0x00, 0x10}, // Claims 16 bytes but has none
			expectedSNI:   "",
			expectError:   true,
			errorContains: "SNI extension truncated",
		},
		{
			name: "valid SNI extension",
			data: func() []byte {
				serverName := "example.com"
				nameBytes := []byte(serverName)
				nameLength := len(nameBytes)
				sniListLength := 1 + 2 + nameLength

				data := make([]byte, 0, 2+sniListLength)
				data = append(data, byte(sniListLength>>8), byte(sniListLength))
				data = append(data, 0x00) // Name type = host_name
				data = append(data, byte(nameLength>>8), byte(nameLength))
				data = append(data, nameBytes...)
				return data
			}(),
			expectedSNI: "example.com",
			expectError: false,
		},
		{
			name: "non-hostname name type",
			data: func() []byte {
				serverName := "example.com"
				nameBytes := []byte(serverName)
				nameLength := len(nameBytes)
				sniListLength := 1 + 2 + nameLength

				data := make([]byte, 0, 2+sniListLength)
				data = append(data, byte(sniListLength>>8), byte(sniListLength))
				data = append(data, 0x01) // Name type = not host_name
				data = append(data, byte(nameLength>>8), byte(nameLength))
				data = append(data, nameBytes...)
				return data
			}(),
			expectedSNI: "",
			expectError: false, // No error, just no hostname found
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, err := parseSNIExtension(tt.data)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSNI, sni)
			}
		})
	}
}

func TestBufferedConn_Read(t *testing.T) {
	tests := []struct {
		name         string
		prependData  []byte
		connData     []byte
		readSize     int
		expectedData []byte
	}{
		{
			name:         "read from buffer only",
			prependData:  []byte("buffered"),
			connData:     []byte("connection"),
			readSize:     8,
			expectedData: []byte("buffered"),
		},
		{
			name:         "read from buffer then connection",
			prependData:  []byte("buf"),
			connData:     []byte("connection"),
			readSize:     10,
			expectedData: []byte("buf"),
		},
		{
			name:         "empty buffer reads from connection",
			prependData:  []byte{},
			connData:     []byte("connection"),
			readSize:     10,
			expectedData: []byte("connection"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			// Write connection data in a goroutine
			go func() {
				_, _ = clientConn.Write(tt.connData)
			}()

			// Create buffered connection
			bufferedConn := NewBufferedConn(serverConn, tt.prependData)

			// Read data
			buf := make([]byte, tt.readSize)
			n, err := bufferedConn.Read(buf)

			require.NoError(t, err)
			assert.Equal(t, tt.expectedData, buf[:n])
		})
	}
}

func TestNewBufferedConn(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	prependData := []byte("prepend")
	bufferedConn := NewBufferedConn(serverConn, prependData)

	require.NotNil(t, bufferedConn)
	assert.Equal(t, serverConn, bufferedConn.Conn)
	assert.Equal(t, prependData, bufferedConn.buffer.Bytes())
}

func TestGetSNIFromConn(t *testing.T) {
	tests := []struct {
		name          string
		clientHello   []byte
		expectedSNI   string
		expectError   bool
		errorContains string
	}{
		{
			name:        "successful SNI extraction",
			clientHello: buildClientHello("example.com"),
			expectedSNI: "example.com",
			expectError: false,
		},
		{
			name:          "invalid TLS record",
			clientHello:   buildInvalidTLSRecord(23),
			expectedSNI:   "",
			expectError:   true,
			errorContains: "not a TLS handshake record",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create pipe for testing
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			// Write ClientHello in a goroutine
			go func() {
				_, _ = clientConn.Write(tt.clientHello)
			}()

			// Get SNI from connection
			sni, bufferedConn, err := GetSNIFromConn(serverConn)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, bufferedConn)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedSNI, sni)
				require.NotNil(t, bufferedConn)

				// Verify buffered connection contains the ClientHello
				bc, ok := bufferedConn.(*BufferedConn)
				require.True(t, ok)
				assert.True(t, bc.buffer.Len() > 0)
			}
		})
	}
}

func TestBufferedConn_MultipleReads(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	prependData := []byte("prepend")
	connData := []byte("connection data")

	// Write connection data in a goroutine
	go func() {
		_, _ = clientConn.Write(connData)
	}()

	// Create buffered connection
	bufferedConn := NewBufferedConn(serverConn, prependData)

	// First read should get prepend data
	buf1 := make([]byte, len(prependData))
	n1, err := bufferedConn.Read(buf1)
	require.NoError(t, err)
	assert.Equal(t, prependData, buf1[:n1])

	// Second read should get connection data
	buf2 := make([]byte, len(connData))
	n2, err := bufferedConn.Read(buf2)
	require.NoError(t, err)
	assert.Equal(t, connData, buf2[:n2])
}

func TestExtractSNI_LargeRecord(t *testing.T) {
	// Create a TLS record that claims to be too large
	record := make([]byte, 5)
	record[0] = 22 // Handshake
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], 20000) // > 16384

	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write record in a goroutine
	go func() {
		_, _ = clientConn.Write(record)
	}()

	// Extract SNI should fail
	_, _, err := ExtractSNI(serverConn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS record too large")
}

func TestParseClientHello_TruncatedMessages(t *testing.T) {
	tests := []struct {
		name          string
		buildData     func() []byte
		errorContains string
	}{
		{
			name: "missing version",
			buildData: func() []byte {
				// ClientHello type + length but no body
				return []byte{0x01, 0x00, 0x00, 0x10}
			},
			errorContains: "truncated",
		},
		{
			name: "missing random",
			buildData: func() []byte {
				data := []byte{0x01, 0x00, 0x00, 0x10}
				data = append(data, 0x03, 0x03) // version
				return data
			},
			errorContains: "truncated",
		},
		{
			name: "missing session ID length",
			buildData: func() []byte {
				data := []byte{0x01, 0x00, 0x00, 0x30}
				data = append(data, 0x03, 0x03)          // version
				data = append(data, make([]byte, 32)...) // random
				return data
			},
			errorContains: "truncated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.buildData()
			_, err := parseClientHello(data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestBufferedConn_ReadAfterBufferDrained(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	prependData := []byte("short")
	connData := []byte("longer connection data")

	// Write connection data in a goroutine
	go func() {
		_, _ = clientConn.Write(connData)
		clientConn.Close()
	}()

	// Create buffered connection
	bufferedConn := NewBufferedConn(serverConn, prependData)

	// Read all data
	allData := make([]byte, 0)
	buf := make([]byte, 10)
	for {
		n, err := bufferedConn.Read(buf)
		if n > 0 {
			allData = append(allData, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	// Should have prepend data followed by connection data
	expected := append(prependData, connData...)
	assert.Equal(t, expected, allData)
}

func TestBufferedConn_EmptyBuffer(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	connData := []byte("connection data")

	// Write connection data in a goroutine
	go func() {
		_, _ = clientConn.Write(connData)
	}()

	// Create buffered connection with empty buffer
	bufferedConn := NewBufferedConn(serverConn, []byte{})

	// Read should go directly to connection
	buf := make([]byte, len(connData))
	n, err := bufferedConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, connData, buf[:n])
}

func TestBufferedConn_NilBuffer(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	connData := []byte("connection data")

	// Write connection data in a goroutine
	go func() {
		_, _ = clientConn.Write(connData)
	}()

	// Create buffered connection with nil buffer
	bufferedConn := &BufferedConn{
		Conn:   serverConn,
		buffer: bytes.NewBuffer(nil),
	}

	// Read should go directly to connection
	buf := make([]byte, len(connData))
	n, err := bufferedConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, connData, buf[:n])
}

func TestPeekClientHello(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientHello := buildClientHello("example.com")

	// Write ClientHello in a goroutine
	go func() {
		_, _ = clientConn.Write(clientHello)
	}()

	// Peek ClientHello
	sni, data, err := PeekClientHello(serverConn)
	require.NoError(t, err)
	assert.Equal(t, "example.com", sni)
	assert.NotEmpty(t, data)
}

func TestPeekClientHelloWithTimeout(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	clientHello := buildClientHello("example.com")

	// Write ClientHello in a goroutine
	go func() {
		_, _ = clientConn.Write(clientHello)
	}()

	// Peek ClientHello with timeout
	sni, data, err := PeekClientHelloWithTimeout(serverConn, 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "example.com", sni)
	assert.NotEmpty(t, data)
}

func TestParseClientHello_NoExtensions(t *testing.T) {
	// Build a ClientHello without extensions
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// No extensions

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return empty SNI, no error
	sni, err := parseClientHello(handshake)
	require.NoError(t, err)
	assert.Empty(t, sni)
}

func TestParseClientHello_WithNonSNIExtension(t *testing.T) {
	// Build a ClientHello with a non-SNI extension
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1+10)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// Extensions - add a non-SNI extension (e.g., supported_versions = 43)
	extensionData := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04} // supported_versions extension
	extensionsLength := len(extensionData)
	clientHelloBody = append(clientHelloBody, byte(extensionsLength>>8), byte(extensionsLength))
	clientHelloBody = append(clientHelloBody, extensionData...)

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return empty SNI, no error
	sni, err := parseClientHello(handshake)
	require.NoError(t, err)
	assert.Empty(t, sni)
}

func TestParseClientHello_TruncatedExtensions(t *testing.T) {
	// Build a ClientHello with truncated extensions
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1+4)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// Extensions length claims more than available
	clientHelloBody = append(clientHelloBody, 0x00, 0x10) // Claims 16 bytes

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return error
	_, err := parseClientHello(handshake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing extensions")
}

func TestParseClientHello_TruncatedCipherSuites(t *testing.T) {
	// Build a ClientHello with truncated cipher suites
	clientHelloBody := make([]byte, 0, 2+32+1+2)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length claims more than available
	clientHelloBody = append(clientHelloBody, 0x00, 0x10) // Claims 16 bytes

	// Build handshake message with correct length
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return error
	_, err := parseClientHello(handshake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cipher suites")
}

func TestParseClientHello_TruncatedCompressionMethods(t *testing.T) {
	// Build a ClientHello with truncated compression methods
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f) // TLS_RSA_WITH_AES_128_CBC_SHA

	// Compression methods length claims more than available
	clientHelloBody = append(clientHelloBody, 0x10) // Claims 16 bytes

	// Build handshake message with correct length
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return error
	_, err := parseClientHello(handshake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "compression methods")
}

func TestParseClientHello_TruncatedSessionID(t *testing.T) {
	// Build a ClientHello with truncated session ID
	clientHelloBody := make([]byte, 0, 2+32+1)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length claims more than available
	clientHelloBody = append(clientHelloBody, 0x20) // Claims 32 bytes

	// Build handshake message with correct length
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return error
	_, err := parseClientHello(handshake)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session ID")
}

func TestSkipFixedFields_MissingVersion(t *testing.T) {
	// Data too short for version
	data := []byte{0x01, 0x00, 0x00, 0x10} // Just handshake header
	pos := 4

	_, err := skipFixedFields(data, pos)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing version")
}

func TestSkipFixedFields_MissingRandom(t *testing.T) {
	// Data has version but not enough for random
	data := make([]byte, 4+2+10) // handshake header + version + partial random
	data[0] = 0x01               // ClientHello
	data[1] = 0x00
	data[2] = 0x00
	data[3] = byte(len(data) - 4)
	data[4] = 0x03 // version
	data[5] = 0x03

	pos := 4

	_, err := skipFixedFields(data, pos)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing random")
}

func TestSkipLengthPrefixedField_MissingLength(t *testing.T) {
	// Data too short for length field
	data := []byte{}
	pos := 0

	_, err := skipLengthPrefixedField(data, pos, 1, "test field")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing test field length")
}

func TestSkipLengthPrefixedField_MissingData(t *testing.T) {
	// Data has length but not enough data
	data := []byte{0x10} // Claims 16 bytes but has none
	pos := 0

	_, err := skipLengthPrefixedField(data, pos, 1, "test field")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing test field")
}

func TestSkipLengthPrefixedField_TwoByteLength(t *testing.T) {
	// Test with 2-byte length field
	data := []byte{0x00, 0x04, 0x01, 0x02, 0x03, 0x04} // 4 bytes of data
	pos := 0

	newPos, err := skipLengthPrefixedField(data, pos, 2, "test field")
	require.NoError(t, err)
	assert.Equal(t, 6, newPos)
}

func TestFindSNIInExtensions_TruncatedExtension(t *testing.T) {
	// Build a ClientHello with truncated extension data
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1+10)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f)

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// Extensions length (6) - provide exactly 6 bytes of extension data
	clientHelloBody = append(clientHelloBody, 0x00, 0x06)
	// Extension type (2 bytes) + extension length (2 bytes) + 2 bytes of data
	// This is a valid extension structure but with truncated SNI data
	clientHelloBody = append(clientHelloBody, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00) // SNI extension with empty list

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should return empty SNI (extension has empty list)
	sni, err := parseClientHello(handshake)
	require.NoError(t, err)
	assert.Empty(t, sni)
}

func TestParseSNIExtension_TruncatedNameEntry(t *testing.T) {
	// SNI extension with truncated name entry - list length claims more than available
	data := []byte{
		0x00, 0x05, // SNI list length = 5
		0x00,       // Name type = host_name
		0x00, 0x10, // Name length = 16 (but no data follows)
	}

	sni, err := parseSNIExtension(data)
	// This should return error because the extension is truncated
	require.Error(t, err)
	assert.Empty(t, sni)
}

func TestParseSNIExtension_TruncatedNameType(t *testing.T) {
	// SNI extension with truncated name type - list length claims more than available
	data := []byte{
		0x00, 0x02, // SNI list length = 2
		0x00, // Name type = host_name
		// Missing name length and name
	}

	sni, err := parseSNIExtension(data)
	// This should return error because the extension is truncated
	require.Error(t, err)
	assert.Empty(t, sni)
}

func TestExtractSNI_TruncatedHandshake(t *testing.T) {
	// Create a TLS record that claims a handshake but doesn't have enough data
	record := make([]byte, 5)
	record[0] = 22 // Handshake
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], 100) // Claims 100 bytes

	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Write record header but close before sending full data
	go func() {
		_, _ = clientConn.Write(record)
		clientConn.Close()
	}()

	// Extract SNI should fail
	_, _, err := ExtractSNI(serverConn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read handshake message")
}

func TestExtractSNIWithTimeout_SetDeadlineError(t *testing.T) {
	// Create a mock connection that fails on SetReadDeadline
	mockConn := &mockConnWithSetDeadlineError{}

	_, _, err := ExtractSNIWithTimeout(mockConn, 1*time.Second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to set read deadline")
}

// mockConnWithSetDeadlineError is a mock connection that fails on SetReadDeadline
type mockConnWithSetDeadlineError struct {
	net.Conn
}

func (m *mockConnWithSetDeadlineError) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConnWithSetDeadlineError) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConnWithSetDeadlineError) Close() error {
	return nil
}

func (m *mockConnWithSetDeadlineError) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockConnWithSetDeadlineError) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}
}

func (m *mockConnWithSetDeadlineError) SetDeadline(t time.Time) error {
	return errors.New("set deadline error")
}

func (m *mockConnWithSetDeadlineError) SetReadDeadline(t time.Time) error {
	return errors.New("set read deadline error")
}

func (m *mockConnWithSetDeadlineError) SetWriteDeadline(t time.Time) error {
	return errors.New("set write deadline error")
}

func TestValidateClientHelloHeader_TruncatedLength(t *testing.T) {
	// Handshake header with length claiming more data than available
	data := []byte{0x01, 0x00, 0x01, 0x00} // Claims 256 bytes but has none

	err := validateClientHelloHeader(data)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "truncated")
}

func TestSkipToExtensions_NoExtensions(t *testing.T) {
	// Build a minimal ClientHello without extensions
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f)

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// No extensions

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// skipToExtensions should return -1 for no extensions
	pos, err := skipToExtensions(handshake)
	require.NoError(t, err)
	assert.Equal(t, -1, pos)
}

func TestFindSNIInExtensions_MultipleExtensions(t *testing.T) {
	// Build a ClientHello with multiple extensions, SNI not first
	clientHelloBody := make([]byte, 0, 2+32+1+2+2+1+1+50)

	// Client version (TLS 1.2)
	clientHelloBody = append(clientHelloBody, 0x03, 0x03)

	// Random (32 bytes)
	random := make([]byte, 32)
	clientHelloBody = append(clientHelloBody, random...)

	// Session ID length (0)
	clientHelloBody = append(clientHelloBody, 0x00)

	// Cipher suites length (2) + one cipher suite
	clientHelloBody = append(clientHelloBody, 0x00, 0x02)
	clientHelloBody = append(clientHelloBody, 0x00, 0x2f)

	// Compression methods length (1) + null compression
	clientHelloBody = append(clientHelloBody, 0x01, 0x00)

	// Build extensions
	// First: supported_versions extension (type 43)
	supportedVersions := []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}

	// Second: SNI extension
	serverName := "example.com"
	nameBytes := []byte(serverName)
	nameLength := len(nameBytes)
	sniListLength := 1 + 2 + nameLength
	sniExtension := make([]byte, 0, 4+2+sniListLength)
	sniExtension = append(sniExtension, 0x00, 0x00) // SNI type
	sniExtension = append(sniExtension, byte((2+sniListLength)>>8), byte(2+sniListLength))
	sniExtension = append(sniExtension, byte(sniListLength>>8), byte(sniListLength))
	sniExtension = append(sniExtension, 0x00) // host_name type
	sniExtension = append(sniExtension, byte(nameLength>>8), byte(nameLength))
	sniExtension = append(sniExtension, nameBytes...)

	// Combine extensions
	allExtensions := append(supportedVersions, sniExtension...)
	extensionsLength := len(allExtensions)

	clientHelloBody = append(clientHelloBody, byte(extensionsLength>>8), byte(extensionsLength))
	clientHelloBody = append(clientHelloBody, allExtensions...)

	// Build handshake message
	handshakeLength := len(clientHelloBody)
	handshake := make([]byte, 4+handshakeLength)
	handshake[0] = 1 // ClientHello
	handshake[1] = byte(handshakeLength >> 16)
	handshake[2] = byte(handshakeLength >> 8)
	handshake[3] = byte(handshakeLength)
	copy(handshake[4:], clientHelloBody)

	// Parse - should find SNI even though it's not first
	sni, err := parseClientHello(handshake)
	require.NoError(t, err)
	assert.Equal(t, "example.com", sni)
}

func TestBufferedConn_PartialBufferRead(t *testing.T) {
	// Create pipe for testing
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	prependData := []byte("prepend data that is longer than read buffer")
	connData := []byte("connection data")

	// Write connection data in a goroutine
	go func() {
		_, _ = clientConn.Write(connData)
	}()

	// Create buffered connection
	bufferedConn := NewBufferedConn(serverConn, prependData)

	// Read with small buffer - should only get part of prepend data
	buf := make([]byte, 10)
	n, err := bufferedConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.Equal(t, prependData[:10], buf[:n])

	// Read again - should get more prepend data
	n, err = bufferedConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, prependData[10:20], buf[:n])
}
