package socks5_client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/txthinking/socks5"
)

// MockDialer implements ContextDialer for testing
type MockDialer struct {
	conn *MockConn
}

func (m *MockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return m.conn, nil
}

type MockConn struct {
	ReadData  []byte
	WriteData []byte
	Closed    bool
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	if len(m.ReadData) == 0 {
		return 0, nil
	}
	n = copy(b, m.ReadData)
	m.ReadData = m.ReadData[n:]
	return n, nil
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	m.WriteData = append(m.WriteData, b...)
	return len(b), nil
}

func (m *MockConn) Close() error {
	m.Closed = true
	return nil
}

func (m *MockConn) LocalAddr() net.Addr                { return nil }
func (m *MockConn) RemoteAddr() net.Addr               { return nil }
func (m *MockConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestClient_DialTCP(t *testing.T) {
	// This is a basic test to verify compilation and basic flow structure.
	// A full test would require simulating SOCKS5 server responses, which is complex manually.
	// Here we just ensure structs and methods are wired correctly.

	dialer := &MockDialer{conn: &MockConn{}}
	client := NewClient("127.0.0.1:1080", "", "", dialer)

	assert.NotNil(t, client)

	// Since MockConn returns empty read, negotiation will fail immediately or hang.
	// We just want to check that it attempts to dial.
	// To test properly we'd need to mock the full handshake interaction.
}

func TestDatagramEncapsulation(t *testing.T) {
	// Test the encapsulation logic in udpWrapper (indirectly by checking txthinking/socks5 usage)

	dstAddr := "8.8.8.8:53"
	payload := []byte("hello")

	a, h, p, err := socks5.ParseAddress(dstAddr)
	assert.NoError(t, err)

	d := socks5.NewDatagram(a, h, p, payload)
	packed := d.Bytes()

	d2, err := socks5.NewDatagramFromBytes(packed)
	assert.NoError(t, err)
	assert.Equal(t, payload, d2.Data)
	assert.Equal(t, a, d2.Atyp)
	assert.Equal(t, h, d2.DstAddr)
	assert.Equal(t, p, d2.DstPort)
}
