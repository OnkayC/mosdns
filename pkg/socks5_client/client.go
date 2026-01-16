package socks5_client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/txthinking/socks5"
)

// ContextDialer dials using a context.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Client is a SOCKS5 client that supports custom dialer and Context.
type Client struct {
	ProxyAddr string
	User      string
	Password  string
	Dialer    ContextDialer
}

// NewClient creates a new SOCKS5 client.
func NewClient(proxyAddr, user, password string, dialer ContextDialer) *Client {
	return &Client{
		ProxyAddr: proxyAddr,
		User:      user,
		Password:  password,
		Dialer:    dialer,
	}
}

// DialContext connects to the address on the named network using the SOCKS5 proxy.
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.dialTCP(ctx, network, addr)
	case "udp", "udp4", "udp6":
		return c.dialUDP(ctx, network, addr)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}

func (c *Client) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := c.Dialer.DialContext(ctx, "tcp", c.ProxyAddr)
	if err != nil {
		return nil, err
	}

	// Error handling: ensure connection is closed if setup fails
	cleanup := true
	defer func() {
		if cleanup {
			conn.Close()
		}
	}()

	// Negotiate
	if err := c.negotiate(conn); err != nil {
		return nil, err
	}

	// Request Connect
	a, h, p, err := socks5.ParseAddress(addr)
	if err != nil {
		return nil, err
	}
	if a == socks5.ATYPDomain {
		h = h[1:]
	}

	req := socks5.NewRequest(socks5.CmdConnect, a, h, p)
	if _, err := req.WriteTo(conn); err != nil {
		return nil, err
	}

	reply, err := socks5.NewReplyFrom(conn)
	if err != nil {
		return nil, err
	}
	if reply.Rep != socks5.RepSuccess {
		return nil, fmt.Errorf("socks5 connect failed: %v", reply.Rep)
	}

	cleanup = false
	return conn, nil
}

func (c *Client) dialUDP(ctx context.Context, network, addr string) (net.Conn, error) {
	// 1. Connect to SOCKS5 server (TCP control connection)
	tcpConn, err := c.Dialer.DialContext(ctx, "tcp", c.ProxyAddr)
	if err != nil {
		return nil, err
	}

	cleanupTcp := true
	defer func() {
		if cleanupTcp {
			tcpConn.Close()
		}
	}()

	// 2. Negotiate
	if err := c.negotiate(tcpConn); err != nil {
		return nil, err
	}

	// 3. UDP Associate
	// We use 0.0.0.0:0 as source address for association usually.
	req := socks5.NewRequest(socks5.CmdUDP, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
	if _, err := req.WriteTo(tcpConn); err != nil {
		return nil, err
	}

	reply, err := socks5.NewReplyFrom(tcpConn)
	if err != nil {
		return nil, err
	}
	if reply.Rep != socks5.RepSuccess {
		return nil, fmt.Errorf("socks5 udp associate failed: %v", reply.Rep)
	}

	// 4. Dial UDP to the relay address
	relayAddr := reply.Address()
	udpConn, err := c.Dialer.DialContext(ctx, "udp", relayAddr)
	if err != nil {
		return nil, err
	}

	cleanupTcp = false
	return &udpWrapper{
		tcpConn: tcpConn,
		udpConn: udpConn,
		dstAddr: addr,
	}, nil
}

func (c *Client) negotiate(conn net.Conn) error {
	m := socks5.MethodNone
	if c.User != "" && c.Password != "" {
		m = socks5.MethodUsernamePassword
	}

	req := socks5.NewNegotiationRequest([]byte{m})
	if _, err := req.WriteTo(conn); err != nil {
		return err
	}

	reply, err := socks5.NewNegotiationReplyFrom(conn)
	if err != nil {
		return err
	}
	if reply.Method != m {
		return errors.New("unsupported authentication method")
	}

	if m == socks5.MethodUsernamePassword {
		upReq := socks5.NewUserPassNegotiationRequest([]byte(c.User), []byte(c.Password))
		if _, err := upReq.WriteTo(conn); err != nil {
			return err
		}
		upReply, err := socks5.NewUserPassNegotiationReplyFrom(conn)
		if err != nil {
			return err
		}
		if upReply.Status != socks5.UserPassStatusSuccess {
			return errors.New("socks5 authentication failed")
		}
	}
	return nil
}

type udpWrapper struct {
	tcpConn net.Conn
	udpConn net.Conn
	dstAddr string
}

func (c *udpWrapper) Read(b []byte) (n int, err error) {
	n, err = c.udpConn.Read(b)
	if err != nil {
		return 0, err
	}
	// Decapsulate
	d, err := socks5.NewDatagramFromBytes(b[:n])
	if err != nil {
		// If packet is malformed, we might want to ignore it or return error.
		// For simplicity, return error.
		return 0, err
	}
	copy(b, d.Data)
	return len(d.Data), nil
}

func (c *udpWrapper) Write(b []byte) (n int, err error) {
	// Encapsulate
	a, h, p, err := socks5.ParseAddress(c.dstAddr)
	if err != nil {
		return 0, err
	}
	if a == socks5.ATYPDomain {
		h = h[1:]
	}

	d := socks5.NewDatagram(a, h, p, b)
	packet := d.Bytes()

	_, err = c.udpConn.Write(packet)
	if err != nil {
		return 0, err
	}
	// Return len(b) to pretend we wrote the payload
	return len(b), nil
}

func (c *udpWrapper) Close() error {
	e1 := c.udpConn.Close()
	e2 := c.tcpConn.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func (c *udpWrapper) LocalAddr() net.Addr {
	return c.udpConn.LocalAddr()
}

func (c *udpWrapper) RemoteAddr() net.Addr {
	return c.udpConn.RemoteAddr()
}

func (c *udpWrapper) SetDeadline(t time.Time) error {
	return c.udpConn.SetDeadline(t)
}

func (c *udpWrapper) SetReadDeadline(t time.Time) error {
	return c.udpConn.SetReadDeadline(t)
}

func (c *udpWrapper) SetWriteDeadline(t time.Time) error {
	return c.udpConn.SetWriteDeadline(t)
}
