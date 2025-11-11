package ja4s

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/voukatas/go-ja4/pkg/ja4"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4s", parseCaddyfileHandler)
}

// ListenerWrapper captures outbound TLS handshake data so the server hello
// can be converted into a JA4S fingerprint.
//
// To observe the unencrypted TLS records this wrapper must appear before the
// TLS placeholder wrapper (`caddy.listeners.tls`) in the listener_wrappers
// chain.
type ListenerWrapper struct {
	// Maximum number of bytes to keep while waiting for the ServerHello record.
	// JA4S only needs the first TLS record, so small buffers are sufficient.
	MaxCaptureBytes int `json:"max_capture_bytes,omitempty"`

	// Protocol hint that is forwarded to the go-ja4 parser. Defaults to "tls".
	Protocol string `json:"protocol,omitempty"`

	logger       *zap.Logger
	protocolByte byte
}

// CaddyModule implements caddy.Module.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4s",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

// Provision configures defaults.
func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	lw.logger = ctx.Logger(lw)
	if lw.MaxCaptureBytes <= 0 {
		lw.MaxCaptureBytes = 16 * 1024
	}
	switch strings.ToLower(lw.Protocol) {
	case "", "tls":
		lw.protocolByte = 't'
	case "dtls":
		lw.protocolByte = 'd'
	default:
		lw.protocolByte = 't'
		lw.logger.Warn("unknown protocol value, defaulting to TLS", zap.String("protocol", lw.Protocol))
	}
	return nil
}

// Validate ensures the listener wrapper is usable.
func (lw *ListenerWrapper) Validate() error {
	if lw.MaxCaptureBytes < minRecordSize {
		return fmt.Errorf("max_capture_bytes must be at least %d", minRecordSize)
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name (e.g., "ja4s")
	d.Next()

	// Check if there's a block with options
	for d.NextBlock(0) {
		switch d.Val() {
		case "max_capture_bytes":
			if !d.NextArg() {
				return d.ArgErr()
			}
			val, err := strconv.Atoi(d.Val())
			if err != nil {
				return d.Errf("invalid max_capture_bytes value: %v", err)
			}
			lw.MaxCaptureBytes = val

		case "protocol":
			if !d.NextArg() {
				return d.ArgErr()
			}
			lw.Protocol = d.Val()

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// WrapListener wraps the provided listener with the JA4S capturing logic.
func (lw *ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	return &trackingListener{
		Listener: ln,
		cfg: trackerConfig{
			maxBytes: lw.MaxCaptureBytes,
			proto:    lw.protocolByte,
			logger:   lw.logger,
		},
	}
}

type trackingListener struct {
	net.Listener
	cfg trackerConfig
}

func (tl *trackingListener) Accept() (net.Conn, error) {
	conn, err := tl.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return newTrackedConn(conn, tl.cfg), nil
}

type trackerConfig struct {
	maxBytes int
	proto    byte
	logger   *zap.Logger
}

// JA4SProvider exposes an already computed JA4S fingerprint for a connection.
type JA4SProvider interface {
	JA4S() (string, error)
}

type trackedConn struct {
	net.Conn
	tracker *serverHelloTracker
}

func newTrackedConn(conn net.Conn, cfg trackerConfig) net.Conn {
	return &trackedConn{
		Conn:    conn,
		tracker: newServerHelloTracker(cfg),
	}
}

func (tc *trackedConn) Write(p []byte) (int, error) {
	if tc.tracker != nil {
		tc.tracker.Observe(p)
	}
	return tc.Conn.Write(p)
}

func (tc *trackedConn) JA4S() (string, error) {
	if tc.tracker == nil {
		return "", ErrUnavailable
	}
	return tc.tracker.Result()
}

// serverHelloTracker keeps the first TLS record that contains the server hello
// message and runs it through the go-ja4 parser.
type serverHelloTracker struct {
	config trackerConfig

	mu          sync.Mutex
	buffer      []byte
	completed   bool
	fingerprint string
	err         error
}

const (
	minRecordSize = 5
)

// ErrUnavailable signals that the JA4S fingerprint could not be computed.
var ErrUnavailable = errors.New("ja4s fingerprint unavailable")

func newServerHelloTracker(cfg trackerConfig) *serverHelloTracker {
	return &serverHelloTracker{
		config: cfg,
		buffer: make([]byte, 0, cfg.maxBytes),
	}
}

// Observe records outbound TLS data while waiting for the first ServerHello
// record to show up.
func (sht *serverHelloTracker) Observe(p []byte) {
	sht.mu.Lock()
	defer sht.mu.Unlock()

	if sht.completed || len(p) == 0 {
		return
	}

	remaining := sht.config.maxBytes - len(sht.buffer)
	if remaining <= 0 {
		return
	}

	if len(p) > remaining {
		sht.buffer = append(sht.buffer, p[:remaining]...)
		sht.err = fmt.Errorf("server hello exceeded %d bytes", sht.config.maxBytes)
		sht.completed = true
		return
	}

	sht.buffer = append(sht.buffer, p...)
	sht.tryComputeLocked()
}

func (sht *serverHelloTracker) tryComputeLocked() {
	data := sht.buffer
	offset := 0

	for {
		if len(data[offset:]) < minRecordSize {
			return
		}

		contentType := data[offset]
		recordLength := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
		totalLen := minRecordSize + recordLength

		if len(data[offset:]) < totalLen {
			return
		}

		record := data[offset : offset+totalLen]

		if contentType != 0x16 {
			offset += totalLen
			continue
		}

		if len(record) < minRecordSize+1 {
			sht.err = fmt.Errorf("server hello record truncated")
			sht.completed = true
			return
		}

		handshakeType := record[5]
		if handshakeType != 0x02 {
			offset += totalLen
			continue
		}

		fp, err := ja4.ParseServerHelloForJA4S(record, sht.config.proto)
		if err != nil {
			sht.err = err
		} else {
			sht.fingerprint = fp
		}
		sht.completed = true
		return
	}
}

// Result returns the JA4S fingerprint (if available).
func (sht *serverHelloTracker) Result() (string, error) {
	sht.mu.Lock()
	defer sht.mu.Unlock()

	if !sht.completed {
		sht.tryComputeLocked()
	}

	if !sht.completed {
		return "", ErrUnavailable
	}

	if sht.err != nil {
		return "", sht.err
	}

	if sht.fingerprint == "" {
		return "", ErrUnavailable
	}

	return sht.fingerprint, nil
}

// parseCaddyfileHandler parses the ja4s handler directive.
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler Handler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

// Interface guards.
var (
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.Validator       = (*ListenerWrapper)(nil)
)
