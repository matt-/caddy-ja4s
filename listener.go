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
	tracked := newTrackedConn(conn, tl.cfg)
	tl.cfg.logger.Info("wrapped connection with JA4S tracker",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("conn_type", fmt.Sprintf("%T", conn)),
	)
	return tracked, nil
}

type trackerConfig struct {
	maxBytes int
	proto    byte
	logger   *zap.Logger
}

// JA4PlusProvider exposes all computed JA4+ fingerprints for a connection.
type JA4PlusProvider interface {
	// JA4S returns the server TLS fingerprint
	JA4S() (string, error)
	// JA4 returns the client TLS fingerprint (if available)
	JA4() (string, error)
	// JA4X returns the certificate fingerprint (if available)
	JA4X() (string, error)
}

type trackedConn struct {
	net.Conn
	serverTracker *serverHelloTracker
	clientTracker *clientHelloTracker
}

func newTrackedConn(conn net.Conn, cfg trackerConfig) net.Conn {
	return &trackedConn{
		Conn:          conn,
		serverTracker: newServerHelloTracker(cfg),
		clientTracker: newClientHelloTracker(cfg),
	}
}

func (tc *trackedConn) Read(p []byte) (int, error) {
	n, err := tc.Conn.Read(p)
	if n > 0 && tc.clientTracker != nil {
		// Capture ClientHello from incoming data
		tc.clientTracker.Observe(p[:n])
	}
	return n, err
}

func (tc *trackedConn) Write(p []byte) (int, error) {
	if tc.serverTracker != nil {
		// Log first few writes to see if we're capturing data
		if len(p) > 0 && tc.serverTracker.config.logger != nil {
			firstBytes := 10
			if len(p) < firstBytes {
				firstBytes = len(p)
			}
			tc.serverTracker.config.logger.Debug("observed TLS data",
				zap.Int("bytes", len(p)),
				zap.String("first_bytes", fmt.Sprintf("%x", p[:firstBytes])),
			)
		}
		tc.serverTracker.Observe(p)
	}
	return tc.Conn.Write(p)
}

func (tc *trackedConn) JA4S() (string, error) {
	if tc.serverTracker == nil {
		return "", ErrUnavailable
	}
	result, err := tc.serverTracker.Result()
	if err != nil && tc.serverTracker.config.logger != nil {
		tc.serverTracker.config.logger.Debug("JA4S() returned error",
			zap.String("error", err.Error()),
		)
	} else if result != "" && tc.serverTracker.config.logger != nil {
		tc.serverTracker.config.logger.Debug("JA4S() returned fingerprint",
			zap.String("fingerprint", result),
		)
	}
	return result, err
}

func (tc *trackedConn) JA4() (string, error) {
	if tc.clientTracker == nil {
		return "", ErrUnavailable
	}
	return tc.clientTracker.Result()
}

func (tc *trackedConn) JA4X() (string, error) {
	// JA4X requires certificate info, which we'll get from TLS connection state
	// This will be handled in the handler where we have access to the TLS connection
	return "", ErrUnavailable
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
		if sht.config.logger != nil {
			sht.config.logger.Warn("buffer full, cannot capture more data",
				zap.Int("buffer_len", len(sht.buffer)),
				zap.Int("max_bytes", sht.config.maxBytes),
			)
		}
		return
	}

	if len(p) > remaining {
		sht.buffer = append(sht.buffer, p[:remaining]...)
		sht.err = fmt.Errorf("server hello exceeded %d bytes", sht.config.maxBytes)
		sht.completed = true
		if sht.config.logger != nil {
			sht.config.logger.Warn("server hello exceeded max bytes",
				zap.Int("max_bytes", sht.config.maxBytes),
			)
		}
		return
	}

	sht.buffer = append(sht.buffer, p...)
	if sht.config.logger != nil {
		sht.config.logger.Debug("appended data to buffer",
			zap.Int("bytes", len(p)),
			zap.Int("total_buffer_len", len(sht.buffer)),
		)
	}
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
		if sht.config.logger != nil {
			sht.config.logger.Debug("fingerprint not completed yet, trying to compute",
				zap.Int("buffer_len", len(sht.buffer)),
			)
		}
		sht.tryComputeLocked()
	}

	if !sht.completed {
		if sht.config.logger != nil {
			sht.config.logger.Debug("fingerprint computation not completed",
				zap.Int("buffer_len", len(sht.buffer)),
			)
		}
		return "", ErrUnavailable
	}

	if sht.err != nil {
		if sht.config.logger != nil {
			sht.config.logger.Warn("fingerprint computation error",
				zap.String("error", sht.err.Error()),
			)
		}
		return "", sht.err
	}

	if sht.fingerprint == "" {
		if sht.config.logger != nil {
			sht.config.logger.Warn("fingerprint is empty after computation")
		}
		return "", ErrUnavailable
	}

	if sht.config.logger != nil {
		sht.config.logger.Info("JA4S fingerprint computed successfully",
			zap.String("fingerprint", sht.fingerprint),
		)
	}

	return sht.fingerprint, nil
}

// clientHelloTracker keeps the first TLS record that contains the client hello
// message and runs it through the go-ja4 parser.
type clientHelloTracker struct {
	config trackerConfig

	mu          sync.Mutex
	buffer      []byte
	completed   bool
	fingerprint string
	err         error
}

func newClientHelloTracker(cfg trackerConfig) *clientHelloTracker {
	return &clientHelloTracker{
		config: cfg,
		buffer: make([]byte, 0, cfg.maxBytes),
	}
}

// Observe records inbound TLS data while waiting for the first ClientHello
// record to show up.
func (cht *clientHelloTracker) Observe(p []byte) {
	cht.mu.Lock()
	defer cht.mu.Unlock()

	if cht.completed || len(p) == 0 {
		return
	}

	remaining := cht.config.maxBytes - len(cht.buffer)
	if remaining <= 0 {
		return
	}

	if len(p) > remaining {
		cht.buffer = append(cht.buffer, p[:remaining]...)
		cht.err = fmt.Errorf("client hello exceeded %d bytes", cht.config.maxBytes)
		cht.completed = true
		return
	}

	cht.buffer = append(cht.buffer, p...)
	cht.tryComputeLocked()
}

func (cht *clientHelloTracker) tryComputeLocked() {
	data := cht.buffer
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
			cht.err = fmt.Errorf("client hello record truncated")
			cht.completed = true
			return
		}

		handshakeType := record[5]
		if handshakeType != 0x01 {
			offset += totalLen
			continue
		}

		fp, err := ja4.ParseClientHelloForJA4(record, cht.config.proto)
		if err != nil {
			cht.err = err
		} else {
			cht.fingerprint = fp
		}
		cht.completed = true
		return
	}
}

// Result returns the JA4 fingerprint (if available).
func (cht *clientHelloTracker) Result() (string, error) {
	cht.mu.Lock()
	defer cht.mu.Unlock()

	if !cht.completed {
		cht.tryComputeLocked()
	}

	if !cht.completed {
		return "", ErrUnavailable
	}

	if cht.err != nil {
		return "", cht.err
	}

	if cht.fingerprint == "" {
		return "", ErrUnavailable
	}

	return cht.fingerprint, nil
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
