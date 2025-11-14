package ja4s

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	caddy.RegisterModule(&Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4", parseCaddyfileHandler)
}

// ListenerWrapper captures inbound TLS handshake data so the client hello
// can be converted into a JA4 fingerprint.
//
// To observe the unencrypted TLS records this wrapper must appear before the
// TLS placeholder wrapper (`caddy.listeners.tls`) in the listener_wrappers
// chain.
type ListenerWrapper struct {
	// Maximum number of bytes to keep while waiting for the ClientHello record.
	// JA4 only needs the first TLS record, so small buffers are sufficient.
	MaxCaptureBytes int `json:"max_capture_bytes,omitempty"`

	// Protocol hint that is forwarded to the go-ja4 parser. Defaults to "tls".
	Protocol string `json:"protocol,omitempty"`

	logger       *zap.Logger
	protocolByte byte
}

// CaddyModule implements caddy.Module.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
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
	// Consume the directive name (e.g., "ja4")
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

// WrapListener wraps the provided listener with the JA4 capturing logic.
func (lw *ListenerWrapper) WrapListener(ln net.Listener) net.Listener {
	cache := newFingerprintCache()
	// Set global cache so handler can access it
	globalCache = cache
	return &trackingListener{
		Listener: ln,
		cfg: trackerConfig{
			maxBytes: lw.MaxCaptureBytes,
			proto:    lw.protocolByte,
			logger:   lw.logger,
			cache:    cache,
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

	// Read ClientHello upfront before TLS wraps the connection
	clientHello, err := readClientHello(conn, tl.cfg.maxBytes)
	if err != nil {
		tl.cfg.logger.Debug("failed to read ClientHello from connection",
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		// Continue anyway - return connection without JA4 capability
		return conn, nil
	}

	// Compute JA4 fingerprint immediately
	fingerprint, err := ja4.ParseClientHelloForJA4(clientHello, tl.cfg.proto)
	if err != nil {
		tl.cfg.logger.Debug("failed to parse ClientHello for JA4",
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		// Return connection with rewind capability so TLS can still read the ClientHello
		return newRewindConn(conn, clientHello), nil
	}

	tl.cfg.logger.Debug("computed JA4 fingerprint from ClientHello",
		zap.String("remote_addr", conn.RemoteAddr().String()),
		zap.String("fingerprint", fingerprint),
	)

	// Store fingerprint in cache keyed by connection address
	addr := conn.RemoteAddr().String()
	tl.cfg.cache.Set(addr, fingerprint)

	// Create a tracked connection that will clean up the cache on close
	tracked := &trackedConn{
		Conn:        newRewindConn(conn, clientHello),
		addr:        addr,
		cache:       tl.cfg.cache,
		fingerprint: fingerprint,
	}

	return tracked, nil
}

type trackerConfig struct {
	maxBytes int
	proto    byte
	logger   *zap.Logger
	cache    *fingerprintCache
}

// fingerprintCache stores JA4 fingerprints keyed by connection remote address.
// This allows us to look up fingerprints without needing to unwrap TLS connections.
type fingerprintCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

func newFingerprintCache() *fingerprintCache {
	return &fingerprintCache{
		cache: make(map[string]string),
	}
}

func (fc *fingerprintCache) Set(addr string, fingerprint string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.cache[addr] = fingerprint
}

func (fc *fingerprintCache) Get(addr string) (string, bool) {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	fp, ok := fc.cache[addr]
	return fp, ok
}

func (fc *fingerprintCache) Clear(addr string) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	delete(fc.cache, addr)
}

// JA4Provider exposes the computed JA4 (client) fingerprint for a connection.
type JA4Provider interface {
	// JA4 returns the client TLS fingerprint
	JA4() (string, error)
}

type trackedConn struct {
	net.Conn
	addr        string
	cache       *fingerprintCache
	fingerprint string
	mu          sync.RWMutex
}

func (tc *trackedConn) Close() error {
	// Clean up cache entry when connection closes
	if tc.cache != nil && tc.addr != "" {
		tc.cache.Clear(tc.addr)
	}
	return tc.Conn.Close()
}

func (tc *trackedConn) JA4() (string, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	if tc.fingerprint == "" {
		return "", ErrUnavailable
	}
	return tc.fingerprint, nil
}

// GetFingerprintFromCache retrieves a JA4 fingerprint from the cache by connection address.
// This is used by the handler to look up fingerprints without needing to unwrap TLS connections.
func GetFingerprintFromCache(addr string) (string, error) {
	// This will be set by the listener wrapper's cache
	// For now, we'll need to pass the cache through the context or make it global
	// Actually, let's make it a package-level variable that gets set
	if globalCache == nil {
		return "", ErrUnavailable
	}
	fp, ok := globalCache.Get(addr)
	if !ok {
		return "", ErrUnavailable
	}
	return fp, nil
}

// globalCache is set by the listener wrapper and used by the handler
var globalCache *fingerprintCache

const (
	minRecordSize = 5
	// TLS record type constants
	tlsRecordTypeHandshake = 0x16
	// TLS handshake type constants
	tlsHandshakeTypeClientHello = 0x01
)

// ErrUnavailable signals that the JA4 fingerprint could not be computed.
var ErrUnavailable = errors.New("ja4 fingerprint unavailable")

// readClientHello reads the ClientHello TLS record from the connection.
// This is based on the approach used in caddy-ja3:
// https://github.com/rushiiMachine/caddy-ja3
func readClientHello(r io.Reader, maxBytes int) ([]byte, error) {
	// Read the TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	// Check if it's a TLS handshake record
	if header[0] != tlsRecordTypeHandshake {
		return nil, fmt.Errorf("not a TLS handshake record (got 0x%02x)", header[0])
	}

	// Get the record length
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > maxBytes {
		return nil, fmt.Errorf("record length %d exceeds max bytes %d", recordLength, maxBytes)
	}

	// Read the rest of the record
	record := make([]byte, 5+recordLength)
	copy(record, header)
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		return nil, fmt.Errorf("failed to read TLS record body: %w", err)
	}

	return record, nil
}

// rewindConn creates a connection that allows the ClientHello data to be read again.
// This is necessary because we read the ClientHello upfront, but TLS needs to read it too.
type rewindConn struct {
	net.Conn
	buf    []byte
	offset int
	mu     sync.Mutex
}

func newRewindConn(conn net.Conn, data []byte) net.Conn {
	return &rewindConn{
		Conn: conn,
		buf:  data,
	}
}

func (rc *rewindConn) Read(p []byte) (int, error) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// First, serve the buffered data
	if rc.offset < len(rc.buf) {
		n := copy(p, rc.buf[rc.offset:])
		rc.offset += n
		return n, nil
	}

	// Once buffered data is exhausted, read from the underlying connection
	return rc.Conn.Read(p)
}

// parseCaddyfileHandler parses the ja4 handler directive.
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
