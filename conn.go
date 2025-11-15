package ja4

import (
	"bufio"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// JA4Provider exposes the computed JA4 (client) fingerprint for a connection.
type JA4Provider interface {
	// JA4 returns the client TLS fingerprint
	JA4() (string, error)
}

type trackerConfig struct {
	maxBytes int
	proto    byte
	logger   *zap.Logger
	cache    *fingerprintCache
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

	// Wrap the connection to intercept the first Read() call and peek at ClientHello
	// This approach uses bufio.Reader.Peek() which doesn't consume bytes, so no rewinding needed
	wrapped := &ja4ConnWrapper{
		Conn:      conn,
		cfg:       tl.cfg,
		done:      false,
		bufReader: bufio.NewReader(conn),
	}

	// Create a tracked connection that will clean up the cache on close
	tracked := &trackedConn{
		Conn:  wrapped,
		addr:  normalizeAddr(conn.RemoteAddr().String()),
		cache: tl.cfg.cache,
	}

	return tracked, nil
}

type trackedConn struct {
	net.Conn
	addr  string
	cache *fingerprintCache
	mu    sync.RWMutex
}

func (tc *trackedConn) Close() error {
	// Clean up cache entry when connection closes
	if tc.cache != nil && tc.addr != "" {
		tc.cache.Clear(tc.addr)
	}
	return tc.Conn.Close()
}

func (tc *trackedConn) JA4() (string, error) {
	// Look up fingerprint from cache by address
	if tc.cache == nil || tc.addr == "" {
		return "", ErrUnavailable
	}
	fp, ok := tc.cache.Get(tc.addr)
	if !ok {
		return "", ErrUnavailable
	}
	return fp, nil
}

// ja4ConnWrapper wraps a connection and intercepts the first Read() call to peek at ClientHello.
// This uses bufio.Reader.Peek() which doesn't consume bytes, so TLS can read normally afterward.
type ja4ConnWrapper struct {
	net.Conn
	cfg       trackerConfig
	done      bool
	bufReader *bufio.Reader
	mu        sync.Mutex
}

func (w *ja4ConnWrapper) Read(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// On first Read(), peek at ClientHello to compute JA4 fingerprint
	if !w.done {
		w.done = true
		w.captureClientHello()
	}

	// Now read normally - bufio.Reader handles buffering automatically
	return w.bufReader.Read(p)
}

// captureClientHello peeks at the ClientHello message without consuming bytes.
func (w *ja4ConnWrapper) captureClientHello() {
	// Peek at the TLS record header (5 bytes)
	header, err := w.bufReader.Peek(5)
	if err != nil {
		// Not enough data or not TLS - this is fine for HTTP connections
		w.cfg.logger.Debug("could not peek TLS header (likely HTTP connection)",
			zap.String("remote_addr", w.Conn.RemoteAddr().String()),
			zap.Error(err),
		)
		return
	}

	// Check if it's a TLS handshake record
	if header[0] != tlsRecordTypeHandshake {
		// Not TLS - this is fine, just return
		return
	}

	// Get the record length
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > w.cfg.maxBytes {
		w.cfg.logger.Debug("ClientHello record too large",
			zap.String("remote_addr", w.Conn.RemoteAddr().String()),
			zap.Int("record_length", recordLength),
			zap.Int("max_bytes", w.cfg.maxBytes),
		)
		return
	}

	// Peek at the full ClientHello record (header + body)
	peekedData, err := w.bufReader.Peek(5 + recordLength)
	if err != nil {
		w.cfg.logger.Debug("could not peek full ClientHello record",
			zap.String("remote_addr", w.Conn.RemoteAddr().String()),
			zap.Error(err),
		)
		return
	}

	// Copy the peeked data since Peek() returns a slice that's only valid until the next read
	clientHello := make([]byte, len(peekedData))
	copy(clientHello, peekedData)

	// Compute JA4 fingerprint
	fingerprint, err := computeJA4(clientHello, w.cfg.proto, w.cfg.logger)
	if err != nil {
		w.cfg.logger.Debug("failed to compute JA4 fingerprint",
			zap.String("remote_addr", w.Conn.RemoteAddr().String()),
			zap.Error(err),
		)
		return
	}

	// Store fingerprint in cache keyed by connection address
	addr := normalizeAddr(w.Conn.RemoteAddr().String())
	w.cfg.cache.Set(addr, fingerprint)

	w.cfg.logger.Debug("computed and stored JA4 fingerprint",
		zap.String("remote_addr", addr),
		zap.String("fingerprint", fingerprint),
	)
}

// normalizeAddr normalizes a network address to ensure consistent format
// for cache lookups. This handles IPv6 brackets and ensures consistent formatting.
func normalizeAddr(addr string) string {
	if addr == "" {
		return addr
	}
	// Remove brackets from IPv6 addresses if present
	// Go's net package sometimes includes brackets, sometimes doesn't
	addr = strings.TrimPrefix(addr, "[")
	addr = strings.TrimSuffix(addr, "]")
	return addr
}
