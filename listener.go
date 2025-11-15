package ja4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"

	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
	// Use a singleton cache that persists across reconfigurations
	// This ensures fingerprints aren't lost when Caddy reconfigures
	if globalCache == nil {
		globalCache = newFingerprintCache()
		lw.logger.Debug("created new global JA4 fingerprint cache")
	} else {
		lw.logger.Debug("reusing existing global JA4 fingerprint cache")
	}

	return &trackingListener{
		Listener: ln,
		cfg: trackerConfig{
			maxBytes: lw.MaxCaptureBytes,
			proto:    lw.protocolByte,
			logger:   lw.logger,
			cache:    globalCache,
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
	// For HTTP connections (port 80), this will fail, which is expected
	// We need to use a peek/rewind approach to avoid consuming bytes from HTTP connections
	clientHello, peekedBytes, err := readClientHelloWithPeek(conn, tl.cfg.maxBytes)
	if err != nil {
		// This is expected for HTTP connections (no TLS handshake)
		// Only log at debug level to avoid noise
		tl.cfg.logger.Debug("no ClientHello found (likely HTTP connection)",
			zap.String("remote_addr", conn.RemoteAddr().String()),
			zap.Error(err),
		)
		// We must rewind the bytes we peeked, otherwise HTTP requests will be broken
		// Create a rewind connection with the peeked bytes so they can be replayed
		return newRewindConn(conn, peekedBytes), nil
	}

	// Compute JA4 fingerprint using our own implementation
	fingerprint, err := computeJA4(clientHello, tl.cfg.proto, tl.cfg.logger)
	if err != nil {
		tl.cfg.logger.Debug("failed to compute JA4 fingerprint",
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
	// Normalize the address to handle IPv6 brackets and ensure consistent format
	addr := normalizeAddr(conn.RemoteAddr().String())
	tl.cfg.cache.Set(addr, fingerprint)

	tl.cfg.logger.Debug("stored JA4 fingerprint in cache",
		zap.String("addr", addr),
		zap.String("fingerprint", fingerprint),
	)

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

// readClientHello reads the ClientHello TLS record from the connection.
// This is based on the approach used in caddy-ja3:
// https://github.com/rushiiMachine/caddy-ja3
func readClientHello(r io.Reader, maxBytes int) ([]byte, error) {
	clientHello, _, err := readClientHelloWithPeek(r, maxBytes)
	return clientHello, err
}

// readClientHelloWithPeek reads the ClientHello TLS record and also returns
// the peeked bytes so they can be rewound if it's not a TLS connection.
// Returns: (clientHello, peekedBytes, error)
// - If TLS: clientHello contains the full record, peekedBytes is nil
// - If not TLS: clientHello is nil, peekedBytes contains the bytes we read (for rewinding)
func readClientHelloWithPeek(r io.Reader, maxBytes int) ([]byte, []byte, error) {
	// Read the TLS record header (5 bytes)
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, nil, fmt.Errorf("failed to read TLS record header: %w", err)
	}

	// Check if it's a TLS handshake record
	if header[0] != tlsRecordTypeHandshake {
		// Not TLS - return the header bytes so they can be rewound
		return nil, header, fmt.Errorf("not a TLS handshake record (got 0x%02x)", header[0])
	}

	// Get the record length
	recordLength := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLength > maxBytes {
		// Return the header bytes we read so they can be rewound
		return nil, header, fmt.Errorf("record length %d exceeds max bytes %d", recordLength, maxBytes)
	}

	// Read the rest of the record
	record := make([]byte, 5+recordLength)
	copy(record, header)
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		// Return the header bytes we read so they can be rewound
		return nil, header, fmt.Errorf("failed to read TLS record body: %w", err)
	}

	// Successfully read TLS record - no need to return peeked bytes
	return record, nil, nil
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

// isGREASEValue checks if a value is a GREASE (Generate Random Extensions And Sustain Extensibility) value.
// GREASE values are used to prevent ossification and should be filtered in JA4 calculations.
// Note: 0x0000 is NOT GREASE - it's the server_name (SNI) extension and should be included.
func isGREASEValue(value uint16) bool {
	// 0x0000 is server_name (SNI) - NOT GREASE, must be included
	if value == 0x0000 {
		return false
	}

	// GREASE values follow specific patterns:
	// Pattern 1: 0x[a-f]a[a-f]a where the first and third nibbles match, and second/fourth are 0xa
	// Pattern 2: 0x[a-f][a-f][a-f][a-f] where all nibbles are the same (but not 0x0000)
	nibble1 := (value >> 12) & 0xF
	nibble2 := (value >> 8) & 0xF
	nibble3 := (value >> 4) & 0xF
	nibble4 := value & 0xF

	// Pattern 1: Paired nibbles with 0xa in positions 2 and 4 (0x0a0a, 0x1a1a, 0x2a2a, etc.)
	if nibble1 == nibble3 && nibble2 == 0xa && nibble4 == 0xa {
		return true
	}

	// Pattern 2: All nibbles the same (0xaaaa, 0xbbbb, 0xcccc, 0xdddd, 0xeeee, 0xffff)
	// But exclude 0x0000 (already handled above)
	if nibble1 == nibble2 && nibble2 == nibble3 && nibble3 == nibble4 && value != 0x0000 {
		return true
	}

	// Pattern 3: Specific known GREASE values
	greaseValues := []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}
	for _, gv := range greaseValues {
		if value == gv {
			return true
		}
	}

	return false
}

// computeJA4 computes the JA4 fingerprint from a ClientHello message.
// Format: t{TLS_version}d{SNI}{cipher_count}{ext_count}{ALPN}_<cipher_hash>_<ext_hash>
func computeJA4(payload []byte, protocol byte, _ *zap.Logger) (string, error) {
	offset := 0

	// Skip TLS/DTLS record header (5 bytes)
	if len(payload) < 5 {
		return "", fmt.Errorf("payload too short for TLS record header")
	}
	offset += 5

	// Handshake Type and Length
	if offset+4 > len(payload) {
		return "", fmt.Errorf("payload too short for handshake header")
	}
	handshakeType := payload[offset]
	handshakeLength := int(payload[offset+1])<<16 | int(payload[offset+2])<<8 | int(payload[offset+3])
	offset += 4

	// CLIENT_HELLO
	if handshakeType != 0x01 {
		return "", fmt.Errorf("not a Client Hello message")
	}

	if offset+handshakeLength > len(payload) {
		return "", fmt.Errorf("incomplete Client Hello message")
	}

	// Start building the JA4 fingerprint
	var ja4Str strings.Builder
	ja4Str.WriteByte(protocol)

	// Client Version
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for client version")
	}
	clientVersion := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2

	// Skip Random (32 bytes)
	if offset+32 > len(payload) {
		return "", fmt.Errorf("payload too short for random")
	}
	offset += 32

	// Session ID
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for session ID length")
	}
	sessionIDLen := int(payload[offset])
	offset += 1 + sessionIDLen

	// Cipher Suites
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	if offset+cipherSuitesLen > len(payload) {
		return "", fmt.Errorf("incomplete cipher suites data")
	}

	ciphers := make([]uint16, 0)
	for i := 0; i < cipherSuitesLen; i += 2 {
		cipher := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if !isGREASEValue(cipher) {
			ciphers = append(ciphers, cipher)
		}
	}
	offset += cipherSuitesLen

	// Compression Methods
	if offset+1 > len(payload) {
		return "", fmt.Errorf("payload too short for compression methods length")
	}
	compressionMethodsLen := int(payload[offset])
	offset += 1 + compressionMethodsLen

	// Extensions
	if offset+2 > len(payload) {
		return "", fmt.Errorf("payload too short for extensions length")
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2

	extensions := make([]uint16, 0)
	extensionCount := 0
	sniFound := false
	alpn := "00"
	signatureAlgorithms := make([]uint16, 0)
	supportedVersionsFound := false
	highestSupportedVersion := uint16(0)

	extensionsEnd := offset + extensionsLen

	for offset+4 <= extensionsEnd && offset+4 <= len(payload) {
		extType := binary.BigEndian.Uint16(payload[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
		offset += 4

		if offset+extLen > extensionsEnd || offset+extLen > len(payload) {
			break
		}

		extDataEnd := offset + extLen

		if isGREASEValue(extType) {
			// Skip GREASE extension
			offset = extDataEnd
			continue
		}

		// Exclude pre_shared_key (0x0029) from count and hash
		// pre_shared_key is session-resumption-specific and would cause inconsistent fingerprints
		if extType == 0x0029 {
			offset = extDataEnd
			continue
		}

		// Count all non-GREASE extensions (including SNI and ALPN, but excluding pre_shared_key)
		extensionCount++

		// Exclude SNI (0x0000) and ALPN (0x0010) from the hash (but still count them)
		if extType != 0x0000 && extType != 0x0010 {
			extensions = append(extensions, extType)
		}

		if extType == 0x0000 { // SNI_EXT
			sniFound = true
		}

		if extType == 0x0010 && extLen > 0 { // ALPN_EXT
			alpnOffset := offset
			if alpnOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for ALPN list length")
			}
			alpnListLen := int(binary.BigEndian.Uint16(payload[alpnOffset : alpnOffset+2]))
			alpnOffset += 2
			if alpnOffset+alpnListLen > extDataEnd {
				return "", fmt.Errorf("incomplete ALPN list")
			}
			if alpnListLen > 0 {
				if alpnOffset+1 > extDataEnd {
					return "", fmt.Errorf("payload too short for ALPN string length")
				}
				alpnStrLen := int(payload[alpnOffset])
				alpnOffset += 1
				if alpnOffset+alpnStrLen > extDataEnd {
					return "", fmt.Errorf("incomplete ALPN string")
				}
				if alpnStrLen > 0 {
					alpnValue := payload[alpnOffset : alpnOffset+alpnStrLen]
					alpnStr := string(alpnValue)
					// ALPN should be 2 characters (e.g., "h2", "h3")
					if len(alpnStr) >= 2 {
						alpn = alpnStr[:2]
					} else if len(alpnStr) == 1 {
						alpn = alpnStr + "0"
					}
				}
			}
		}

		// SIGNATURE_ALGORITHMS_EXT (0x000d)
		if extType == 0x000d {
			sigOffset := offset
			if sigOffset+2 > extDataEnd {
				return "", fmt.Errorf("payload too short for signature algorithms length")
			}
			sigAlgsLen := int(binary.BigEndian.Uint16(payload[sigOffset : sigOffset+2]))
			sigOffset += 2
			if sigOffset+sigAlgsLen > extDataEnd {
				return "", fmt.Errorf("incomplete signature algorithms data")
			}
			for j := 0; j < sigAlgsLen; j += 2 {
				sigAlgo := binary.BigEndian.Uint16(payload[sigOffset+j : sigOffset+j+2])
				if !isGREASEValue(sigAlgo) {
					signatureAlgorithms = append(signatureAlgorithms, sigAlgo)
				}
			}
		}

		// SUPPORTED_VERSIONS_EXT (0x002b)
		if extType == 0x002b {
			supportedVersionsFound = true
			svOffset := offset
			if svOffset+1 > extDataEnd {
				return "", fmt.Errorf("payload too short for supported versions length")
			}
			svLen := int(payload[svOffset])
			svOffset += 1
			if svOffset+svLen > extDataEnd {
				return "", fmt.Errorf("incomplete supported versions data")
			}
			for j := 0; j < svLen; j += 2 {
				if svOffset+j+2 > extDataEnd {
					break
				}
				version := binary.BigEndian.Uint16(payload[svOffset+j : svOffset+j+2])
				if !isGREASEValue(version) && version > highestSupportedVersion {
					highestSupportedVersion = version
				}
			}
		}

		// Move to the next extension
		offset = extDataEnd
	}

	// Determine TLS Version
	var tlsVersion string
	if supportedVersionsFound {
		tlsVersion = mapTLSVersion(highestSupportedVersion)
	} else {
		tlsVersion = mapTLSVersion(clientVersion)
	}

	// SNI Indicator
	sniIndicator := 'i'
	if sniFound {
		sniIndicator = 'd'
	}

	// Cipher Count
	cipherCountDisplay := len(ciphers)
	if cipherCountDisplay > 99 {
		cipherCountDisplay = 99
	}

	// Extension Count (all non-GREASE extensions, including SNI and ALPN)
	extensionCountDisplay := extensionCount
	if extensionCountDisplay > 99 {
		extensionCountDisplay = 99
	}

	// ALPN Characters
	alpnFirstChar := '0'
	alpnLastChar := '0'
	if len(alpn) >= 2 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = rune(alpn[1])
	} else if len(alpn) == 1 {
		alpnFirstChar = rune(alpn[0])
		alpnLastChar = '0'
	}

	// Build the complete JA4 prefix
	ja4Str.WriteString(tlsVersion)
	ja4Str.WriteByte(byte(sniIndicator))
	ja4Str.WriteString(fmt.Sprintf("%02d%02d%c%c_", cipherCountDisplay, extensionCountDisplay, alpnFirstChar, alpnLastChar))

	// Sort ciphers
	sort.Slice(ciphers, func(i, j int) bool { return ciphers[i] < ciphers[j] })

	// Compute JA4_b (Cipher Hash) - truncated SHA256
	var ja4b string
	if len(ciphers) == 0 {
		ja4b = "000000000000"
	} else {
		cipherStr := buildHexList(ciphers)
		ja4b = computeTruncatedSHA256(cipherStr)
	}
	ja4Str.WriteString(ja4b)
	ja4Str.WriteByte('_')

	// Sort extensions
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })

	// Compute JA4_c (Extension Hash) - truncated SHA256
	extStr := buildHexList(extensions)
	if len(signatureAlgorithms) > 0 {
		// Note: Signature algorithms should NOT be sorted - use order from ClientHello
		extStr += "_"
		extStr += buildHexList(signatureAlgorithms)
	}

	var ja4c string
	if len(extensions) == 0 {
		ja4c = "000000000000"
	} else {
		ja4c = computeTruncatedSHA256(extStr)
	}
	ja4Str.WriteString(ja4c)

	return ja4Str.String(), nil
}

// mapTLSVersion maps TLS version to JA4 format
func mapTLSVersion(version uint16) string {
	switch version {
	case 0x0300:
		return "00" // SSL 3.0
	case 0x0301:
		return "01" // TLS 1.0
	case 0x0302:
		return "02" // TLS 1.1
	case 0x0303:
		return "13" // TLS 1.2
	case 0x0304:
		return "13" // TLS 1.3
	default:
		return "00"
	}
}

// buildHexList builds a hex list string from uint16 values
func buildHexList(values []uint16) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// computeTruncatedSHA256 computes SHA256 and returns first 12 hex characters
func computeTruncatedSHA256(data string) string {
	hash := sha256.Sum256([]byte(data))
	hexHash := hex.EncodeToString(hash[:])
	return hexHash[:12]
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
