package ja4s

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Handler injects the JA4 (client TLS) fingerprint into request/response metadata so it can
// be consumed by other handlers (for example, to pass it upstream or log it).
type Handler struct {
	// Optional HTTP header that should carry the fingerprint to upstream handlers.
	RequestHeader string `json:"request_header,omitempty"`

	// Optional response header written back to clients.
	ResponseHeader string `json:"response_header,omitempty"`

	// Optional variable key for caddyhttp's context table. The value can be used
	// via the `{http.vars.<key>}` placeholder. Defaults to "ja4".
	VarName string `json:"var_name,omitempty"`

	// If true, requests will fail when a fingerprint cannot be produced.
	Require bool `json:"require,omitempty"`

	// List of JA4 fingerprints to block. Requests with matching fingerprints will be rejected.
	BlockedJA4s []string `json:"blocked_ja4s,omitempty"`

	// Path to a file containing JA4 fingerprints to block (one per line).
	BlockFile string `json:"block_file,omitempty"`

	logger     *zap.Logger
	blockedSet map[string]bool // For efficient lookup
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets defaults.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if h.VarName == "" {
		h.VarName = "ja4"
	}

	// Build blocked set from both list and file
	h.blockedSet = make(map[string]bool)

	// Add fingerprints from the list
	for _, fp := range h.BlockedJA4s {
		if fp != "" {
			h.blockedSet[fp] = true
		}
	}

	// Load fingerprints from file if specified
	if h.BlockFile != "" {
		data, err := os.ReadFile(h.BlockFile)
		if err != nil {
			return fmt.Errorf("failed to read block file %s: %w", h.BlockFile, err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			// Skip empty lines and comments
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			h.blockedSet[line] = true
		}

		h.logger.Info("loaded blocked JA4 fingerprints from file",
			zap.String("file", h.BlockFile),
			zap.Int("count", len(h.blockedSet)),
		)
	}

	if len(h.blockedSet) > 0 {
		h.logger.Info("JA4 blocking enabled",
			zap.Int("blocked_count", len(h.blockedSet)),
		)
	}

	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name (e.g., "ja4")
	d.Next()

	// Parse options in the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "request_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.RequestHeader = d.Val()

		case "response_header":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.ResponseHeader = d.Val()

		case "var_name":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.VarName = d.Val()

		case "require":
			h.Require = true

		case "block":
			// Parse multiple JA4 fingerprints to block
			for d.NextArg() {
				h.BlockedJA4s = append(h.BlockedJA4s, d.Val())
			}

		case "block_file":
			if !d.NextArg() {
				return d.ArgErr()
			}
			h.BlockFile = d.Val()

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// ServeHTTP makes the JA4 fingerprint available downstream.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("panic in JA4 handler",
				zap.Any("panic", rec),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("host", r.Host),
			)
			panic(rec) // Re-panic after logging
		}
	}()

	h.logger.Debug("JA4 handler called",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	)

	// Extract JA4 fingerprint
	fingerprint, err := JA4FromRequest(r, h.logger)
	if err != nil {
		h.logger.Warn("failed to extract JA4 fingerprint",
			zap.String("error", err.Error()),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
		)
		if h.Require {
			return caddyhttp.Error(http.StatusPreconditionFailed, fmt.Errorf("ja4 fingerprint missing: %w", err))
		}
		return next.ServeHTTP(w, r)
	}

	// Check if fingerprint is blocked
	if h.blockedSet[fingerprint] {
		h.logger.Warn("request blocked due to JA4 fingerprint",
			zap.String("fingerprint", fingerprint),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
		)
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("request blocked: JA4 fingerprint %s is not allowed", fingerprint))
	}

	h.logger.Debug("JA4 fingerprint extracted successfully",
		zap.String("fingerprint", fingerprint),
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	)

	if h.RequestHeader != "" {
		r.Header.Set(h.RequestHeader, fingerprint)
	}

	if h.ResponseHeader != "" {
		w.Header().Set(h.ResponseHeader, fingerprint)
	}

	if h.VarName != "" {
		caddyhttp.SetVar(r.Context(), h.VarName, fingerprint)
	}

	return next.ServeHTTP(w, r)
}

// JA4FromRequest extracts the JA4 (client) fingerprint from the underlying net.Conn if it
// is available.
func JA4FromRequest(r *http.Request, logger *zap.Logger) (string, error) {
	conn, err := connectionFromRequest(r, logger)
	if err != nil {
		return "", err
	}

	logger.Debug("connection found in request context",
		zap.String("conn_type", fmt.Sprintf("%T", conn)),
	)

	// First, try direct type assertion
	provider, ok := conn.(JA4Provider)
	if !ok {
		// If it's a TLS connection, try to unwrap it to get the underlying connection
		if tlsConn, isTLS := conn.(*tls.Conn); isTLS {
			var err error
			provider, err = unwrapTLSConnection(tlsConn, logger)
			if err != nil {
				logger.Warn("connection does not implement JA4Provider",
					zap.String("conn_type", fmt.Sprintf("%T", conn)),
					zap.Error(err),
				)
				return "", ErrUnavailable
			}
		} else {
			logger.Warn("connection does not implement JA4Provider",
				zap.String("conn_type", fmt.Sprintf("%T", conn)),
			)
			return "", ErrUnavailable
		}
	}

	logger.Debug("connection implements JA4Provider, calling JA4()")
	return provider.JA4()
}

// unwrapTLSConnection extracts the underlying connection from a tls.Conn using reflection.
// This is necessary because tls.Conn's underlying connection field is unexported.
// While this uses unsafe internally via reflect.NewAt, it provides a more structured
// and type-safe API than direct unsafe.Pointer manipulation.
func unwrapTLSConnection(tlsConn *tls.Conn, logger *zap.Logger) (JA4Provider, error) {
	defer func() {
		if rec := recover(); rec != nil {
			logger.Warn("panic while accessing TLS connection field",
				zap.Any("panic", rec),
			)
		}
	}()

	logger.Debug("connection is TLS, attempting to unwrap",
		zap.String("tls_conn_type", fmt.Sprintf("%T", tlsConn)),
	)

	// Use reflection to access the unexported "conn" field
	connValue := reflect.ValueOf(tlsConn).Elem()
	connField := connValue.FieldByName("conn")

	if !connField.IsValid() {
		return nil, fmt.Errorf("could not find 'conn' field in tls.Conn")
	}

	// For unexported fields, we need to use reflect.NewAt to create a value
	// that can be interfaced. This requires converting the field's address
	// to unsafe.Pointer, but uses reflection's structured API rather than
	// direct unsafe pointer manipulation, making it safer and more maintainable.
	if !connField.CanInterface() {
		connField = reflect.NewAt(connField.Type(), unsafe.Pointer(connField.UnsafeAddr())).Elem()
	}

	underlyingConn, ok := connField.Interface().(net.Conn)
	if !ok || underlyingConn == nil {
		return nil, fmt.Errorf("underlying connection field is not a valid net.Conn")
	}

	logger.Debug("found underlying connection",
		zap.String("underlying_conn_type", fmt.Sprintf("%T", underlyingConn)),
	)

	provider, ok := underlyingConn.(JA4Provider)
	if !ok {
		return nil, fmt.Errorf("underlying connection does not implement JA4Provider (type: %T)", underlyingConn)
	}

	logger.Debug("underlying connection implements JA4Provider")
	return provider, nil
}

func connectionFromRequest(r *http.Request, logger *zap.Logger) (net.Conn, error) {
	if r == nil {
		return nil, errors.New("request is nil")
	}

	conn, ok := r.Context().Value(caddyhttp.ConnCtxKey).(net.Conn)
	if !ok || conn == nil {
		logger.Debug("connection not found in request context",
			zap.Bool("has_value", r.Context().Value(caddyhttp.ConnCtxKey) != nil),
		)
		return nil, ErrUnavailable
	}

	return conn, nil
}

// Interface guards.
var (
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)
