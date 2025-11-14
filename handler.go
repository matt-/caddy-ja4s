package ja4s

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// Handler injects the JA4S fingerprint into request/response metadata so it can
// be consumed by other handlers (for example, to pass it upstream or log it).
type Handler struct {
	// Optional HTTP header that should carry the fingerprint to upstream handlers.
	RequestHeader string `json:"request_header,omitempty"`

	// Optional response header written back to clients.
	ResponseHeader string `json:"response_header,omitempty"`

	// Optional variable key for caddyhttp's context table. The value can be used
	// via the `{http.vars.<key>}` placeholder. Defaults to "ja4s".
	VarName string `json:"var_name,omitempty"`

	// If true, requests will fail when a fingerprint cannot be produced.
	Require bool `json:"require,omitempty"`

	logger *zap.Logger
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4s",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets defaults.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if h.VarName == "" {
		h.VarName = "ja4s"
	}
	return nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// Consume the directive name (e.g., "ja4s")
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

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// ServeHTTP makes all JA4+ fingerprints available downstream.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	defer func() {
		if rec := recover(); rec != nil {
			h.logger.Error("panic in JA4+ handler",
				zap.Any("panic", rec),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("host", r.Host),
			)
			panic(rec) // Re-panic after logging
		}
	}()

	h.logger.Debug("JA4+ handler called",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("host", r.Host),
	)

	// Extract all available JA4+ fingerprints
	ja4s, _ := FromRequest(r, h.logger)
	ja4, _ := JA4FromRequest(r, h.logger)
	ja4h := JA4HFromRequest(r, h.logger)
	ja4x := JA4XFromRequest(r, h.logger)

	// Set JA4S (primary fingerprint for backward compatibility)
	if ja4s != "" {
		if h.RequestHeader != "" {
			r.Header.Set(h.RequestHeader, ja4s)
		}
		if h.ResponseHeader != "" {
			w.Header().Set(h.ResponseHeader, ja4s)
		}
		if h.VarName != "" {
			caddyhttp.SetVar(r.Context(), h.VarName, ja4s)
		}
	} else if h.Require {
		return caddyhttp.Error(http.StatusPreconditionFailed, fmt.Errorf("ja4s fingerprint missing"))
	}

	// Set all JA4+ fingerprints as variables
	if ja4 != "" {
		caddyhttp.SetVar(r.Context(), "ja4", ja4)
	}
	if ja4s != "" {
		caddyhttp.SetVar(r.Context(), "ja4s", ja4s)
	}
	if ja4h != "" {
		caddyhttp.SetVar(r.Context(), "ja4h", ja4h)
	}
	if ja4x != "" {
		caddyhttp.SetVar(r.Context(), "ja4x", ja4x)
	}

	// Log all fingerprints
	if ja4 != "" || ja4s != "" || ja4h != "" || ja4x != "" {
		h.logger.Info("JA4+ fingerprints extracted",
			zap.String("ja4", ja4),
			zap.String("ja4s", ja4s),
			zap.String("ja4h", ja4h),
			zap.String("ja4x", ja4x),
			zap.String("remote_addr", r.RemoteAddr),
			zap.String("host", r.Host),
		)
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

	provider, ok := conn.(JA4PlusProvider)
	if !ok {
		// Try to unwrap TLS connection
		if tlsConn, isTLS := conn.(*tls.Conn); isTLS {
			type tlsConnStruct struct {
				conn net.Conn
			}
			tlsConnAsStruct := (*tlsConnStruct)(unsafe.Pointer(tlsConn))
			if tlsConnAsStruct != nil && tlsConnAsStruct.conn != nil {
				provider, ok = tlsConnAsStruct.conn.(JA4PlusProvider)
			}
		}
		if !ok {
			return "", ErrUnavailable
		}
	}

	return provider.JA4()
}

// JA4HFromRequest computes the JA4H (HTTP) fingerprint from the HTTP request headers.
func JA4HFromRequest(r *http.Request, logger *zap.Logger) string {
	// JA4H is computed from HTTP headers
	// Format: ge<http_version><method><header_order_hash>_<header_value_hash>
	// This is a simplified implementation - full JA4H spec may require more details
	if r == nil {
		return ""
	}

	// For now, return empty - full JA4H implementation would require parsing
	// HTTP headers according to the JA4H specification
	// TODO: Implement full JA4H computation
	return ""
}

// JA4XFromRequest extracts the JA4X (certificate) fingerprint from the TLS connection.
func JA4XFromRequest(r *http.Request, logger *zap.Logger) string {
	if r == nil || r.TLS == nil {
		return ""
	}

	// JA4X is computed from the TLS certificate
	// Format: <cert_serial_hash>_<cert_subject_hash>_<cert_issuer_hash>
	// This is a simplified implementation - full JA4X spec may require more details
	if len(r.TLS.PeerCertificates) == 0 {
		return ""
	}

	// TODO: Implement full JA4X computation according to spec
	// For now, return empty
	_ = r.TLS.PeerCertificates[0] // Will be used when implementing JA4X
	return ""
}

// FromRequest extracts the JA4S fingerprint from the underlying net.Conn if it
// is available.
func FromRequest(r *http.Request, logger *zap.Logger) (string, error) {
	conn, err := connectionFromRequest(r, logger)
	if err != nil {
		return "", err
	}

	logger.Debug("connection found in request context",
		zap.String("conn_type", fmt.Sprintf("%T", conn)),
	)

	// First, try direct type assertion
	provider, ok := conn.(JA4PlusProvider)
	if !ok {
		// If it's a TLS connection, try to unwrap it to get the underlying connection
		if tlsConn, isTLS := conn.(*tls.Conn); isTLS {
			logger.Debug("connection is TLS, attempting to unwrap",
				zap.String("tls_conn_type", fmt.Sprintf("%T", tlsConn)),
			)
			// Use unsafe to access the unexported "conn" field in tls.Conn
			// tls.Conn struct: { conn net.Conn, ... }
			// We need to get a pointer to the first field (conn)
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logger.Warn("panic while accessing TLS connection field",
							zap.Any("panic", rec),
						)
					}
				}()

				// Create a struct with the same layout as tls.Conn's first field
				// tls.Conn's first field is: conn net.Conn
				// We can cast the pointer to access it
				type tlsConnStruct struct {
					conn net.Conn
				}

				// Cast tls.Conn to our struct type to access the first field
				tlsConnAsStruct := (*tlsConnStruct)(unsafe.Pointer(tlsConn))
				if tlsConnAsStruct != nil && tlsConnAsStruct.conn != nil {
					underlyingConn := tlsConnAsStruct.conn
					logger.Debug("found underlying connection",
						zap.String("underlying_conn_type", fmt.Sprintf("%T", underlyingConn)),
					)
					if foundProvider, foundOK := underlyingConn.(JA4PlusProvider); foundOK {
						logger.Debug("underlying connection implements JA4PlusProvider")
						provider = foundProvider
						ok = true
					} else {
						logger.Warn("underlying connection does not implement JA4PlusProvider",
							zap.String("underlying_conn_type", fmt.Sprintf("%T", underlyingConn)),
						)
					}
				} else {
					logger.Warn("could not access underlying connection from TLS connection")
				}
			}()
		}

		if !ok {
			logger.Warn("connection does not implement JA4PlusProvider",
				zap.String("conn_type", fmt.Sprintf("%T", conn)),
			)
			return "", ErrUnavailable
		}
	}

	logger.Debug("connection implements JA4PlusProvider, calling JA4S()")
	return provider.JA4S()
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
