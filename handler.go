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

	logger *zap.Logger
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

		default:
			return d.Errf("unknown option: %s", d.Val())
		}
	}

	return nil
}

// ServeHTTP makes the JA4 fingerprint available downstream.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
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

	h.logger.Info("JA4 fingerprint extracted successfully",
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
			logger.Debug("connection is TLS, attempting to unwrap",
				zap.String("tls_conn_type", fmt.Sprintf("%T", tlsConn)),
			)
			// Use unsafe to access the unexported "conn" field in tls.Conn
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						logger.Warn("panic while accessing TLS connection field",
							zap.Any("panic", rec),
						)
					}
				}()

				// Create a struct with the same layout as tls.Conn's first field
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
					if foundProvider, foundOK := underlyingConn.(JA4Provider); foundOK {
						logger.Debug("underlying connection implements JA4Provider")
						provider = foundProvider
						ok = true
					} else {
						logger.Warn("underlying connection does not implement JA4Provider",
							zap.String("underlying_conn_type", fmt.Sprintf("%T", underlyingConn)),
						)
					}
				} else {
					logger.Warn("could not access underlying connection from TLS connection")
				}
			}()
		}

		if !ok {
			logger.Warn("connection does not implement JA4Provider",
				zap.String("conn_type", fmt.Sprintf("%T", conn)),
			)
			return "", ErrUnavailable
		}
	}

	logger.Debug("connection implements JA4Provider, calling JA4()")
	return provider.JA4()
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
