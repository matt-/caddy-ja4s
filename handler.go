package ja4s

import (
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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
}

// CaddyModule implements caddy.Module.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4s",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets defaults.
func (h *Handler) Provision(caddy.Context) error {
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

// ServeHTTP makes the fingerprint available downstream.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	fingerprint, err := FromRequest(r)
	if err != nil {
		if h.Require {
			return caddyhttp.Error(http.StatusPreconditionFailed, fmt.Errorf("ja4s fingerprint missing: %w", err))
		}
		return next.ServeHTTP(w, r)
	}

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

// FromRequest extracts the JA4S fingerprint from the underlying net.Conn if it
// is available.
func FromRequest(r *http.Request) (string, error) {
	conn, err := connectionFromRequest(r)
	if err != nil {
		return "", err
	}

	provider, ok := conn.(JA4SProvider)
	if !ok {
		return "", ErrUnavailable
	}

	return provider.JA4S()
}

func connectionFromRequest(r *http.Request) (net.Conn, error) {
	if r == nil {
		return nil, errors.New("request is nil")
	}

	conn, ok := r.Context().Value(caddyhttp.ConnCtxKey).(net.Conn)
	if !ok || conn == nil {
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
