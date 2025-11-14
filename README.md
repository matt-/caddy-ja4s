## Caddy JA4 Module

This repository provides a pair of modules that make the client-side
[JA4](https://github.com/FoxIO-LLC/ja4) fingerprint available inside the Caddy
HTTP pipeline by reusing the TLS parsing logic from
[`github.com/voukatas/go-ja4`](https://github.com/voukatas/go-ja4).

- `caddy.listeners.ja4` – a listener wrapper that records the TLS
  `ClientHello` record before it is encrypted so it can be turned into a JA4
  fingerprint.
- `http.handlers.ja4` – an HTTP handler that injects the computed fingerprint
  into request metadata (headers/vars) so the rest of the Caddy config can use
  it (for logging, routing, forwarding to an upstream, etc.).

### About JA4 Fingerprints

JA4 fingerprints the **client's** TLS handshake (ClientHello), producing a
fingerprint like `t13d1516h2_8daaf6152771_02713d6af862`. This fingerprint is
consistent for a given client configuration and can be used to identify clients
and TLS libraries. The fingerprint format matches the
[JA4 standard](https://github.com/FoxIO-LLC/ja4) and can be looked up in
fingerprint databases like the
[JA4+ mapping CSV](https://raw.githubusercontent.com/FoxIO-LLC/ja4/main/ja4plus-mapping.csv).

### Installation

Build Caddy with this module enabled, for example with `xcaddy`:

```bash
# From the caddy-ja4s directory
xcaddy build --with github.com/matt-/caddy-ja4s=.

# Or with an absolute path
xcaddy build --with github.com/matt-/caddy-ja4s=/Users/mattaustin/hax/caddy/caddy-ja4s
```

**If building Caddy from source**, add this to Caddy's `go.mod`:

```go
replace github.com/matt-/caddy-ja4s => /Users/mattaustin/hax/caddy/caddy-ja4s
```

### Configuration

The listener wrapper must run **before** the TLS placeholder wrapper so that it
can observe the plaintext TLS handshake. Make sure your `listener_wrappers`
list keeps the `ja4` wrapper in front of `tls`.

**Important:** The `ja4` listener wrapper must appear **before** the `tls` wrapper in the `listener_wrappers` block.

### Example: Displaying JA4 Fingerprint

```caddyfile
{
    servers {
        listener_wrappers {
            ja4
            tls
        }
    }
    order ja4 before respond
}

example.com {
    ja4 {
        var_name ja4
    }
    templates
    respond "JA4: {http.vars.ja4}"
}
```

**Note:** You can also use a `route` block instead of the `order` directive:

```caddyfile
example.com {
    route {
        ja4 {
            var_name ja4
        }
        templates
        respond "JA4: {http.vars.ja4}"
    }
}
```

### Example: Forwarding JA4 to Upstream

```caddyfile
{
    servers {
        listener_wrappers {
            ja4
            tls
        }
    }
    order ja4 before reverse_proxy
}

example.com {
    ja4 {
        request_header X-JA4
        var_name ja4
    }
    reverse_proxy localhost:8080 {
        header_up X-JA4 {http.vars.ja4}
    }
}
```

### Handler Options

The `ja4` handler supports these options:

```caddyfile
ja4 {
    request_header <header-name>    # Header to set on request (optional)
    response_header <header-name>   # Header to set on response (optional)
    var_name <name>                 # Variable name (default: "ja4")
    require                         # Reject requests without fingerprint (optional)
}
```

The JA4 fingerprint is available as the `{http.vars.ja4}` placeholder (or whatever you set with `var_name`).
