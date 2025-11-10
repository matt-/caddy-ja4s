## Caddy JA4S Module

This repository provides a pair of modules that make the server-side
[JA4S](https://github.com/FoxIO-LLC/ja4) fingerprint available inside the Caddy
HTTP pipeline by reusing the TLS parsing logic from
[`github.com/voukatas/go-ja4`](https://github.com/voukatas/go-ja4).

- `caddy.listeners.ja4s` – a listener wrapper that records the TLS
  `ServerHello` record before it is encrypted so it can be turned into a JA4S
  fingerprint.
- `http.handlers.ja4s` – an HTTP handler that injects the computed fingerprint
  into request metadata (headers/vars) so the rest of the Caddy config can use
  it (for logging, routing, forwarding to an upstream, etc.).

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

### Basic Configuration

The listener wrapper must run **before** the TLS placeholder wrapper so that it
can observe the plaintext TLS handshake. Make sure your `listener_wrappers`
list keeps the `ja4s` wrapper in front of `tls`.

#### JSON Configuration

```jsonc
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "listener_wrappers": [
            { "wrapper": "ja4s" },
            { "wrapper": "tls" }
          ],
          "routes": [
            {
              "handle": [
                {
                  "handler": "ja4s",
                  "request_header": "X-JA4S",
                  "response_header": "X-JA4S",
                  "var_name": "ja4s"
                },
                { "handler": "static_response", "body": "OK" }
              ]
            }
          ]
        }
      }
    }
  }
}
```

#### Caddyfile Configuration

Configure the listener wrapper in the global options block, and use the handler in your site blocks:

```caddyfile
{
    servers {
        listener_wrappers {
            ja4s
            tls
        }
    }
}

example.com {
    # Use the ja4s handler
    ja4s {
        request_header X-JA4S
        response_header X-JA4S
        var_name ja4s
        # require  # Uncomment to reject requests without fingerprint
    }

    # Log the fingerprint
    log {
        format console
    }

    # Use the fingerprint in a response
    respond "JA4S: {http.vars.ja4s}"
}
```

**Important:** The `ja4s` listener wrapper must appear **before** the `tls` wrapper in the `listener_wrappers` block so it can observe the plaintext TLS handshake.

You can also configure additional listener wrapper options if needed:

```caddyfile
{
    servers {
        listener_wrappers {
            ja4s {
                max_capture_bytes 16384
                protocol tls
            }
            tls
        }
    }
}
```

**Handler in Caddyfile:**

The `ja4s` handler supports these options in Caddyfile:

```caddyfile
ja4s {
    request_header <header-name>    # Header to set on request (optional)
    response_header <header-name>   # Header to set on response (optional)
    var_name <name>                 # Variable name (default: "ja4s")
    require                         # Reject requests without fingerprint (optional)
}
```

#### Handler Options

With the handler in place:

- The request upstream header `X-JA4S` will contain the fingerprint.
- The response header `X-JA4S` is echoed back to the client.
- The value is also available as the `{http.vars.ja4s}` placeholder for logs,
  matchers, templates, etc.

Set `require` in the handler block if you prefer to reject requests where a
fingerprint could not be extracted (for example, when a connection is not
handled by TLS or the negotiation failed too early).

### Development

Run the tests/linting with the standard Go tooling:

```bash
go test ./...
```
