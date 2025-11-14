## Caddy JA4 Module (WIP)

This repository provides the [JA4](https://github.com/FoxIO-LLC/ja4) fingerprint available inside the Caddy
HTTP pipeline by using logic from
[`github.com/voukatas/go-ja4`](https://github.com/voukatas/go-ja4).

### About JA4 Fingerprints

JA4 fingerprints the **client's** TLS handshake (ClientHello), producing a
fingerprint like `t13d1517h2_8daaf6152771_b6f405a00624`. This fingerprint is
consistent for a given client configuration and can be used to identify clients
and TLS libraries. The fingerprint format matches the
[JA4 standard](https://github.com/FoxIO-LLC/ja4) and can be looked up in
fingerprint databases like the
[JA4 DB](https://docs.ja4db.com/ja4+-database/usage/read-the-database).

### Installation

Build Caddy with this module enabled, for example with `xcaddy`:

```bash

xcaddy build --with github.com/matt-/caddy-ja4

```

**If building Caddy from source**, add this to Caddy's `go.mod`:

```go
replace github.com/matt-/caddy-ja4s => /path/to/project/caddy-ja4s
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
    block <fp1> <fp2> ...           # Block specific JA4 fingerprints (optional)
    block_file <path>               # Path to file with blocked fingerprints (optional)
}
```

The JA4 fingerprint is available as the `{http.vars.ja4}` placeholder (or whatever you set with `var_name`).

### Blocking JA4 Fingerprints

You can block requests based on their JA4 fingerprint using the `block` option or `block_file` option:

**Using inline block list:**

```caddyfile
example.com {
    ja4 {
        var_name ja4
        block t13d1516h2_8daaf6152771_02713d6af862 t13d190900_9dc949149365_97f8aa674fd9
    }
    respond "OK"
}
```

**Using a block file:**

```caddyfile
example.com {
    ja4 {
        var_name ja4
        block_file /etc/caddy/blocked_ja4s.txt
    }
    respond "OK"
}
```

The block file format is one fingerprint per line, with `#` for comments:

```
# Blocked JA4 fingerprints
t13d1516h2_8daaf6152771_02713d6af862
t13d190900_9dc949149365_97f8aa674fd9
# Another blocked fingerprint
t13d191000_9dc949149365_e7c285222651
```

Blocked requests will receive a `403 Forbidden` response. You can combine both `block` and `block_file` options - fingerprints from both sources will be blocked.
