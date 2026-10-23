# FlexBasicAuth

A [Traefik](https://traefik.io) middleware plugin that works like the built-in `basicAuth`
middleware, but reads the Basic credentials from a configurable request header instead of
always using `Authorization`.

## Why

Traefik's built-in `basicAuth` only reads credentials from `Authorization`. Its `headerField`
option is unrelated: it just writes the authenticated username to a header for the backend, it
doesn't change where credentials are read from.

That's a problem if the backend already uses `Authorization` for its own auth, for example
OpenID Connect (`Authorization: Bearer ...`). With `basicAuth` enabled, Traefik tries to parse
the Bearer token as Basic credentials and returns 401. There's no way to keep Basic auth at the
edge and let the Bearer token through on the same route with the built-in middleware.

FlexBasicAuth reads Basic credentials from any header you pick (e.g. `X-Basic-Auth`) and leaves
`Authorization` alone when it isn't the configured header, so an OpenID Bearer token passes
through unmodified.

## Configuration

| Option         | Type     | Default        | Description                                                                                   |
|----------------|----------|----------------|-------------------------------------------------------------------------------------------------|
| `users`        | []string | *(required)*   | htpasswd-style `login:hash` entries. Supports bcrypt (`$2a$`/`$2b$`/`$2y$`), MD5-crypt/apr1 (`$apr1$`/`$1$`), and SHA1 (`{SHA}`), same formats as the built-in `basicAuth`. |
| `header`       | string   | `Authorization`| Request header to read the `Basic <base64>` credentials from.                                  |
| `realm`        | string   | `traefik`      | Realm sent in the `WWW-Authenticate: Basic realm="..."` response on 401.                        |
| `removeHeader` | bool     | `false`        | Remove the credentials header from the request before it reaches the backend.                  |
| `headerField`  | string   | `""` (disabled)| If set, write the authenticated username to this header for the backend.                        |

With `header` unset (or set to `Authorization`), FlexBasicAuth behaves exactly like the built-in
`basicAuth`. Point `header` elsewhere and `Authorization` is never read, inspected, or modified.

### Example: BasicAuth + OpenID on the same route

```yaml
http:
  middlewares:
    flex-basic-auth:
      plugin:
        flexbasicauth:
          users:
            - "user:$apr1$..."
          header: "X-Basic-Auth"
          realm: "traefik"
          removeHeader: true
          headerField: "X-Authenticated-User"
```

The client sends credentials as `X-Basic-Auth: Basic <base64(user:password)>`. `removeHeader:
true` strips that header before the backend sees it, and `headerField` passes the authenticated
username along as `X-Authenticated-User`. `Authorization: Bearer <openid-token>` is never
touched, so the backend's own OIDC check keeps working.

### Kubernetes (IngressRoute / Middleware CRD)

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: flex-basic-auth
spec:
  plugin:
    flexbasicauth:
      users:
        - "user:$apr1$..."
      header: "X-Basic-Auth"
      removeHeader: true
      headerField: "X-Authenticated-User"
```

## Generating password hashes

Any htpasswd-compatible tool works:

```bash
htpasswd -nbB user password      # bcrypt
htpasswd -nbs user password      # SHA1
openssl passwd -apr1 user        # MD5-crypt / apr1
```

## Local plugin testing (before publishing)

Traefik plugins run through [yaegi](https://github.com/traefik/yaegi), not a compiler. Third-party
dependencies (here, `golang.org/x/crypto/bcrypt`) have to be vendored, since Traefik won't run
`go mod vendor` for you:

```bash
go mod vendor
```

Put the module (including `vendor/`) under
`plugins-local/src/github.com/stanislavtrubachev/flex-basic-auth-traefik` on the Traefik
host/container, and enable it in the static configuration:

```yaml
experimental:
  localPlugins:
    flexbasicauth:
      modulename: github.com/stanislavtrubachev/flex-basic-auth-traefik
```

## Development

```bash
go test ./... -race -cover
go run ./cmd/devserver   # standalone server for manual testing, not part of the plugin
```
