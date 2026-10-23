# FlexBasicAuth

<img src="./assets/image_flexbasicauth_400x400.png" alt="Mascot FlexBasicAuth" width="100" align="left"/>

A [Traefik](https://traefik.io) middleware plugin that works like the built-in `basicAuth`
middleware, but reads the Basic credentials from a configurable request header instead of
always using `Authorization`.

<br clear="left"/>

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

## Cookie mode: a browser login form without breaking git/API/OIDC

Header mode has one limitation: a plain browser's native Basic Auth popup only ever sends
credentials through `Authorization`. If you want a normal-looking browser login (no browser
extension, no custom header) on a host where `Authorization` is already used for something
else, header mode can't do it, since the native popup would collide with that.

That's exactly the case for something like a Gitea server: `git clone`/`push` over HTTPS and
API tokens all use `Authorization`. Set `mode: cookie` instead, and FlexBasicAuth serves its own
login form and, after a successful login, sets a signed session cookie. Browsers send cookies
automatically on every request, so the user logs in once and stays logged in, without ever
touching `Authorization`.

### How browser and command-line clients are told apart

The same rule from header mode still applies and is the reason nothing breaks: **if a request
already carries `Authorization`, FlexBasicAuth does not touch it at all** and passes the request
straight through. `git`, API clients, and OIDC Bearer tokens all send `Authorization`, so they
never see the cookie gate.

For requests with no `Authorization` and no valid session cookie yet, FlexBasicAuth has to
decide whether to show an HTML login page or a plain HTTP challenge, and it does that by
checking the `Accept` header:

- **Browser** (`Accept: text/html,...`) → gets the login form. Submitting it sets the session
  cookie and redirects back to the page the user was trying to reach.
- **Everything else** (`git`, `curl`, API clients, they send `Accept: */*`) → gets a plain
  `401 Unauthorized` with `WWW-Authenticate: Basic`. That's the standard challenge these tools
  already know how to react to: they retry the same request with their own `Authorization`
  (credentials embedded in the remote URL, a credential helper, an API token, whatever they
  already use for that host), which then goes straight through by the rule above, so the
  backend's own auth (Gitea, an API, OIDC) handles it exactly as if FlexBasicAuth weren't there.

In short: a browser gets a real login page; a command-line client gets a normal 401 challenge
and authenticates however it already does against the backend. Neither one ever has to know
about the other.

### Configuration

| Option         | Type   | Default                      | Description                                                             |
|----------------|--------|-------------------------------|---------------------------------------------------------------------------|
| `mode`         | string | `"header"`                    | `"header"` (default) or `"cookie"`.                                      |
| `cookieName`   | string | *(required in cookie mode)*   | Name of the session cookie. Pick something that won't collide with the backend's own cookies (not `session`, not `i_like_gitea`, etc). |
| `cookieSecret` | string | *(required in cookie mode)*   | HMAC signing key for the session cookie. Treat it like a password: generate a random one, e.g. `openssl rand -hex 32`. |
| `cookieTTL`    | string | `"24h"`                       | Session lifetime, as a Go duration (`h`/`m`/`s`, no `d` for days, use e.g. `168h` for a week). |
| `loginPath`    | string | `"/__flexbasicauth/login"`    | Path the login form posts to. Pick something that doesn't collide with a real route on the backend. |

The cookie is set with `HttpOnly`, `Secure`, and `SameSite=Lax`, and no `Domain` attribute (so
it's scoped to the exact host). It's read only by exact name, so any other cookies already in
the request (a backend session cookie, a CSRF cookie, anything) are left untouched and still
reach the backend normally.

`users` works the same way as in header mode: it's a list, not a single account. Add one
`login:hash` entry per person who needs browser access:

```yaml
users:
  - "admin:$apr1$..."
  - "alice:$apr1$..."
```

Each person logs in with their own entry, and the session cookie is signed with the username
that actually logged in, so everyone gets their own independent session. This is still a gate
in front of the backend, not a replacement for whatever login system the backend itself has:
these credentials only control who gets past FlexBasicAuth, they have nothing to do with the
backend's own user accounts (a Gitea login, API tokens, etc.), which keep working exactly as
they did before, over `Authorization`.

### Example: gating a Gitea web UI without breaking git/API

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: gitea-flex-basic-auth
spec:
  plugin:
    flexbasicauth:
      users:
        - "admin:$apr1$..."
      mode: "cookie"
      cookieName: "flex_basic_auth_session"
      cookieSecret: "<openssl rand -hex 32>"
      cookieTTL: "168h"
      loginPath: "/__flexbasicauth/login"
```

Attach this middleware to the Gitea route. Browsing to the host shows a login form; `git
clone`/`push` and API/token access keep working exactly as before, untouched.

## Generating password hashes

Any htpasswd-compatible tool works:

```bash
htpasswd -nbB user password      # bcrypt
htpasswd -nbs user password      # SHA1
openssl passwd -apr1 user        # MD5-crypt / apr1
```

## Local usage plugin (without using a publication)

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

## Installing without internet access

The catalog mode (`experimental.plugins`) requires Traefik to reach the plugin registry
backend at startup to download the module. That won't work on an air-gapped host. Use
`experimental.localPlugins` instead (same mechanism as above): it never makes a network
call, since yaegi only interprets files already on disk.

This works offline because `vendor/` is already committed to this repository: nobody needs
to run `go mod vendor` on the air-gapped host, or reach a Go module proxy at all. You only
need to get the repository's files onto that host by any transport you already have,
network or not:

- `git clone` from an internal mirror, if you have one.
- `scp`/`rsync` the repository directory from a machine that already has it.
- A tarball on a USB drive: `tar czf flexbasicauth.tar.gz -C .. flex-basic-auth-traefik`,
  copy it over, `tar xzf` on the target.

Whichever way you move it, the result has to land at
`plugins-local/src/github.com/stanislavtrubachev/flex-basic-auth-traefik` on the Traefik
host (or be mounted there as a volume, if Traefik runs in a container), with `vendor/` and
`.traefik.yml` included. Then enable it in the static configuration as shown above and
restart Traefik. No outbound network access is needed at any point.

## Development

```bash
go test ./... -race -cover
go run ./cmd/devserver   # standalone server for manual testing, not part of the plugin
```
