# OIDC / trusted reverse-proxy authentication

LassiNet does **not** implement an OIDC client. It trusts the identity that a
reverse proxy (Authelia, oauth2-proxy, Keycloak gatekeeper, etc.) has already
authenticated, but only when the proxy also presents a shared secret header.

This is deliberate: OIDC flows, MFA, sessions and provider quirks belong in
the proxy; LassiNet stays a small control plane.

## Required proxy headers

| Header | Meaning |
|---|---|
| `X-LassiNet-Proxy-Secret` | shared secret; **required** |
| `X-Auth-Request-User` | user identity/email (configurable) |
| `X-Auth-Request-Groups` | comma-separated groups (configurable) |

The secret header is the trust boundary. Without it, an attacker who can reach
the port cannot impersonate a user by adding the other headers.

## Configuration

```bash
LASSI_PROXY_AUTH=1
LASSI_PROXY_AUTH_SECRET=<long-random-shared-secret>
LASSI_PROXY_AUTH_OPERATOR_GROUP=lassinet-operators
LASSI_PROXY_AUTH_VIEWER_GROUP=lassinet-viewers
LASSI_PROXY_AUTH_DEFAULT_ROLE=viewer     # viewer | operator | none
LASSI_PROXY_AUTH_USER_HEADER=X-Auth-Request-User
LASSI_PROXY_AUTH_GROUPS_HEADER=X-Auth-Request-Groups
```

- Users in the operator group get write access; viewer group is read-only.
- With no matching group, the default role applies. `viewer` is the safe
  default; `none` makes it a 401.
- **Never use default `operator`** unless you really want every authenticated
  proxy user to be able to block.
- The app also enforces CSRF double-submit for cookie/proxy writes. On the
  first GET, LassiNet sets a signed, non-HttpOnly `lassi_csrf` cookie; the
  dashboard sends it back in `X-CSRF-Token`. A script behind the proxy must do
  the same or use a Bearer token directly.

## Nginx + oauth2-proxy (shape)

```nginx
location = /oauth2/auth {
    internal;
    proxy_pass http://127.0.0.1:4180/oauth2/auth;
    proxy_set_header X-Original-URL $scheme://$host$request_uri;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
}

location / {
    auth_request /oauth2/auth;
    auth_request_set $user   $upstream_http_x_auth_request_user;
    auth_request_set $groups $upstream_http_x_auth_request_groups;

    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Auth-Request-User $user;
    proxy_set_header X-Auth-Request-Groups $groups;
    proxy_set_header X-LassiNet-Proxy-Secret "<the same long secret>";
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

`oauth2-proxy` must be configured with the OIDC issuer/client and to emit the
user/groups headers. Authelia's `forward-auth` has an equivalent.

## Exposure checklist

- Keep `LASSI_HOST=127.0.0.1`; the proxy is the only reachable door.
- Put TLS on the proxy; set `LASSI_FORWARDED_ALLOW_IPS` to the proxy peer, not
  a whole subnet.
- Never expose the app directly while proxy auth is enabled: the secret is the
  only thing separating "proxy user" from "anyone".
- Rotate the proxy secret and operator/viewer tokens independently; a proxy
  restart does not invalidate Bearer tokens.
- The audit `actor` becomes the proxy user email for write events.
- The proxy session lifetime is the proxy's job; LassiNet does not see its
  cookie. LassiNet's own token sessions and `LASSI_SESSION_TTL` still apply to
  token/cookie logins.

## What this is not

No built-in OIDC authorization-code client, no per-route scopes, no MFA in the
app, no user database. Those remain in the identity proxy. This integration is
only as safe as the proxy and its secret handling.
