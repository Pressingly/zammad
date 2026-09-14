# mPass Proxy Auth — SSO Middleware

Rack middleware that integrates Zammad with mPass (Cognito) via
oauth2-proxy's forwarded headers. Follows the same proxy-header shim
pattern used by Penpot, Plane, Outline, and Twenty in the FOSS bundle.

## How it works

1. Traefik forwards every request through `strip-auth-headers` (removes
   client-supplied auth headers) then `mpass-auth` (oauth2-proxy
   ForwardAuth).
2. oauth2-proxy sets `X-Auth-Request-Email` on authenticated requests.
3. This middleware reads that header, resolves or creates a Zammad user,
   and establishes a Rails session.

The middleware reads **only** `X-Auth-Request-Email`. The
`X-Auth-Request-User` header is ignored — it carries the Cognito `sub`
UUID, not a usable identity (see Penpot regression test `3a7adafc5`).

## Configuration

| Env var | Required | Description |
|---------|----------|-------------|
| `AUTH_TYPE` | Yes | Set to `SSO` to activate the middleware. Matches the convention used by Outline, Plane, Penpot, and Twenty in the FOSS bundle. Passed via docker-compose `environment:` block |
| `DEFAULT_EMAIL_DOMAIN` | Yes | Domain appended to bare usernames. **Fails closed** when unset — bare usernames are rejected. Cognito's `cognito:username` claim often lacks `@`, making this the primary code path |
| `SMB_CORPORATE_ID` | No | When set, enforces corporate-ID check against the JWT `custom:corporate_id` claim in `X-Auth-Request-Access-Token`. Requests without a matching corporate ID get 403 |

## User provisioning (JIT)

- **New users**: created on first SSO login with `login` = email,
  `firstname` = email local-part, and the default signup role.
- **Existing users**: looked up by `login` then `email` (both lowercased).
- **Role assignment**: every SSO user is created with the default signup
  role (Customer). Roles are **never** derived from the email domain, and
  an existing user's roles are never changed on login. `Agent` and `Admin`
  are granted out of band by the bundle's `provision-workspaces-admin.sh`.
  `DEFAULT_EMAIL_DOMAIN` is used only to complete bare usernames — it is
  the platform's *synthetic* domain for users with no verified email, so
  deriving privilege from it would elevate exactly the unverified
  population.
- **Session mismatch**: if the session user differs from the header
  identity, the session is silently re-keyed to the new user (follows
  the Penpot/Plane pattern).

## Local auth lockdown

When `AUTH_TYPE=SSO`, the initializer forces these Settings on every
boot:

| Setting | Value | Effect |
|---------|-------|--------|
| `user_show_password_login` | `false` | Hides password form on login page, hides password change in profile |
| `user_lost_password` | `false` | Disables "Forgot password?" link and backend reset endpoints |
| `user_create_account` | `false` | Disables self-registration (not in the original plan, added defensively to prevent local signup bypassing SSO) |
| `system_init_done` | `true` | Skips the guided-setup wizard. Its router guard redirects *every* route to `/guided-setup` while this is false, so an already SSO-authenticated user lands on the create-admin sign-up screen instead of the helpdesk |

Settings are only forced when their rows exist in the database (safe during
`db:migrate` before seeds run), and a setting already holding the wanted
value is left untouched rather than rewritten on each boot.

> **Ordering dependency.** `Service::System::CheckSetup` writes
> `system_init_done` back to `false` if it runs while no Admin exists
> (excluding the system user). On a fresh install that window lasts until
> `provision-workspaces-admin.sh` grants the first Admin — which itself
> requires that user to have logged in via SSO at least once. Reaching a
> `/guided-setup*` URL during that window re-enables the redirect until the
> next Rails boot re-asserts the setting. Grant the first Admin promptly.

`fqdn` and `http_type` are **not** set here — they are owned by the bundle's
`dev/provision/provision-zammad.sh`, which also disables Zammad's built-in
`auth_sso`.

Additionally:
- **Email is immutable** — a `validate` callback on User rejects email
  changes for all users except system (user_id=1). This surfaces as a
  proper validation error (422), not a 500. This prevents users from
  changing their SSO lookup key.
- **Password change rejected** — `Service::User::ChangePassword` is
  prepended with a guard that returns 403 when SSO is active. This
  removes the upstream admin escape hatch (`admin.*` permission bypass
  in `useCheckChangePassword`). Recovery for the bootstrap admin
  requires `rails c` in the container. This is intentional: with mPass
  as the sole identity source, no local password path should exist.

## Security controls

- **`DEFAULT_EMAIL_DOMAIN` fails closed**: unlike Outline/Plane/Penpot
  which fall back to a hardcoded domain, this middleware returns 403
  when a bare username arrives and `DEFAULT_EMAIL_DOMAIN` is unset.
  This prevents local-part collision impersonation.
- **Corporate-ID enforcement**: when `SMB_CORPORATE_ID` is set, the
  access token's `custom:corporate_id` must match. Missing or
  undecodable tokens are rejected.
- **Header trust is topology-based**: Traefik's `strip-auth-headers`
  middleware removes any client-supplied `X-Auth-Request-*` headers
  before `mpass-auth` sets the real ones. The middleware does NOT
  implement its own IP-based trust check (that is `create_sso`'s
  `auth_sso_trusted_ips` concern, which we bypass entirely).

## Files

| File | Purpose |
|------|---------|
| `lib/zammad/mpass_proxy_auth.rb` | The Rack middleware |
| `lib/zammad/mpass_auth_lockdown.rb` | Email immutability + password change guard |
| `config/initializers/mpass_proxy_auth.rb` | Wires middleware, lockdown modules, and forces Settings on boot |
| `doc/mpass_sso.md` | This file |
| `spec/lib/zammad/mpass_proxy_auth_spec.rb` | RSpec tests for the Rack middleware |
| `spec/lib/zammad/mpass_auth_lockdown_spec.rb` | RSpec tests for auth lockdown modules |

## Important: disable `auth_sso` Setting

The upstream header SSO endpoint (`create_sso`) reads `X-Forwarded-User`
and does NOT auto-create users. With our middleware active, leaving
`auth_sso` enabled opens a second, weaker authentication path that
accepts identity from a different header without JIT provisioning.

**The provisioner MUST set `auth_sso` to `false`** (or restrict
`auth_sso_trusted_ips` to an empty list). This middleware fully replaces
the upstream SSO flow.

## Design decisions

- **Rack middleware, not a controller** — Zammad is a unified Rails
  monolith (like Penpot/Plane), so the middleware form applies. A
  controller endpoint is only needed for split FE/BE deployments
  (Twenty/SurfSense).
- **Email is immutable** — the email IS the SSO lookup key. Allowing
  local email changes would either lock users out or pre-stage profiles
  for hijacking.
- **`create_sso` is bypassed** — the upstream SSO endpoint does not
  auto-create users and reads `X-Forwarded-User`, not
  `X-Auth-Request-Email`. Our middleware replaces its functionality
  entirely.
- **Maintenance mode respected** — the middleware checks
  `Setting.get('maintenance_mode')` and returns 403 for non-admin
  users, matching the controller-level `authentication_check_prerequesits`
  behavior.
- **Module patching uses `to_prepare`** — the `User.include` and
  `Service::User::ChangePassword.prepend` calls run inside
  `config.to_prepare` so the patches survive class reloading in
  development mode. Settings are forced in `after_initialize` (once
  per boot) with an `exists?` guard to handle pre-seed state.
- **No local password recovery** — the `RejectPasswordChange` prepend
  blocks all callers including admins. With mPass as the sole identity
  source, password-based recovery is replaced by Cognito-level recovery.
  If the bootstrap admin needs emergency access, use `rails c` in the
  container.
