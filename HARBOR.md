# Harbor Drive session extension

This branch is based on upstream SFTPGo v2.7.5, commit
`9888a3d169aed9011ae6e4f7a97ae735c1643068`. The deployed UI remains the separate
Harbor Drive Markdown/PWA release owned by `~/lab/server-infra`.

`httpd.web_client_cookie_lifetime` optionally sets the password-authenticated
WebClient cookie duration in minutes, up to 44640 (31 days). Zero retains
upstream behavior. Long sessions have a fixed expiry measured from login and
are not silently extended. WebAdmin, API, share, partial authentication, OIDC
and CSRF token lifetimes retain their original configuration and limits.
Existing IP matching and Secure/HttpOnly/SameSite cookie behavior are unchanged.

For a WebClient duration above 12 hours, startup requires a SQL provider and
uses its existing shared-session table to persist revocations. Only SHA-256
token hashes and a revocation marker are stored by this mode. Account signatures
are checked on each authenticated WebClient request, so account changes,
password changes, disabling and deleting a user invalidate old cookies. No new
schema or separate authentication service is introduced.

Existing short cookies keep their original expiry. Sign out and sign in after
deployment to receive the new 31-day cookie. A network/IP change can still
require another login. The production signing key stays in Bitwarden and is
injected only by the existing service launcher.

Build outputs, Go modules, compiler caches and temporary files must be explicitly
placed under `/Volumes/Harbor/DevCache`; verify that volume and disk capacity
first. Production must run an immutable copy under `~/services/sftpgo`, never
the binary in this checkout or DevCache. Back up the deployed executable,
matching source archive, configuration, database and active UI release.
