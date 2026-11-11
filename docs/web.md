# Web app (Phase 3d): approver login, QR setup, two modes

Code: `tollgate/app/`. Start it with `.venv\Scripts\python.exe scripts\run_app.py`. It
listens on `http://127.0.0.1:8000` only (there is no host option).

| File | Purpose |
|------|---------|
| `main.py` | Builds the app: account, approval service, executor, desk, roles; the release loop. |
| `auth_mode.py` | `TOLLGATE_AUTH_MODE` = `demo` (default) or `real`; the session key. Anything else stops startup. |
| `sessions.py` | Signed cookies (HMAC-SHA256) and CSRF tokens. Standard library only. |
| `ratelimit.py` | Login attempt limit and lockout. |
| `security_headers.py` | Security headers on every response, and a generic 500 on any unexpected error. |
| `routes.py` | Pages and form handlers. |
| `templates/`, `static/` | Plain HTML (Jinja2, auto-escaped), `style.css` and `app.js`. The look follows `design/preview_*.html`, but with no inline styles or scripts (strict CSP), system fonts only, and no network calls from the page. |

## Pages
- `/overview`: real counts only: held requests waiting, Gate verdicts from the audit log
  (allowed, held, blocked), recent activity. Security score and Sentinel show
  "Sentinel is not enabled yet" (no fake score).
- `/login`: the owner logs in with name and password. The agent has no login.
- `/setup`: real mode, first run: name, password (12+ characters) and alert destination, then
  a QR code for Google Authenticator (or any TOTP app), shown **once**. Setup finishes only
  when the first code from the app matches, from the same browser, within 10 minutes. After
  that, replacing the authenticator needs the **current** code and goes through the 3c
  guarded settings change (15-minute cooling-off, owner notified, can be cancelled).
- `/approvals`: held payments (approve with a one-time code, or reject), and approved payments
  waiting out their cooling-off, with a countdown and a Cancel button. Demo mode adds an
  **Approve with demo code** button: the page carries this 30-second step's code and the next
  one; if this step's code was already used, `app.js` waits for the next step and then sends
  the next code, so a normal click never sends a used code. The server checks the code exactly
  as for a typed one. Demo also offers "Try as a stolen session (no code)", which counts as a
  failed code. Real mode never shows a code.
- `/audit` ("Activity"): the audit log (newest first, filter tabs, hash-chain check) and the
  owner alerts.
- `/security`: live breaker, lockout and hash-chain status, and the settings in force
  (read-only). Sentinel: "not enabled yet".

## Intro animation
The padlock-and-key intro from `design/preview_demo_mode.html` plays once per browser tab
(remembered in `sessionStorage`), on the first page opened, in both modes. It is plain SVG and
CSS classes (`_intro.html`, `style.css`); `app.js` decides whether to show it.
- Skip: the "Skip intro" button (focused when it starts) or any key. It ends by itself after 6.3 s.
- Never shown with `prefers-reduced-motion`, with `?nointro=1` in the URL (for tests and
  screen recordings, e.g. `http://127.0.0.1:8000/login?nointro=1`), when sessionStorage is
  blocked, or if anything in the script fails. The element is `hidden` in the HTML, so without
  the script the page just shows.
- `?nointro=1` is read only by the browser script; the server ignores it, so it cannot change
  any security behaviour.

## Two modes
| | demo (default) | real |
|---|---|---|
| Banner | DEMO banner on every page | none |
| Account | `demo-owner` / `demo-password-not-secret` (fake, documented) | none until setup |
| Second factor | fixed fake mock secret; current code shown on the approvals page | your authenticator app; code never shown |
| Fake mock secret | the only secret used | refused |
| Session key | random each start | `TOLLGATE_SESSION_KEY`, 32+ characters, required |
| Cookie | `tollgate_session`, HttpOnly, SameSite=Strict | `__Host-tollgate`, also Secure |
| Seed data | two held demo payments | none |

## Settings (approved)
| Setting | Value |
|---|---|
| Session lifetime | 1 hour after login, however active |
| Idle timeout | 15 minutes without use |
| Login limit | 5 failures within 60 s, per name and per client IP |
| Login lockout | 15 minutes; refused even with the right password; audited |
| Setup confirm | within 10 minutes; wrong codes count toward the same limiter |
| Release loop | every 5 seconds |
| Cookies | HttpOnly, SameSite=Strict, Path=/, Max-Age 3600; real mode adds Secure and `__Host-` |

Session expiry lives in `tollgate/approval/accounts.py`, so it applies outside the web app
too. An expired session is deleted on the server; the cookie alone is worthless.

## Protections
- Every POST checks a CSRF token (HMAC of the session token, or of a pre-login cookie for
  the login and setup forms). Missing or wrong → 403, audited.
- Any request with an `Authorization` header is refused (403). Bearer or API credentials
  are never accepted, so an agent cannot approve with one.
- Approving still needs the 3c step-up: live session **and** a fresh code. 3 bad codes lock
  approvals, trip both breakers and end every session (tested through the web layer).
- Headers on every response: `Content-Security-Policy` (`default-src 'none'`, scripts and
  styles from this site only, no inline scripts, `frame-ancestors 'none'`),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Cache-Control: no-store`.
- Customer text and reasons are shown escaped, marked "untrusted".
- The QR secret, passwords and codes are never written to the audit log, outbox or Python
  logs (tested). The audit log also redacts any reason that looks like a secret.
- Any unexpected error → a generic "refused" page (500), nothing approved.

## Release loop
A background task calls `release_due()` (and applies due settings changes) every 5 seconds.
Errors are counted and audited; that round releases nothing more. It stops when the app
shuts down. With `TOLLGATE_SENTINEL=on` (the default) the same loop then runs Sentinel's due
jobs; a Sentinel error never stops a release. With `off` it is exactly the loop above. See
[sentinel.md](sentinel.md).

## Honest limits
- **Not tested in a real browser.** All tests use FastAPI's test client. The live server was
  started and served pages over HTTP, but nobody clicked through it in Chrome or Firefox.
  That includes `app.js` (countdowns, demo code box, the wait-for-a-fresh-code button) and
  the phone-width layout: tests check the HTML and the server side, and `node --check`
  checks the script's syntax, but no browser ran it.
- Real mode's `Secure` / `__Host-` cookie on plain `http://127.0.0.1` depends on the browser
  treating localhost as secure. That is not tested. See the README for what to do if login
  does not stick.
- Real-mode first setup: whoever reaches `/setup` first becomes the approver. The app only
  listens on 127.0.0.1, so run setup right after starting it.
- No unlock page: after a lockout, approvals stay locked until restart (state is in memory).
  This is deliberate (stricter); unlocking needs a person at the code level.
- The new authenticator from a reset is not confirmed with a code before it applies.
- Login timing differs slightly for an unknown name vs a wrong password.
- No agent intake in the app yet: in real mode the held list is empty until code submits
  proposals through the drafter handle.
- Everything is in memory and lost on restart, including sessions and waiting approvals
  (waiting approvals then never release: fail closed).
- A clean Ctrl+C shutdown of the live server was not tested; shutdown is tested through the
  test client's app lifecycle only.

## Sentinel and "Try to break it" pages
`/sentinel` and `/drills` need a logged-in approver; every button is a POST with a CSRF
token. Rules and numbers: [sentinel.md](sentinel.md#web-pages). The DEMO banner now sits in
the page flow (not sticky) and the side nav carries a DEMO label in demo mode. The stolen
session drill uses FastAPI's in-process test client (httpx, already in requirements.txt).
Not checked in a real browser.

If approvals lock during the demo, stop and restart the app.
