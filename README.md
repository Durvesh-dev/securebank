# SecureBank – Secure Online Banking Web Application

**Course:** Web Application & Security (WAS) – Assignment 4
**Scenario:** Online Banking System
**Developer:** Durvesh Bhadgaonkar (Roll No. 24101B2006), B.E. IT, Vidyalankar Institute of Technology
**GitHub:** https://github.com/Durvesh-dev/securebank
**Live link:** `<paste your deployed URL here>`

SecureBank is a full-stack web application (Node.js + Express backend, HTML/CSS/JS frontend) where customers sign in, view their balance and transactions, and transfer funds, and an administrator reviews users and a tamper-evident security audit log. It is designed around the OWASP secure-design principles listed in the assignment.

## Features
- Customer login, account summary, transaction history
- Fund transfer between accounts with server-side checks
- Admin dashboard: user list, account lock status, audit log with integrity check
- Role-based access (customer / admin)

## Tech stack
| Layer | Technology |
|---|---|
| Frontend | HTML5, CSS3, vanilla JavaScript (no inline scripts) |
| Backend | Node.js 18+, Express 4 |
| Security libraries | helmet, express-session, express-rate-limit, express-validator, bcryptjs |
| Storage | JSON file store (`data/db.json`), hash-chained audit log (`logs/audit.log`) |
| Hosting | Render (free web service) over HTTPS |

## Project structure
```
securebank/
├── src/
│   ├── server.js      # routes, security headers, sessions, error handling
│   ├── config.js      # configuration from environment variables
│   ├── db.js          # data layer (bcrypt hashes only)
│   ├── middleware.js  # CSRF, auth, RBAC, timeout, validation
│   └── logger.js      # hash-chained audit logging
├── public/            # index.html, styles.css, app.js
├── data/  logs/       # created at runtime
├── .env.example
└── package.json
```

## Security principles implemented

| Principle | Implementation | Where |
|---|---|---|
| **Architecture** | 3-tier separation: presentation (`public/`), application/security middleware (`src/`), data layer (`db.js`). Client is untrusted; every rule is enforced on the server. | `src/` |
| **Deployment** | HTTPS via host, HSTS, `trust proxy`, `NODE_ENV=production`, `x-powered-by` removed, server refuses to start without a strong secret. | `server.js`, `config.js` |
| **Input validation** | Allow-list regex validation for username, account number (12 digits), IFSC, amount range, remark. JSON body limited to 10 KB. Output rendered with `textContent` only (XSS-safe). | `server.js`, `app.js` |
| **Authentication** | bcrypt (cost 12) password hashing, generic error messages, dummy-hash compare to stop user enumeration, account lockout after 5 failures, rate limit of 20 login attempts / 15 min. | `/api/login` |
| **Authorization** | Server-side RBAC via `requireRole()`. Customers cannot reach `/api/admin/*`; admins cannot transfer money. Denials are logged. | `middleware.js` |
| **Configuration management** | All settings and secrets from environment variables (`.env`, never committed); config object frozen. | `config.js`, `.gitignore` |
| **Sensitive data** | No plain-text passwords stored or logged; account numbers masked in UI, API and logs; cookies `HttpOnly`. | `db.js`, `logger.js` |
| **Session management** | Session ID regenerated on login (stops fixation), cookie `HttpOnly + Secure + SameSite=Strict`, 10-min idle timeout, session destroyed on logout. | `server.js`, `middleware.js` |
| **Cryptography** | Standard libraries only: bcrypt for passwords, `crypto.randomBytes` for tokens, SHA-256 for audit chain, `timingSafeEqual` for token comparison. TLS in transit. | throughout |
| **Parameter manipulation** | Source account and user identity always taken from the session, never from the request (prevents IDOR). Unexpected fields (e.g. `fromUserId`) rejected and logged. Amount re-checked against balance on server. CSRF token required on every state-changing request. | `/api/transfer` |
| **Exception management** | Central error handler returns a safe message with a reference ID; stack traces never sent to the client. | `server.js` |
| **Auditing & logging** | Append-only audit log of logins, failures, lockouts, transfers, denials, CSRF and tampering attempts, with timestamp, user and IP. Each entry includes the SHA-256 of the previous one; the admin page verifies the chain. | `logger.js` |

## Run locally
```bash
npm install
cp .env.example .env          # then set SESSION_SECRET
npm start                     # http://localhost:3000
```
The example `.env` uses `NODE_ENV=development` so cookies work on plain http://localhost. Use `production` on the host.

**Demo accounts:** `asha / Asha@2026`, `rohan / Rohan@2026`, `admin / Admin#2026`

## Deploy on Render (free)
1. Push this folder to a GitHub repository.
2. On https://render.com → **New → Web Service** → connect the repo.
3. Build command: `npm install` · Start command: `npm start`
4. Environment variables: `NODE_ENV=production`, `SESSION_SECRET=<64-char random hex>`
5. Deploy. Render gives an `https://<name>.onrender.com` link — submit that link.

Note: on the free plan the file storage resets when the service restarts, so the demo data is re-seeded automatically.

## Security test cases
| # | Test | Expected result |
|---|---|---|
| 1 | Wrong password 5 times | Account locked, `ACCOUNT_LOCKED` logged |
| 2 | Login as `asha`, call `/api/admin/users` | 403, `AUTHORIZATION_DENIED` logged |
| 3 | Transfer with extra field `fromUserId` (via DevTools/Postman) | 400, `PARAMETER_TAMPERING` logged |
| 4 | POST without `X-CSRF-Token` header | 403, `CSRF_REJECTED` logged |
| 5 | Remark `<script>alert(1)</script>` | 400, rejected by validation |
| 6 | Amount `-500` or `999999` | 400, rejected |
| 7 | Idle 10 minutes | Session expired, must sign in again |
| 8 | Edit a line in `logs/audit.log` | Admin page shows chain **TAMPERED** |
