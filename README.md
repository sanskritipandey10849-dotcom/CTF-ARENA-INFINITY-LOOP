# CTF ARENA – INFINITY LOOP

A local educational CTF platform built with HTML, CSS, JavaScript, Node.js, Express and SQLite.

## Requirements
- Node.js 20 or newer
- npm

## Setup (Windows / VS Code)
1. Extract this folder and open it in VS Code.
2. In Terminal, run `npm install`.
3. Copy `.env.example` to `.env`.
4. Replace `SESSION_SECRET` and `FLAG_PEPPER` with long random values. Keep `.env` private.
5. Run `npm run admin` once to create the administrator account using the credentials in `.env`.
6. Run `npm run dev`.
7. Open http://localhost:3000

Student accounts can be registered from the website. The initial five educational challenges are seeded automatically.

## Admin
Set `ADMIN_USERNAME` and `ADMIN_PASSWORD` in `.env` before running `npm run admin`.
Admin login uses the same login page.

## Notes
- SQLite data is stored in `data/arena.db`.
- Flags are stored as HMAC-SHA256 digests using `FLAG_PEPPER`; raw flags are not returned by APIs.
- Sessions use random opaque cookies with server-side hashed session identifiers.
- This is a hackathon/demo starter. Before public deployment, add HTTPS, robust CSRF protection for all state-changing requests, persistent backups, monitoring, stronger admin provisioning, and a production session cleanup policy. The included SameSite=Strict cookie is a baseline, not a substitute for a complete deployment security review.
- Challenges are safe, simulated learning exercises. Do not use the platform to test systems without authorization.
