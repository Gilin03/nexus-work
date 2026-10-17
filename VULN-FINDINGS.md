# VULN-FINDINGS — nexus-work/app

scanned_at: 2026-10-17 · method: single-pass manual review following
`anthropics/defending-code-reference-harness`'s `/vuln-scan` review brief
(target has 12 source files, under the skill's 15-file auto-`--single`
threshold, so no subagent fan-out). No `THREAT_MODEL.md` was generated first
— `docs/01_기획.md` already documents entry points and trust boundaries for
this project.

## Summary

| severity | count |
|---|---|
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| low-confidence | 0 |

**No reportable findings.** Covered 8 focus areas across all 12 files in
`app/`: auth/session, authorization/scope, SQL layer, upload handling, input
validation/output encoding, approval workflow, chat interface, config/secrets.

## What was checked and why it didn't produce findings

- **SQL injection** — every query in `db.py`-backed call sites uses constant
  SQL strings + `%s` params (also enforced by `tests/test_sql_static.py`'s
  AST check). `employees` search builds its `LIKE` pattern through
  `validators.like_pattern`, which escapes `\`, `%`, `_` in the correct order
  before parameterized binding.
- **XSS** — zero `|safe` filters anywhere in `templates/`; all output goes
  through Jinja's default auto-escaping. CSP (`script-src 'self'`, no
  `unsafe-inline`) is a second layer.
- **Auth/session** — constant-time dummy-hash comparison for unknown
  usernames, identical failure message, `SELECT ... FOR UPDATE` on the user
  row during failure counting (no race to bypass the 5-attempt lock),
  `session_version` bump on logout/password-change invalidates all other
  cookies for that user.
- **Authorization/scope** — every scope check (`_can_access`, `role_required`,
  `admin.before_request`) re-reads role/dept/lock state from the DB on each
  request; nothing is trusted from the session beyond `uid`/`session_version`.
  `/admin/*` is gated at the blueprint level, so a new admin route can't skip
  the check by omission.
- **Approval workflow (business-logic integrity)** — `approval_decide` /
  `approval_withdraw` / `expense_submit` all take a `SELECT ... FOR UPDATE`
  row lock before mutating, and every state-changing `UPDATE` is conditioned
  on the expected prior state (`WHERE status = 'pending'` etc.), so concurrent
  double-decide/double-submit requests can't both succeed. Self-approval and
  out-of-turn approval are blocked server-side independent of the DB trigger.
- **Uploads** — extension allowlist + magic-byte content check
  (`uploads.inspect_upload`), server-generated UUID storage name (no path
  traversal), always served `as_attachment=True` (no inline render of
  attacker content), display filename sanitized to a safe charset before use
  in `Content-Disposition`.
- **Chat interface** — responder output is control-character-stripped,
  length-capped, and rendered through normal auto-escaping; the responder
  only ever receives the already-authenticated `g.user`, never a
  client-suppliable identity.
- **Secrets** — `SECRET_KEY`/DB passwords only come from `.env`
  (`.env` itself is gitignored and not tracked); `db/grants.sql` uses
  placeholder tokens substituted at init time, not literal passwords.
- **No dangerous sinks** — grep across `app/` for
  `eval(|exec(|pickle|yaml.load|subprocess|os.system|os.popen|shell=True|render_template_string`
  returned nothing.

## Out of scope / already known (not findings, per this skill's exclusion list)

- In-process-memory rate limiting (documented `# ponytail:` comment in
  `security.py`) — volumetric/DoS-class, excluded by the scan brief.
- Idle/absolute session expiry read from the cookie's own timestamp rather
  than a server-side session table (documented limitation in `auth.py`'s
  module docstring) — no concrete exploit path given `session_version`
  revocation already covers the stolen-cookie case.

## Recommendation

Nothing to patch from this pass. This single-pass review agrees with the
existing automated signal (453 pytest cases, 18/18 black-box defense checks
in `scripts/defense_check.py`) — independent confirmation, not a substitute
for it. If deeper assurance is wanted later, the harness's execution-verified
`vuln-pipeline` only targets C/C++ out of the box and would need `/customize`
porting to Python/Flask; likely not worth the effort at this codebase's size.
