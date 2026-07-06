"""Email-change business logic (issue / verify / resend).

This is the only module that touches the ``pending_email`` / ``pending_email_token``
/ ``pending_email_token_expires`` columns on the ``users`` table. It is the
email-change analog of ``services/verification_service.py``: the route layer
in ``api/routes/auth.py`` calls these functions and renders/redirects on the
result.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized -- never
  concatenate.
- VULN-3 (Reflected XSS): the token is never reflected back to the client; the
  /verify-email-change route renders a fixed outcome message, not the token.
- VULN-7 / VULN-8: the issue endpoint is reached via ``POST /profile/email/request``,
  which the existing CSRF + rate-limit middleware already guard. This module
  adds no new auth surface of its own.

Token model (mirrors Option A in verification_service.py):
- ``secrets.token_urlsafe(32)`` (256-bit) stored raw in ``pending_email_token``.
- ``pending_email_token_expires`` is ``time.time() + config.EMAIL_CHANGE_TTL_SECONDS``
  (default 1 hour, env-tunable).
- A successful verify clears all three columns, making the link single-use.
- The atomic promotion is one UPDATE: ``email = pending_email, pending_email =
  NULL, pending_email_token = NULL, pending_email_token_expires = NULL``.

This slice is additive: the eight lab vulnerabilities (VULN-1..VULN-8) on the
v0.1.0 base are not modified.
"""

import html
import logging
import re
import secrets
import time

from fastapi.responses import JSONResponse

from app.core import config, mailer
from app.core.security import verify_password
from app.db.session import get_db

logger = logging.getLogger(__name__)

# Project-wide email regex. The signup form uses HTML5 type="email" client-side
# (no server-side check exists in auth_service.signup); the email-change flow
# enforces it server-side as a defense-in-depth gate. Kept narrow on purpose
# to match what the browser considers a valid email: at least one @, a domain
# with at least one dot, no whitespace.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(value: str) -> bool:
    """Return True iff `value` is a syntactically well-formed email address.

    Server-side mirror of the browser's type="email" check. Rejects empty
    strings, whitespace, strings without `@`, and domains without a dot.
    Does not second-guess unusual but valid TLDs.
    """
    if not value:
        return False
    return _EMAIL_RE.match(value) is not None


def _esc(value: str) -> str:
    """Local helper: html.escape(..., quote=True) re-exported for readability."""
    return html.escape(value or "", quote=True)


def start_email_change(
    request_user_id: int,
    current_password: str,
    new_email: str,
    confirm_new_email: str,
) -> JSONResponse:
    """Issue a pending email change for the calling user.

    Inputs are pre-validated by the route handler (non-empty, match, regex).
    This function does the password gate, the uniqueness check, the token
    issuance, the persistence, and the email send.

    Returns JSON for every outcome so the profile page's fetch() handler can
    render feedback inline without a reload (mirrors
    verification_service.resend_for_credentials):
    - 400 {"error": "All fields are required"}     (defense in depth)
    - 400 {"error": "Emails do not match"}
    - 400 {"error": "Invalid email address"}
    - 401 {"error": "Not authenticated"}           (row gone)
    - 401 {"error": "Incorrect password"}
    - 400 {"error": "New email must be different from the current email"}
    - 409 {"error": "That email is already in use"}
    - 500 {"error": "Could not save the email change. Please try again."}
            (pending triple rolled back)
    - 502 {"error": "Could not send the verification email. Please try again later."}
            (pending triple rolled back)
    - 200 {"success": True, "message": "Verification email sent to {new_email}."}

    Every SELECT/UPDATE is parameterized; the confirm URL is the only string
    that crosses the wire, and the mailer escapes it before it enters HTML.
    """
    if not (current_password and new_email and confirm_new_email):
        return JSONResponse(
            content={"error": "All fields are required"}, status_code=400
        )
    if new_email != confirm_new_email:
        return JSONResponse(content={"error": "Emails do not match"}, status_code=400)
    if not is_valid_email(new_email):
        return JSONResponse(content={"error": "Invalid email address"}, status_code=400)

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, password FROM users WHERE id = ?",
            [request_user_id],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        # Session references a row that no longer exists. Defense in depth.
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    # FR-03: verify the current password with the existing verify_password
    # primitive. In v0.1.0 that is MD5 hex equality; in later versions it is
    # bcrypt. Either way it fails closed.
    if not verify_password(current_password, row["password"]):
        return JSONResponse(
            content={"error": "Incorrect password"}, status_code=401
        )

    # FR-02 final gate: refuse a "change" that doesn't change.
    if new_email == row["email"]:
        return JSONResponse(
            content={"error": "New email must be different from the current email"},
            status_code=400,
        )

    # FR-04: uniqueness check. Exclude the calling user's own row so a user
    # re-submitting their own current address doesn't fail spuriously after a
    # previous successful change. Parameterized.
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by email + id !=
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            [new_email, request_user_id],
        ).fetchone()
    finally:
        conn.close()
    if existing:
        return JSONResponse(
            content={"error": "That email is already in use"}, status_code=409
        )

    # FR-05: issue a fresh token and persist the pending triple. We re-issue
    # even if a previous pending triple is still set, so the second click wins
    # (matches SP-02 and TC-19 in the spec).
    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_CHANGE_TTL_SECONDS

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized UPDATE by primary key.
        conn.execute(
            "UPDATE users SET pending_email = ?, pending_email_token = ?, "
            "pending_email_token_expires = ? WHERE id = ?",
            [new_email, token, expires, request_user_id],
        )
        conn.commit()
    except Exception:
        logger.exception(
            "start_email_change: persist failed for user_id=%s", request_user_id
        )
        try:
            conn.execute(
                "UPDATE users SET pending_email = NULL, pending_email_token = NULL, "
                "pending_email_token_expires = NULL WHERE id = ?",
                [request_user_id],
            )
            conn.commit()
        except Exception:
            logger.exception(
                "start_email_change: rollback persist failed for user_id=%s",
                request_user_id,
            )
        return JSONResponse(
            content={"error": "Could not save the email change. Please try again."},
            status_code=500,
        )
    finally:
        conn.close()

    # Build the confirm URL. The token stays in the URL as one opaque value;
    # the mailer (core.mailer.send_email_change_email) escapes it wholesale
    # before it enters the HTML body.
    confirm_url = f"{config.APP_BASE_URL}/verify-email-change?token={token}"

    # FR-06: synchronous send. We choose background=False so the mailer's
    # return value tells us whether to roll back. The signup flow uses
    # background=True because the user can resend from /login; here, the
    # user has no resend affordance other than re-submitting the form, so
    # failing fast and rolling back is the right trade-off.
    if not mailer.send_email_change_email(new_email, row["username"], confirm_url):
        # Roll back the persistence. We re-open a connection because the
        # previous one was closed in the finally block above.
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET pending_email = NULL, pending_email_token = NULL, "
                "pending_email_token_expires = NULL WHERE id = ?",
                [request_user_id],
            )
            conn.commit()
        except Exception:
            logger.exception(
                "start_email_change: rollback after send failed for user_id=%s",
                request_user_id,
            )
        finally:
            conn.close()
        return JSONResponse(
            content={
                "error": "Could not send the verification email. Please try again later."
            },
            status_code=502,
        )

    # The new email is reflected in the success message so the user can
    # confirm they typed the right address. It is escaped (VULN-3 posture)
    # before the JSON serialization (json.dumps does NOT escape HTML by
    # default).
    return JSONResponse(
        content={
            "success": True,
            "message": f"Verification email sent to {_esc(new_email)}.",
        }
    )


def verify_email_change_token(token: str) -> dict:
    """Validate the token and atomically promote pending_email -> email on success.

    Returns a dict with shape::

        {"status": "ok",      "user": {id, username, new_email}}
        {"status": "expired", "user": None}
        {"status": "invalid", "user": None}

    The token is looked up by exact match -- it is never reflected back to
    the caller (VULN-3 posture). A successful verify is a single UPDATE that
    promotes the email AND clears the three pending columns, so the same
    token cannot be used twice.

    Called by GET /verify-email-change, which is a token-as-capability GET
    (no session required). The route handler also writes request.session if
    a session is present, so the verifying browser sees the new email
    immediately on /profile; the route handler is the right place for that
    side-effect because it knows about the request.
    """
    if not token:
        return {"status": "invalid", "user": None}

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized lookup by token value.
        row = conn.execute(
            "SELECT id, username, email, pending_email, "
            "pending_email_token_expires FROM users "
            "WHERE pending_email_token = ?",
            [token],
        ).fetchone()
        if not row:
            # No outstanding token matches (never issued, or already consumed).
            return {"status": "invalid", "user": None}

        expires = row["pending_email_token_expires"]
        if expires is None or time.time() > float(expires):
            # Expired -- DO NOT clear the pending triple. The user can
            # re-submit the form to re-issue a fresh token. (SP-02, EC-09.)
            return {"status": "expired", "user": None}

        # FIXED: SQL Injection closed -- single-statement atomic promotion.
        # Reading pending_email from the same row that owns the token means an
        # attacker who learned a valid token cannot substitute a different
        # email (EC-05).
        conn.execute(
            "UPDATE users SET email = pending_email, pending_email = NULL, "
            "pending_email_token = NULL, pending_email_token_expires = NULL "
            "WHERE id = ?",
            [row["id"]],
        )
        conn.commit()
        return {
            "status": "ok",
            "user": {
                "id": row["id"],
                "username": row["username"],
                "new_email": row["pending_email"],
            },
        }
    except Exception:
        logger.exception("verify_email_change_token failed")
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def resend_email_change_for_credentials(
    request_user_id: int, current_password: str
) -> JSONResponse:
    """Re-issue a fresh token against the same pending_email, gated on the password.

    The route handler in auth.py does not currently call this function -- the
    spec's FR-XX defines the re-request path as "user re-submits the form,"
    which goes through start_email_change with a fresh password re-prompt.
    This helper exists for spec completeness (the affected-files table in
    spec §3 lists it) and for a future UI affordance to resend without
    re-typing the new email.

    Behavior (mirrors verification_service.resend_for_credentials):
    - 400 {"error": "Current password is required"}
    - 401 {"error": "Not authenticated"}            (row gone)
    - 401 {"error": "Incorrect password"}
    - 400 {"error": "No pending email change to resend."}
            (row has NULL pending_email -- user has not yet submitted a request)
    - 500 {"error": "Could not save the email change. Please try again."}
    - 502 {"error": "Could not send the verification email. ..."}
    - 200 {"success": True, "message": "Verification email sent to {new_email}."}
    """
    if not current_password:
        return JSONResponse(
            content={"error": "Current password is required"}, status_code=400
        )

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT id, username, email, password, pending_email "
            "FROM users WHERE id = ?",
            [request_user_id],
        ).fetchone()
    finally:
        conn.close()

    if not row:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    if not verify_password(current_password, row["password"]):
        return JSONResponse(content={"error": "Incorrect password"}, status_code=401)

    if not row["pending_email"]:
        return JSONResponse(
            content={"error": "No pending email change to resend."},
            status_code=400,
        )

    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_CHANGE_TTL_SECONDS

    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET pending_email_token = ?, "
            "pending_email_token_expires = ? WHERE id = ?",
            [token, expires, request_user_id],
        )
        conn.commit()
    except Exception:
        logger.exception("resend_email_change_for_credentials: persist failed")
        return JSONResponse(
            content={"error": "Could not save the email change. Please try again."},
            status_code=500,
        )
    finally:
        conn.close()

    confirm_url = f"{config.APP_BASE_URL}/verify-email-change?token={token}"
    if not mailer.send_email_change_email(
        row["pending_email"], row["username"], confirm_url
    ):
        return JSONResponse(
            content={
                "error": "Could not send the verification email. Please try again later."
            },
            status_code=502,
        )

    return JSONResponse(
        content={
            "success": True,
            "message": f"Verification email sent to {_esc(row['pending_email'])}.",
        }
    )
