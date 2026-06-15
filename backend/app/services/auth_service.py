"""Authentication business logic for signup and login.

The HTTP route handlers in api/routes/auth.py are thin wrappers around the
two functions defined here. Keeping the business logic separate from the
transport layer means the SQL + password-verification flow can be unit-
tested without spinning up FastAPI, and the route handler stays a one-liner
that just forwards form fields to the service.

Closed vulnerabilities relevant to this file:
- VULN-1 (SQL Injection): every SQL statement uses parameterized `?`
  placeholders. Never reintroduce string concatenation here.
- VULN-5 (Weak Password Storage): passwords are hashed with bcrypt via
  core/security.hash_password() before insert, and checked with
  core/security.verify_password() in Python (NOT inside SQL -- bcrypt's
  per-call salt makes SQL equality matching impossible).
"""

import sqlite3

from starlette.requests import Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse

from app.db.session import get_db
from app.core.security import hash_password, verify_password


def signup(username: str, email: str, password: str):
    """Create a new user account.

    Returns (one of):
    - RedirectResponse(302, /login) on success -- the browser then follows
      to the login page, where the user authenticates with the credentials
      they just chose.
    - HTMLResponse(400, ...) if any field is empty, if the username already
      exists, or on any other DB error. The 400 responses are tiny HTML
      snippets with a "Go back" link -- intentional for the lab's no-JS
      signup flow.

    Note that the CSRF middleware has already validated the request before
    this function runs, so we do not need to re-check any csrf_token here.
    """
    # Trivial input validation. The HTML form's `required` attribute catches
    # most cases client-side, but a hand-crafted POST can still skip it, so
    # we re-validate server-side.
    if not username or not email or not password:
        return HTMLResponse(
            content="<h3>All fields are required</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )

    # Hash before insert. The plaintext password never touches the DB.
    hashed = hash_password(password)

    # FIXED: SQL Injection closed by using parameterized query.
    # The `?` placeholders are passed as a separate argument list, so the
    # SQLite driver binds the values without any string interpolation --
    # crafted input like `'); DROP TABLE users; --` is treated as data,
    # not as SQL.
    query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"

    conn = get_db()
    try:
        conn.execute(query, [username, email, hashed])
        conn.commit()
        # 302 makes the browser issue a fresh GET to /login. We do NOT log
        # the user in here -- forcing them to authenticate exercises the
        # password they just chose (and ends up writing the session cookie
        # via the login flow).
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        # Triggered by the `UNIQUE` constraint on `username`. Distinct from
        # the generic Exception branch below so the user gets a precise
        # error message instead of a generic "Error: ...".
        return HTMLResponse(
            content="<h3>Username already exists</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    except Exception as e:
        # Catch-all for unexpected DB errors (disk full, schema mismatch,
        # etc.). The error message is reflected back to the user; for a
        # production app you would log this server-side and show a
        # generic error instead.
        return HTMLResponse(
            content=f"<h3>Error: {str(e)}</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    finally:
        conn.close()


def login(request: Request, username: str, password: str):
    """Authenticate a user and populate the session on success.

    Returns:
    - JSONResponse(200, {"success": True, "redirect": "/welcome"}) on a
      valid credential pair. The session cookie is written by
      SessionMiddleware on the way out because we mutate request.session.
    - JSONResponse(401, {"error": "..."}) on bad credentials, missing
      fields, or DB errors.

    The HTML login page uses fetch() instead of a normal form submit so it
    can read the JSON response and redirect (or display the error inline)
    without a full page reload. That is why this function returns JSON
    instead of a redirect, in contrast to signup() above.

    Note: the same generic 401 body is used for "no such username", "bcrypt
    mismatch", and "legacy MD5 hash" cases. That intentional uniformity
    prevents username-enumeration via timing or message-text differences.
    """
    if not username or not password:
        return JSONResponse(
            content={"error": "Username and password are required"},
            status_code=401,
        )

    # FIXED: SQL Injection closed by using parameterized query.
    # We fetch the row by username, then compare passwords in Python.
    # Pre-fix versions of this code put the password equality test inside
    # the SQL (`WHERE username = ? AND password = ?`); that no longer
    # works because bcrypt produces a different hash each time (random
    # salt), so SQL equality would never match. Doing the bcrypt
    # comparison in Python via verify_password() is the correct primitive.
    query = "SELECT * FROM users WHERE username = ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [username])
        user = cursor.fetchone()
    except Exception:
        # Treat any DB error as a failed login. We do not surface the
        # underlying exception (avoid leaking schema details to an
        # attacker probing the endpoint).
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
    finally:
        conn.close()

    # verify_password() returns False rather than raising on a malformed
    # hash, so legacy MD5 rows fail closed here -- they cannot log in.
    if user and verify_password(password, user["password"]):
        # Populate the session. SessionMiddleware serializes this dict
        # and writes it back as a signed cookie on the response. The
        # CSRF token (already in the session from the prior GET /login
        # page render) is preserved -- we are merging keys, not
        # replacing the whole session.
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    else:
        # Same JSON body for "no such user" and "wrong password". See the
        # docstring's note on enumeration resistance.
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
