# Technical Design Document
## Vulnerable Web Application - Security Education Platform

**Version:** 1.0.0
**Last Updated:** May 26, 2026
**Purpose:** Educational platform for hands-on OWASP Top 10 vulnerability learning

---

## 1. Context and Purpose

This technical design document describes an intentionally vulnerable web application built for security education. The application demonstrates 8 common web security vulnerabilities (based on OWASP Top 10) through deliberate, exploitable flaws that students can attack, understand, and then remediate using secure coding practices.

**Educational Goal:** Bridge the gap between theoretical security knowledge and practical attack/defense skills by providing a working application that students can exploit safely in a controlled environment.

**Warning:** This application is deliberately insecure and must never be deployed to production or used on unauthorized systems.

---

## 2. System Architecture

### 2.1 High-Level Architecture

The application follows a **three-layer architecture** with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                     Presentation Layer                       │
│                 (Frontend: HTML/CSS/JS)                      │
│        login.html, signup.html, dashboard.html              │
└─────────────────────────────────────────────────────────────┘
                              ↓ HTTP Requests
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
│                 (FastAPI Routes & Services)                  │
│           auth.py (routes) → auth_service.py (logic)        │
└─────────────────────────────────────────────────────────────┘
                              ↓ SQL Queries
┌─────────────────────────────────────────────────────────────┐
│                      Data Layer                              │
│                     (SQLite Database)                        │
│                  session.py (connection)                     │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Backend Framework** | FastAPI | ≥0.109.0 | Web framework and routing |
| **ASGI Server** | Uvicorn | ≥0.27.0 | Production server |
| **Database** | SQLite3 | Built-in | Data persistence |
| **Session Management** | Starlette | (via FastAPI) | Session middleware |
| **Frontend** | HTML5/CSS3/JavaScript | Vanilla | User interface |
| **Package Manager** | uv | Latest | Python dependency management |
| **Python Runtime** | Python | ≥3.9 | Application runtime |

---

## 3. Component Design

### 3.1 Backend Components

#### 3.1.1 Entry Point (`backend/app/main.py`)

**Responsibilities:**
- Initialize FastAPI application instance
- Configure and register SessionMiddleware with hardcoded secret
- Mount static file directories (CSS, images)
- Register API routes from `auth.py`
- Initialize database schema on startup
- Start Uvicorn server on port 3001 (configurable via PORT env var)

**Key Design Decisions:**
- Session middleware uses weak hardcoded secret ("super-secret-key-12345") — **Vulnerability #4: Session Hijacking**
- Static files served via `StaticFiles` mount at `/static/*` paths
- Database initialization occurs at application startup

#### 3.1.2 HTTP Routes (`backend/app/api/routes/auth.py`)

**Endpoint Registry:**

| Method | Path | Handler | Purpose | Protected? |
|--------|------|---------|---------|------------|
| GET | `/` | `index()` | Redirect to signup | No |
| GET | `/signup` | `signup_page()` | Serve signup form | No |
| POST | `/signup` | `signup_post()` | Process registration | No |
| GET | `/login` | `login_page()` | Serve login form | No |
| POST | `/login` | `login_post()` | Process login | No |
| GET | `/download/db` | `download_db()` | Serve database file | No |
| GET | `/search` | `search_user()` | Search users | No |
| GET | `/welcome` | `welcome_page()` | User dashboard | Yes (session) |
| GET | `/logout` | `logout()` | Clear session | No |

**Key Design Decisions:**
- `/download/db` endpoint has **no authentication** — **Vulnerability #6: Exposed Database**
- `/search` endpoint directly interpolates user input into HTML response — **Vulnerability #3: Reflected XSS**
- `/welcome` endpoint checks for `user_id` in session before access
- All POST endpoints lack CSRF tokens — **Vulnerability #8: CSRF**
- No rate limiting configured on any endpoint — **Vulnerability #7: No Rate Limiting**

#### 3.1.3 Business Logic (`backend/app/services/auth_service.py`)

**Functions:**

| Function | Purpose | Input | Output |
|----------|---------|-------|--------|
| `signup()` | Register new user | username, email, password | RedirectResponse or HTMLResponse |
| `login()` | Authenticate user | request, username, password | RedirectResponse or JSONResponse |

**Key Design Decisions:**
- SQL queries built via string concatenation — **Vulnerability #1: SQL Injection**
  - `login()`: `WHERE username = '" + username + "' AND password = '" + hashed + "'"`
  - `signup()`: `INSERT INTO users ... VALUES ('" + username + "', '" + email + "', '" + hashed + "')"`
- Password hashing uses MD5 (no salt) — **Vulnerability #5: Weak Password Storage**
- No input validation beyond checking fields are non-null
- Error messages reveal when username already exists (information leakage)

#### 3.1.4 Database Layer (`backend/app/db/session.py`)

**Schema:**

```sql
CREATE TABLE IF NOT EXISTS users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email    TEXT,
    password TEXT
)
```

**Functions:**

| Function | Purpose | Returns |
|----------|---------|---------|
| `get_db()` | Open database connection with Row factory | sqlite3.Connection |
| `init_db()` | Create users table if missing | None |

**Key Design Decisions:**
- SQLite database file stored at project root (`vulnerable_app.db`)
- `check_same_thread=False` allows connection sharing (simplifies implementation)
- Row factory enabled for dict-style access to results
- No connection pooling (simplified for educational use)

#### 3.1.5 Security Utilities (`backend/app/core/security.py`)

**Functions:**

| Function | Purpose | Algorithm |
|----------|---------|-----------|
| `hash_password()` | Hash password for storage | MD5 (no salt) |

**Key Design Decisions:**
- Uses `hashlib.md5()` without salt — **Vulnerability #5: Weak Password Storage**
- Returns hexadecimal digest
- No pepper or key derivation function (KDF)

---

### 3.2 Frontend Components

#### 3.2.1 HTML Templates

| Template | Purpose | Key Features |
|----------|---------|--------------|
| `login.html` | User authentication form | Client-side AJAX login, error display inline |
| `signup.html` | User registration form | Password confirmation validation, university branding |
| `dashboard.html` | Protected user dashboard | Shows logged-in username, vulnerability list, mission statement |

**Key Design Decisions:**
- Client-side form submission via `fetch()` API for login
- Username displayed via server-side placeholder substitution (`{{username}}`)
- University/organization logos in header (PUCIT, Excaliat, FCCU)
- No JavaScript framework (vanilla JS for simplicity)
- Responsive design with split-panel layout for auth pages

#### 3.2.2 Styling (`frontend/static/css/styles.css`)

**Design System:**
- **Primary Color:** Indigo/Deep Blue (#1a237e, #3949ab)
- **Secondary Colors:** Gradient backgrounds, white forms
- **Typography:** System UI fonts (Segoe UI, -apple-system)
- **Layout:** CSS Grid for auth split, Flexbox for components
- **Components:** Forms, buttons, cards, tags for vulnerability types

**Key Design Decisions:**
- Fixed header (70px height) with logos and title
- Auth pages use split layout: left decorative panel, right form panel
- Dashboard uses centered container with vulnerability grid
- Mobile-responsive design considerations
- Color-coded vulnerability tags (SQLi, XSS, Session, etc.)

---

### 3.3 Data Flow

#### 3.3.1 User Registration Flow

```
1. User visits /signup → signup.html served
2. User fills form → POST /signup with username, email, password
3. auth.py:signup_post() receives data via FastAPI Form()
4. auth_service.py:signup() called
5. hash_password() computes MD5 hash
6. SQL query built via string concatenation
7. INSERT query executed via session.py:get_db()
8. Redirect to /login on success
```

#### 3.3.2 User Login Flow

```
1. User visits /login → login.html served
2. User fills form → POST /login with username, password
3. auth.py:login_post() receives data via FastAPI Form()
4. auth_service.py:login() called with request object
5. hash_password() computes MD5 of input password
6. SQL query built via string concatenation
7. SELECT query executed via session.py:get_db()
8. On success: session['user_id'], session['username'], session['email'] set
9. Redirect to /welcome
10. welcome_page() checks session for user_id
11. dashboard.html loaded with username substituted
```

#### 3.3.3 Vulnerability Injection Flows

**SQL Injection Path:**
```
User Input (login form)
    ↓
FastAPI Form() parameter extraction
    ↓
auth_service.py:login()
    ↓
String concatenation: "WHERE username = '" + username + "'"
    ↓
SQLite executes malicious SQL
    ↓
Authentication bypassed
```

**Stored XSS Path:**
```
User Input (signup form - username with <script>)
    ↓
auth_service.py:signup()
    ↓
Stored in database unescaped
    ↓
User logs in → welcome_page()
    ↓
HTML loaded: html.replace('{{username}}', username)
    ↓
JavaScript executes in user's browser
```

**Reflected XSS Path:**
```
User Input (URL query parameter ?q=<script>)
    ↓
auth.py:search_user()
    ↓
HTML constructed: f"<li>{row[0]} ({row[1]})</li>"
    ↓
No escaping applied
    ↓
JavaScript executes immediately
```

---

## 4. Vulnerability Design

### 4.1 Intentional Vulnerabilities

| # | Vulnerability | OWASP Category | Location | Root Cause |
|---|---------------|----------------|----------|------------|
| 1 | SQL Injection | A03:2021 - Injection | `auth_service.py:51-52` | String concatenation in SQL query construction |
| 2 | Stored XSS | A03:2021 - Injection | `auth.py:91-92` | Username not escaped when reflected in dashboard |
| 3 | Reflected XSS | A03:2021 - Injection | `auth.py:63-77` | Query parameter interpolated into HTML without escaping |
| 4 | Session Hijacking | A07:2021 - ID and Auth Failures | `main.py:25` | Hardcoded weak secret key for session signing |
| 5 | Weak Password Storage | A02:2021 - Cryptographic Failures | `security.py:8-10` | MD5 hashing without salt or KDF |
| 6 | Exposed Database | A01:2021 - Broken Access Control | `auth.py:50-54` | No authentication check on `/download/db` endpoint |
| 7 | No Rate Limiting | A07:2021 - ID and Auth Failures | (Global) | No middleware for request throttling |
| 8 | CSRF | A01:2021 - Broken Access Control | (Global) | No CSRF tokens on POST endpoints |

### 4.2 Vulnerability Chain Analysis

**Critical Attack Path:**
```
SQL Injection (auth_service.py) → Authentication Bypass
        ↓
Weak Session Secret (main.py) → Predictable Session Tokens
        ↓
Session Hijacking → Impersonation Without Credentials
        ↓
Reflected XSS (auth.py) → Session Theft via Malicious Link
        ↓
Stored XSS (database) → Persistent Attack on Account
        ↓
Database Exposure (auth.py) → All Credentials Compromised
        ↓
Weak Password Storage (security.py) → Offline Password Cracking
```

### 4.3 Educational Learning Outcomes

| Vulnerability | Learning Objectives |
|---------------|---------------------|
| SQL Injection | Understand parameterized queries, input validation, ORM benefits |
| XSS | Learn output encoding, Content Security Policy, sanitization |
| Session Hijacking | Secure session management, HttpOnly cookies, secure key generation |
| Weak Password Storage | Modern password hashing (bcrypt, argon2), salt, pepper, KDFs |
| Exposed Database | Access control principles, least privilege, endpoint security |
| No Rate Limiting | Defense in depth, account lockout, CAPTCHA, anomaly detection |
| CSRF | SameSite cookies, CSRF tokens, state-changing operations verification |

---

## 5. Security Considerations

### 5.1 Intentional Insecurities

The following are **deliberately implemented flaws** for educational purposes:

1. **SQL Injection:** Direct string concatenation in database queries without parameterization
2. **XSS:** User input reflected without HTML escaping or sanitization
3. **Weak Session Secret:** Hardcoded secret key in source code
4. **MD5 Password Hashing:** Broken algorithm with no salt
5. **Unauthenticated Database Download:** Public endpoint serving SQLite file
6. **No Rate Limiting:** Unlimited request attempts on all endpoints
7. **Missing CSRF Protection:** No tokens or SameSite cookie attributes
8. **Information Leakage:** Error messages reveal system details

### 5.2 Deployment Restrictions

**MUST NEVER:**
- Deploy to production environments
- Connect to real user data or production databases
- Host on publicly accessible servers without explicit authorization
- Use in penetration testing against unauthorized targets

**MUST ALWAYS:**
- Run in isolated development/educational environments
- Use only for authorized security training and education
- Obtain explicit written permission before using on any system
- Clearly document educational purpose to all users

### 5.3 Safe Usage Guidelines

1. **Environment Isolation:** Run in Docker containers or VMs when possible
2. **Network Segmentation:** Restrict to localhost or isolated networks
3. **Data Sanitization:** Never use real PII or sensitive data in test accounts
4. **Access Control:** Limit access to authorized students/personnel only
5. **Monitoring:** Log all access and exploitation attempts for educational review

---

## 6. Development and Deployment

### 6.1 Prerequisites

- Python 3.9 or higher
- uv package manager
- Git (optional, for cloning)
- Modern web browser with DevTools

### 6.2 Setup Instructions

```powershell
# Clone repository
git clone <repository-url>
cd "Vulnerable-app"

# Install dependencies
cd backend
uv sync

# Activate virtual environment
.venv\Scripts\Activate.ps1

# Run application
python app/main.py
```

Application starts on `http://localhost:3001`

### 6.3 Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| PORT | 3001 | Server port number |
| SECRET_KEY | "super-secret-key-12345" | Session signing secret (intentionally weak) |

### 6.4 Database Management

**Location:** `vulnerable_app.db` in project root

**View contents:**
```powershell
python -c "import sqlite3; conn = sqlite3.connect('vulnerable_app.db'); [print(r) for r in conn.execute('SELECT * FROM users').fetchall()]; conn.close()"
```

**Reset database:** Delete `vulnerable_app.db` file and restart application (recreates automatically)

### 6.5 Project Structure

```
Vulnerable-app/
├── README.md                           # Project overview
├── CLAUDE.md                           # Codebase instructions
├── docs/
│   └── EXPLOITS.md                     # Exploitation guide
├── backend/
│   ├── pyproject.toml                  # Project dependencies
│   ├── requirements.txt                # Pip requirements
│   ├── uv.lock                         # Dependency lock file
│   └── app/
│       ├── main.py                     # Application entry point
│       ├── core/
│       │   └── security.py             # Password hashing utilities
│       ├── db/
│       │   └── session.py              # Database connection layer
│       ├── services/
│       │   └── auth_service.py         # Authentication business logic
│       └── api/
│           └── routes/
│               └── auth.py             # HTTP route handlers
└── frontend/
    ├── static/
    │   ├── css/
    │   │   └── styles.css              # Application styling
    │   └── images/
    │       ├── PUCIT_Logo.png
    │       ├── blue-logo-scl2.png
    │       └── excaliat-logo.png
    └── templates/
        ├── login.html                  # Login page
        ├── signup.html                 # Registration page
        └── dashboard.html              # Protected dashboard
```

---

## 7. Testing and Verification

### 7.1 Vulnerability Verification Steps

**SQL Injection:**
1. Navigate to `http://localhost:3001/login`
2. Enter username: `admin' OR '1'='1' --`
3. Enter any password
4. Verify successful login bypass

**Stored XSS:**
1. Sign up with username: `<img src=x onerror=alert('XSS')>`
2. Log in with those credentials
3. Verify alert popup appears on dashboard

**Reflected XSS:**
1. Visit `http://localhost:3001/search?q=<img src=x onerror=alert(1)>`
2. Verify alert popup appears immediately

**Session Hijacking:**
1. Log in normally
2. Copy session cookie from DevTools
3. Log out
4. Paste cookie back in DevTools
5. Verify access restored to `/welcome`

**Weak Password Storage:**
1. Sign up account
2. Download database via `http://localhost:3001/download/db`
3. Open with DB Browser for SQLite
4. Verify MD5 hashes (not plaintext, but reversible via rainbow tables)

**Exposed Database:**
1. Visit `http://localhost:3001/download/db` without authentication
2. Verify database file downloads successfully

**No Rate Limiting:**
1. Create brute force script
2. Run unlimited login attempts
3. Verify no blocking or throttling occurs

**CSRF:**
1. Craft malicious HTML form pointing to `/signup` or `/login`
2. Open form in browser while logged in
3. Verify request executes without CSRF token

### 7.2 End-to-End Test Cases

| Test | Steps | Expected Result |
|------|-------|-----------------|
| Normal Signup | Fill signup form with valid data | Account created, redirect to login |
| Normal Login | Fill login form with valid credentials | Session created, redirect to `/welcome` |
| Dashboard Access | Visit `/welcome` after login | Dashboard displays username |
| Logout Protection | Visit `/welcome` after logout | Redirect to `/login` |
| Search Function | Use `/search?q=test` endpoint | Returns matching users (or reflected XSS if malicious) |

---

## 8. Future Enhancements

### 8.1 Educational Improvements

- **Vulnerability Hints System:** Add optional hints that guide students to vulnerable code locations
- **Exploit Confirmation API:** Endpoints to verify successful exploitation (educational feedback)
- **Fix Validation Mode:** Mode that checks if vulnerabilities have been properly remediated
- **Progress Tracking:** Track which vulnerabilities have been found, exploited, and fixed
- **Challenge Levels:** Easy/medium/hard variants of each vulnerability type

### 8.2 Technical Enhancements

- **Docker Support:** Containerized deployment for easy classroom setup
- **Multiple Vulnerability Scenarios:** Additional intentional flaws (IDOR, SSRF, RCE simulation)
- **Logging Framework:** Request logging for attack analysis and learning
- **Automated Scanning Integration:** Integration with OWASP ZAP/Burp Suite for educational scanning
- **Fix Guides:** Step-by-step remediation instructions for each vulnerability

### 8.3 Documentation Improvements

- **Architecture Diagrams:** Visual representation of data flows and component interactions
- **Attack Tree Documentation:** Structured attack paths showing vulnerability relationships
- **Code Review Guides:** Checklists for reviewing similar codebases for these flaws
- **Secure Coding Patterns:** Templates showing correct implementations for each vulnerability

---

## 9. Maintenance and Support

### 9.1 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | May 2026 | Initial release with 8 OWASP Top 10 vulnerabilities |

### 9.2 Known Limitations

1. **Simplified Attack Vectors:** Vulnerabilities are deliberately straightforward for educational clarity
2. **No Production Hardening:** Missing all security controls found in real applications
3. **Single-User Model:** No multi-tenancy, role-based access control, or complex permission systems
4. **No API Versioning:** Single API endpoint structure without versioning
5. **Limited Database Complexity:** Single table schema (real apps have relational complexity)

### 9.3 Support Resources

- **Exploitation Guide:** `docs/EXPLOITS.md` contains step-by-step attack instructions
- **OWASP Top 10:** https://owasp.org/Top10/ for official vulnerability documentation
- **FastAPI Docs:** https://fastapi.tiangolo.com/ for framework documentation
- **SQLite Docs:** https://www.sqlite.org/docs.html for database reference

---

## 10. References

### 10.1 Standards and Guidelines

- **OWASP Top 10:** https://owasp.org/Top10/
- **CWE/SANS Top 25:** https://cwe.mitre.org/top25/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **ISO/IEC 27001:** Information security management systems

### 10.2 Educational Resources

- **OWASP Web Security Testing Guide:** https://owasp.org/www-project-web-security-testing-guide/
- **PortSwigger Web Security Academy:** https://portswigger.net/web-security
- **Hacker101:** https://www.hacker101.com/
- **OWASP Juice Shop:** https://owasp.org/www-project-juice-shop/

### 10.3 Security Tools

- **OWASP ZAP:** https://www.zaproxy.org/
- **Burp Suite:** https://portswigger.net/burp
- **sqlmap:** https://sqlmap.org/
- **Metasploit:** https://www.metasploit.com/

---



## 11. Technical Requirements

### 11.1 Technology Stack

**Backend**
- **Framework**: FastAPI 0.109.0+
- **Server**: Uvicorn 0.27.0+
- **Language**: Python 3.9+
- **Database**: SQLite3
- **Session Management**: Starlette SessionMiddleware

**Frontend**
- **HTML**: HTML5
- **CSS**: Custom CSS3 (no framework)
- **JavaScript**: Vanilla JS
- **Icons**: None required (text-based UI)

**Development Tools**
- **Package Manager**: pip/uv
- **Project Config**: pyproject.toml
- **Testing**: pytest (optional)

### 11.2 Architecture

```
Vulnerable App/
├── backend/
│   ├── app/
│   │   ├── main.py              # Application entry point
│   │   ├── api/
│   │   │   └── routes/
│   │   │       └── auth.py      # HTTP route handlers
│   │   ├── core/
│   │   │   └── security.py      # Password hashing (vulnerable)
│   │   ├── db/
│   │   │   └── session.py       # Database management
│   │   └── services/
│   │       └── auth_service.py  # Business logic (vulnerable)
│   └── pyproject.toml           # Dependencies
│
├── frontend/
│   ├── templates/
│   │   ├── login.html
│   │   ├── signup.html
│   │   └── dashboard.html
│   └── static/
│       ├── css/styles.css
│       └── images/
│           ├── PUCIT_Logo.png
│           ├── blue-logo-scl2.png
│           └── excaliat-logo.png
│
└── vulnerable_app.db            # SQLite database
```

### 11.3 Database Schema

```sql
CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email    TEXT,
    password TEXT  -- MD5 hash (vulnerable)
);
-- The Email Change with Verification feature adds three nullable columns
-- to the users table (idempotent ALTER; no grandfather UPDATE needed):
ALTER TABLE users ADD COLUMN pending_email TEXT;
ALTER TABLE users ADD COLUMN pending_email_token TEXT;
ALTER TABLE users ADD COLUMN pending_email_token_expires REAL;
```

### 11.4 API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | Redirect to signup | No |
| GET | `/signup` | Display signup form | No |
| POST | `/signup` | Create user account | No |
| GET | `/login` | Display login form | No |
| POST | `/login` | Authenticate user | No |
| GET | `/welcome` | Display protected dashboard | Yes |
| GET | `/logout` | Terminate session | No |
| GET | `/search` | Search users | No (vulnerable) |
| GET | `/download/db` | Download database | No (vulnerable) |

The Email Change with Verification feature (additive; not in the v0.1.0 lab baseline) adds:

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/profile/email/request` | Issue a pending email change (sends verification link to the new address) | Yes (session + `csrf_token` hidden field) |
| GET | `/verify-email-change?token=…` | Promote `pending_email` to `email` on a valid, unexpired, unconsumed token | No (token is the capability) |

### 11.5 Deployment Requirements

**Development Environment**
- Python 3.9 or later
- Git (for cloning)
- Local filesystem access for database

**Production Restrictions**
- MUST NOT be deployed to public internet
- MUST NOT be used on systems without explicit permission
- MUST include clear warnings about vulnerabilities

```

**Document Status:** Complete
**Next Review Date:** Upon next major version release
**Approval:** Educational use only - not for production deployment