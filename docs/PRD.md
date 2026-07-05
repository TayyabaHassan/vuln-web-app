# Product Requirement Document

## Vulnerable Web Application - Security Lab

**Version:** 1.0.0
**Status:** Released
**Last Updated:** May 26, 2026
**Product Owner:** Arif Butt

---

## Document History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-05-26 | Product Team | Initial PRD |

---

## Executive Summary

The Vulnerable Web Application is an intentionally insecure web application designed as an educational platform for teaching common security vulnerabilities through hands-on exploitation. Unlike theoretical learning, this platform enables students to exploit vulnerabilities in a working application to understand how real attacks operate and how to implement proper defenses.

The application contains a fully functional authentication system with 8 deliberately introduced security flaws, covering critical OWASP Top 10 vulnerabilities. Built with FastAPI and SQLite, the codebase is simple enough to be read in a single session while being realistic enough to demonstrate actual attack techniques.

### Key Value Propositions

- **Practical Learning**: Exploit real vulnerabilities rather than studying theory
- **Complete Code Access**: Full source code visibility for root cause analysis
- **Safe Environment**: Controlled sandbox for ethical security education
- **Comprehensive Coverage**: 8 major vulnerability types in a single application
- **Professional Presentation**: University-branded interface suitable for academic institutions

---

## 1. Product Overview

### 1.1 Problem Statement

Traditional security education often focuses on theoretical knowledge without practical application. Students learn about SQL injection, XSS, and other vulnerabilities through slides and documentation but never experience exploiting or defending against them in a real application environment.

### 1.2 Solution

A deliberately vulnerable web application that serves as a hands-on laboratory where students can:
1. Identify security vulnerabilities in source code
2. Exploit vulnerabilities using real attack vectors
3. Analyze root causes at the code level
4. Implement secure coding practices to mitigate each vulnerability

### 1.3 Scope

The product includes:
- User authentication system (signup, login, logout)
- Protected dashboard page
- 8 intentional security vulnerabilities
- Comprehensive exploitation documentation
- Professional UI with university branding
- Database file download endpoint (intentional vulnerability)

Out of scope:
- User account management beyond signup/login
- Multi-factor authentication
- API endpoints for external integration
- Production deployment support

---

## 2. Target Audience

### 2.1 Primary Users

- **University Students**: Undergraduate and graduate students enrolled in cybersecurity, computer science, or software engineering programs
- **Security Training Participants**: Professionals attending security workshops or bootcamps
- **Self-Learners**: Individuals seeking hands-on security experience

### 2.2 Secondary Users

- **Instructors**: Faculty members teaching security courses
- **Security Researchers**: Professionals demonstrating vulnerabilities
- **CTF Participants**: Capture The Flag competitors

---

## 3. Functional Requirements

### 3.1 Core Features

#### FR-1: User Registration
- Users must be able to create an account with username, email, and password
- Username must be unique in the database
- Password confirmation must match the password field
- Successful registration redirects to the login page

#### FR-2: User Authentication
- Users must be able to log in with valid credentials
- Successful authentication redirects to the protected dashboard
- Failed authentication displays an error message
- Session must be established upon successful login

#### FR-3: Protected Dashboard
- The `/welcome` page must only be accessible to authenticated users
- The page must display the logged-in user's username
- The page must list all vulnerabilities to be discovered
- The page must include logout functionality

#### FR-4: User Logout
- Users must be able to terminate their session
- Logout must clear all session data
- After logout, users must be redirected to the login page

#### FR-5: User Search
- The `/search` endpoint must accept a query parameter
- Results must be displayed as an HTML response
- Search must match against both username and email fields

#### FR-6: User Email Change (Email Change with Verification)
- Authenticated users must be able to request a change of their email address from the profile page
- The change must require the current password and a confirmation of the new email
- The new email must be verified via a single-use confirmation link emailed to the new address
- The current email must remain in effect until the verification link is opened
- The token must be time-bounded (default 1 hour, env-tunable) and single-use

### 3.2 Intentional Vulnerabilities

#### VULN-1: SQL Injection (Priority: CRITICAL)
- **Location**: Login endpoint (`/login`)
- **Vulnerability**: Raw SQL query construction without parameterization
- **Attack Vector**: SQL payload in username field to bypass authentication
- **Exploitation**: Use `' OR '1'='1' --` to bypass password check
- **Root Cause**: String concatenation in `auth_service.py:login()`
- **Impact**: Complete authentication bypass

#### VULN-2: Stored XSS (Priority: HIGH)
- **Location**: Username field on signup page
- **Vulnerability**: JavaScript stored in database without escaping
- **Attack Vector**: Malicious username containing `<script>` tags
- **Exploitation**: Create account with `<img src=x onerror=alert('XSS')>`
- **Root Cause**: Unsanitized input saved to database, unescaped output
- **Impact**: Persistent code execution for all account visitors

#### VULN-3: Reflected XSS (Priority: HIGH)
- **Location**: Search endpoint (`/search`)
- **Vulnerability**: Query parameter reflected in response without escaping
- **Attack Vector**: JavaScript in URL parameter
- **Exploitation**: `/search?q=<img src=x onerror=alert('XSS')>`
- **Root Cause**: Direct output of user input in HTML response
- **Impact**: One-time code execution per link click

#### VULN-4: Session Hijacking (Priority: HIGH)
- **Location**: Session middleware configuration
- **Vulnerability**: Weak hardcoded session secret key
- **Attack Vector**: Session cookie theft and reuse
- **Exploitation**: Copy `session` cookie from DevTools, use in other browser
- **Root Cause**: Hardcoded `SECRET_KEY = "super-secret-key-12345"` in `main.py`
- **Impact**: Session takeover without credentials

#### VULN-5: Weak Password Storage (Priority: HIGH)
- **Location**: Password hashing in `security.py`
- **Vulnerability**: MD5 algorithm with no salt
- **Attack Vector**: Dictionary/brute force attacks on password hash
- **Exploitation**: Hash rainbow tables can reverse MD5 hashes
- **Root Cause**: `hashlib.md5()` usage in `security.py:hash_password()`
- **Impact**: Passwords compromised if database leaked

#### VULN-6: Exposed Database Endpoint (Priority: CRITICAL)
- **Location**: `/download/db` endpoint
- **Vulnerability**: Unauthenticated database file download
- **Attack Vector**: Direct HTTP GET to download SQLite file
- **Exploitation**: Visit `http://localhost:3001/download/db`
- **Root Cause**: No authentication check in `auth.py:download_db()`
- **Impact**: Complete database compromise

#### VULN-7: No Rate Limiting (Priority: MEDIUM)
- **Location**: All endpoints
- **Vulnerability**: Unlimited request attempts without throttling
- **Attack Vector**: Automated brute force scripts
- **Exploitation**: Rapid password guessing with no delays
- **Root Cause**: No rate limiting middleware configured
- **Impact**: Credential guessing attacks possible

#### VULN-8: CSRF (Priority: MEDIUM)
- **Location**: All form submissions
- **Vulnerability**: No CSRF token validation
- **Attack Vector**: Cross-site request forgery via malicious links
- **Exploitation**: Crafted forms submit without origin validation
- **Root Cause**: No CSRF protection on form submissions
- **Impact**: Unintended actions performed on user's behalf

---

## 4. Non-Functional Requirements

### 4.1 Performance

- Application must respond to requests within 200ms on average
- Database queries must complete within 50ms
- Static assets (CSS, images) must be cached appropriately

### 4.2 Usability

- Application must have a clean, professional interface
- Forms must provide clear error messages
- Navigation between pages must be intuitive
- Responsive design for mobile compatibility

### 4.3 Reliability

- Application must remain stable during vulnerability exploitation
- Database corruption must not occur during attacks
- Application must restart cleanly after crashes

### 4.4 Maintainability

- Code must be well-documented with docstrings
- Project structure must follow clear separation of concerns
- Dependencies must be managed via `pyproject.toml`

### 4.5 Security (Educational Context)

- Application must NOT be deployed to production environments
- Clear warnings must be displayed about intentional vulnerabilities
- Documentation must emphasize ethical use only

---

## 5. User Stories

### Epic 1: Account Management

**US-1.1: As a student, I want to create an account so that I can access the security lab.**
- Acceptance Criteria:
  - Signup form accepts username, email, and password
  - Password must be confirmed
  - Unique usernames enforced
  - Redirects to login after successful signup

**US-1.2: As a student, I want to log in to my account so that I can access the protected dashboard.**
- Acceptance Criteria:
  - Login form accepts username and password
  - Valid credentials grant access to `/welcome`
  - Invalid credentials display error message
  - Session established on success

**US-1.3: As a student, I want to log out so that I can end my session securely.**
- Acceptance Criteria:
  - Logout button available on dashboard
  - Clears all session data
  - Redirects to login page

### Epic 2: Vulnerability Exploitation

**US-2.1: As a student, I want to exploit SQL injection so that I can bypass authentication.**
- Acceptance Criteria:
  - Login bypass possible via SQL payload
  - Admin access gained without password
  - Vulnerability documented in code

**US-2.2: As a student, I want to demonstrate XSS so that I can understand injection attacks.**
- Acceptance Criteria:
  - Stored XSS possible via username field
  - Reflected XSS possible via search parameter
  - JavaScript executes in browser context

**US-2.3: As a student, I want to steal sessions so that I can understand session management.**
- Acceptance Criteria:
  - Session cookies accessible via browser tools
  - Cookie reuse allows session takeover
  - Weak secret key exploitable

**US-2.4: As a student, I want to access the database so that I can understand data exposure.**
- Acceptance Criteria:
  - Database file downloadable via HTTP
  - No authentication required
  - All user data readable

### Epic 3: Learning Experience

**US-3.1: As a student, I want a vulnerability checklist so that I can track my progress.**
- Acceptance Criteria:
  - Dashboard lists all 8 vulnerabilities
  - Each vulnerability has category tag
  - Description provided for each

**US-3.2: As a student, I want step-by-step instructions so that I can learn exploitation techniques.**
- Acceptance Criteria:
  - EXPLOITS.md provides detailed guides
  - Each vulnerability has dedicated section
  - Code-level explanations included

**US-3.3: As a student, I want professional branding so that the lab feels like a real academic tool.**
- Acceptance Criteria:
  - University logos displayed on all pages
  - Professional color scheme
  - Clean, modern UI design

---

## 6. Security Requirements (Educational Context)

### 6.1 Intentional Vulnerabilities

The following security flaws are DELIBERATELY implemented for educational purposes:

1. **SQL Injection**: Raw string concatenation in queries
2. **Stored XSS**: Unescaped database output in HTML
3. **Reflected XSS**: Unescaped URL parameters in HTML
4. **Session Weakness**: Hardcoded weak secret key
5. **Weak Crypto**: MD5 password hashing without salt
6. **Data Exposure**: Unauthenticated database download
7. **No Rate Limiting**: Unlimited authentication attempts
8. **CSRF Vulnerability**: No token validation

### 6.2 Safety Guidelines

- Application intended for educational use only
- Never deploy to production environments
- Only use on systems you own or have explicit permission to access
- Follow ethical hacking guidelines
- Obtain written authorization before testing on third-party systems

### 6.3 Legal Disclaimer

This application is provided strictly for educational purposes. Unauthorized access to computer systems is illegal. Ensure you have explicit permission before testing security vulnerabilities on any system you do not own. The authors are not responsible for misuse of this project.

---

## 7. Future Roadmap

### Phase 1: Enhancements (Short-term - 3 months)

- **Additional Vulnerabilities**
  - Command Injection
  - File Upload Vulnerabilities
  - XML External Entity (XXE)
  - Server-Side Request Forgery (SSRF)

- **Improved Documentation**
  - Video tutorials for each exploit
  - Code review exercises
  - Comparison with secure implementations

- **Learning Analytics**
  - Track vulnerabilities discovered by user
  - Progress tracking dashboard
  - Completion certificates

### Phase 2: Platform Features (Medium-term - 6 months)

- **Multi-user Scenarios**
  - Privilege escalation paths
  - Role-based access control (vulnerable)
  - Account takeover scenarios

- **Advanced Exploits**
  - Race condition vulnerabilities
  - Deserialization attacks
  - Authentication bypass techniques

- **Challenge System**
  - Difficulty levels for each vulnerability
  - Timed challenges
  - Leaderboard (optional)

### Phase 3: Ecosystem (Long-term - 12+ months)

- **Multiple Applications**
  - E-commerce vulnerable app
  - Social media vulnerable app
  - API security lab

- **Integration**
  - Docker containers for easy setup
  - Cloud deployment option (isolated)
  - CI/CD pipeline vulnerabilities

- **Community Features**
  - User-contributed challenges
  - Discussion forums
  - Solution sharing (optional hints)

---

## 8. Success Metrics

### 8.1 Learning Effectiveness

- **Vulnerability Discovery Rate**: Students should be able to identify 6+ vulnerabilities within first 2 hours
- **Exploitation Success**: 80% of students successfully exploit SQL injection within first hour
- **Code Understanding**: Students can locate root cause code for 5+ vulnerabilities after completing guide

### 8.2 User Satisfaction

- **Ease of Use**: 4+ out of 5 stars on feedback surveys
- **Documentation Clarity**: 90% of students find EXPLOITS.md clear and helpful
- **Relevance**: 85% of students report improved understanding of real-world vulnerabilities

### 8.3 Engagement

- **Session Duration**: Average lab session > 45 minutes
- **Return Visits**: 60% of users attempt the lab more than once
- **Completion Rate**: 70% of users attempt exploitation of all 8 vulnerabilities

---

## 9. Risk Assessment

### 9.1 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Students deploy to production | Low | Critical | Clear warnings in documentation and UI |
| Database corruption during attacks | Medium | Medium | Backup scripts provided |
| Difficulty too high for beginners | Medium | High | Comprehensive documentation and hints |
| Difficulty too low for advanced users | Low | Medium | Challenge system in roadmap |

### 9.2 Legal Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Misuse for malicious activities | Low | Critical | Legal disclaimers, ethics guidelines |
| Accidental exposure of personal data | Low | Medium | Warning about using real credentials |

### 9.3 Reputational Risks

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| University brand associated with "hacking" | Low | Medium | Clear educational context |
| Security community criticism of vulnerabilities | Low | Low | Intentional nature clearly documented |

---

## 10. Dependencies

### 10.1 External Dependencies

- **FastAPI** 0.109.0+: Web framework
- **Uvicorn** 0.27.0+: ASGI server
- **python-multipart** 0.0.6+: Form data parsing
- **itsdangerous** 2.0.0+: Session signing

### 10.2 Internal Dependencies

- **Python 3.9+**: Runtime environment
- **SQLite3**: Database engine (built into Python)
- **Filesystem**: Database file storage

---

## 11. Compliance Considerations

### 11.1 Educational Use

This product is designed exclusively for educational purposes. Its intentional vulnerabilities should never be used for malicious activities.

### 11.2 Ethical Guidelines

Users must adhere to:
- Only testing systems they own or have explicit permission to test
- Following vulnerability disclosure guidelines
- Respecting privacy and data protection laws
- Using knowledge for defensive purposes

### 11.3 Institutional Use

For academic institutions using this product:
- Ensure students understand ethical guidelines
- Obtain appropriate liability waivers
- Provide supervision during lab sessions
- Use isolated network environments

---

## 12. Support and Maintenance

### 12.1 Documentation

- **README.md**: Installation and getting started guide
- **EXPLOITS.md**: Detailed vulnerability exploitation guide
- **Code Comments**: Inline documentation for all source files
- **This PRD**: Complete product requirements

### 12.2 Issue Reporting

Issues should be reported via GitHub Issues with:
- Clear description of the problem
- Steps to reproduce
- Expected vs. actual behavior
- Environment details

### 12.3 Contribution Guidelines

Contributions welcome for:
- New vulnerability examples
- Documentation improvements
- UI/UX enhancements
- Educational content

---

## 13. Glossary

| Term | Definition |
|------|------------|
| SQL Injection | Attack where malicious SQL code is inserted into input fields |
| XSS (Cross-Site Scripting) | Injection of malicious scripts into web pages viewed by other users |
| Session Hijacking | Theft of session cookies to impersonate authenticated users |
| CSRF (Cross-Site Request Forgery) | Attack forcing users to execute unwanted actions on authenticated sites |
| Brute Force | Trial-and-error method for guessing credentials |
| OWASP Top 10 | Standard awareness document for most critical security risks |
| FastAPI | Modern Python web framework for building APIs |
| SQLite | Lightweight, file-based SQL database engine |
| Middleware | Software that handles requests between application and server |

---

## 14. Appendices

### Appendix A: Vulnerability Severity Matrix

| ID | Vulnerability | CVSS Score | OWASP Category | Exploit Difficulty | Impact |
|----|---------------|------------|----------------|-------------------|--------|
| VULN-1 | SQL Injection | 9.8 (Critical) | Injection | Very Easy | Complete System Compromise |
| VULN-2 | Stored XSS | 7.5 (High) | XSS | Easy | Data Theft, Session Hijacking |
| VULN-3 | Reflected XSS | 6.1 (Medium) | XSS | Easy | One-time Attack Execution |
| VULN-4 | Session Hijacking | 7.5 (High) | Broken Authentication | Easy | Account Takeover |
| VULN-5 | Weak Password Storage | 7.5 (High) | Cryptographic Failures | Medium | Credential Compromise |
| VULN-6 | Exposed Database | 9.8 (Critical) | Security Misconfiguration | Trivial | Complete Data Breach |
| VULN-7 | No Rate Limiting | 7.5 (High) | Broken Authentication | Medium | Credential Guessing |
| VULN-8 | CSRF | 6.5 (Medium) | CSRF | Medium | Unwanted Actions |

### Appendix B: Quick Start Guide

```bash
# 1. Clone repository
git clone <repository-url>
cd "Vulnerable app"

# 2. Install dependencies
cd backend
pip install uv
uv sync

# 3. Activate virtual environment
.venv\Scripts\Activate.ps1  # Windows PowerShell

# 4. Run application
python app/main.py

# 5. Access application
# Open http://localhost:3001 in browser
```

### Appendix C: Testing Checklist

- [ ] Signup with new account
- [ ] Login with valid credentials
- [ ] Access protected `/welcome` page
- [ ] Logout functionality
- [ ] SQL injection exploitation
- [ ] Stored XSS exploitation
- [ ] Reflected XSS exploitation
- [ ] Session hijacking demonstration
- [ ] Weak password hashing verification
- [ ] Database download vulnerability
- [ ] Brute force attack capability
- [ ] CSRF token absence verification

---

**Document End**

For questions or clarifications regarding this PRD, please contact the product team or open an issue in the project repository.