# SecureLogAnalyzer Study Guide

## 1. Project overview

This project is a Flask-based Windows security log analyzer. It lets an authenticated user upload a Windows Event XML file, parse the events, detect suspicious patterns, view them in a dashboard, and export a PDF report. The app is built around a SQLite database, server-rendered templates, and rule-based threat detection.

The project is implemented in:
- app.py — route layer and app setup
- config.py — configuration and session settings
- parser/log_parser.py — safe XML parsing
- analyzer/threat_detector.py — rule engine
- database/database.py — SQLite schema and queries
- report/pdf_report.py — PDF generation
- templates/ and static/ — frontend

## 2. Project structure

```text
SecureLogAnalyzer/
├── app.py
├── config.py
├── requirements.txt
├── database/
│   └── logs.db
├── parser/
│   └── log_parser.py
├── analyzer/
│   └── threat_detector.py
├── report/
│   └── pdf_report.py
├── utils/
│   └── helpers.py
├── templates/
├── static/
├── tests/
│   └── test_threat_detector.py
├── uploads/
├── reports/
└── sample_logs/
```

## 3. Technology stack

- Python 3.11+
- Flask 3.1.3
- SQLite via sqlite3
- Jinja2 templates
- Werkzeug security helpers
- itsdangerous for CSRF token signing
- defusedxml for safe XML parsing
- reportlab for PDF generation
- HTML/CSS/JavaScript front-end

## 4. Complete application flow

1. User opens the site.
2. Flask app initializes from Config.
3. Database is created on startup via create_database().
4. Login/register routes handle authentication.
5. Passwords are hashed with generate_password_hash().
6. A session is created with user_id, username, and role.
7. A logged-in user visits /upload.
8. The app validates file presence and extension.
9. File is saved to uploads/.
10. parse_xml_log() uses defusedxml to read XML safely.
11. Events are cleared and inserted into the SQLite events table.
12. The dashboard calls get_all_events() and detect_threats().
13. Rule-based detections produce threat records.
14. The reports page generates a PDF with generate_pdf().
15. The browser receives the file as an attachment.

## 5. Top 20 must-know concepts

1. Flask app initialization in app.py
2. Config object in config.py
3. CSRF protection and session token validation in app.py
4. Password hashing via werkzeug.security.generate_password_hash
5. Login verification with check_password_hash
6. Account lockout logic in database/database.py
7. Session creation in /login
8. Protected route pattern via login_required()
9. Admin-only access via admin_required()
10. SQLite users table
11. SQLite events table
12. parse_xml_log() logic
13. Threat detection rules in threat_detector.py
14. Failed login threshold logic
15. Possible brute-force detection
16. Possible account compromise detection
17. Upload validation path
18. PDF report generation
19. Jinja templates and dashboard rendering
20. Security weaknesses and limitations

## 6. Important modules

### app.py
- Creates the Flask app
- Initializes config and secret key
- Implements CSRF before_request hook
- Defines all routes for login, dashboard, upload, reports, password change and admin actions
- Handles errors for 400, 403, 404, 500

### config.py
- SECRET_KEY from environment with dev fallback
- UPLOAD_FOLDER default uploads
- REPORT_FOLDER default reports
- MAX_CONTENT_LENGTH = 100MB
- ALLOWED_EXTENSIONS = {"xml"}
- SESSION_COOKIE_HTTPONLY / SAMESITE / SECURE settings

### database/database.py
- create_database() creates users and events tables
- insert_events() writes log entries
- get_all_events() reads them
- search_events() filters by event_id, level, provider, start/end time
- get_user() / get_user_by_id() retrieve account info
- record_failed_login() and is_account_locked() handle brute-force security
- update_user_password() mutates stored hash

### parser/log_parser.py
- Uses defusedxml.ElementTree to parse XML safely
- Finds Event, System, Provider, EventID, Level, Computer, TimeCreated
- Builds a list of dictionaries for each event
- Does not fully sanitize message content; it stores the raw XML message text

### analyzer/threat_detector.py
- Maintains THREAT_RULES for Windows event IDs
- detect_threats(events) sorts events and creates rule-based detections
- Detects:
  - Event ID in THREAT_RULES
  - 5 failed logins in 10-minute window
  - failed login followed by successful login
  - suspicious privilege escalation after account creation
  - security log tampering after suspicious activity

### report/pdf_report.py
- Uses reportlab
- Creates a PDF with summary metrics and tables
- Returns a PDF file to the browser from /reports

## 7. Database explanation

### events table

| Column | Type | Purpose |
|---|---|---|
| id | INTEGER PRIMARY KEY AUTOINCREMENT | row identity |
| event_id | TEXT | Windows Event ID |
| level | TEXT | log level |
| time | TEXT | timestamp string |
| provider | TEXT | event source |
| computer | TEXT | host name |
| message | TEXT | message content |

### users table

| Column | Type | Purpose |
|---|---|---|
| id | INTEGER PRIMARY KEY AUTOINCREMENT | user identity |
| username | TEXT UNIQUE NOT NULL | login name |
| password_hash | TEXT NOT NULL | hashed password |
| role | TEXT NOT NULL DEFAULT 'user' | account role |
| created_at | TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP | created stamp |
| last_login | TEXT | last successful login |
| failed_login_attempts | INTEGER DEFAULT 0 | brute-force counter |
| locked_until | TEXT | lock expiry |
| is_active | INTEGER DEFAULT 1 | enabled/disabled state |

## 8. Authentication and account security

### Registration
- /register validates username and password length
- rejects duplicate username
- hashes password with generate_password_hash
- inserts a user record

### Login
- /login fetches user by username
- denies disabled account
- denies locked account
- verifies password with check_password_hash
- resets failed count on success
- stores session values

### Sessions
- Flask session stores user_id, username, role
- session cookie is configured as HTTPOnly and SameSite=Lax
- SESSION_COOKIE_SECURE is enabled only when set to 1 in env

### Password change
- /change-password requires current password
- enforces minimum length and confirmation
- rejects reusing the same password
- updates stored hash
- clears session after successful change

### Lockout mechanism
- record_failed_login() increments failed attempts
- if attempts >= 5, it sets locked_until = datetime('now', '+15 minutes')
- is_account_locked() checks current lock expiry

## 9. Log analysis engine

The analysis engine supports Windows Security XML logs. It reads XML files such as event exports, extracts event nodes, and groups metadata into a list of events.

### Detection rules actually implemented

1. Individual event ID detection
   - Recognizes IDs: 4624, 4625, 1102, 4672, 4720, 4726, 4728, 4732
   - Severity mapping is defined in THREAT_RULES

2. Brute-force detection
   - Counts 4625 failed login events over a 10-minute window
   - If 5 or more occur, it flags Possible Brute Force Attack

3. Account compromise detection
   - Looks for 4625 followed by 4624 within the same time window
   - Flags Possible Account Compromise

4. Privilege escalation after account creation
   - If 4720 occurs then later 4672 or 4728 or 4732, a suspicious sequence is flagged

5. Security log tampering
   - If suspicious activity occurs before Event ID 1102, and then 1102 happens, it flags Possible Security Log Tampering

## 10. File upload security

The upload flow is in /upload and uses:
- allowed_file() in utils/helpers.py
- secure_filename() from Werkzeug
- extension filter: only .xml
- size limit: MAX_CONTENT_LENGTH = 100 MB

There is protection against simple extension abuse, but the code stores untrusted uploaded XML content in a local upload directory and then parses it. The project does not perform content scanning beyond XML parsing and structural checks.

## 11. PDF report generation

The report is generated in report/pdf_report.py with reportlab. It creates:
- title page and summary metrics
- threat table
- event table
- output saved in reports/security_report.pdf

The report is returned to the browser with send_file() from /reports.

## 12. Frontend basics

The app uses server-rendered templates with Jinja2. Main pages include:
- index.html
- login.html
- register.html
- dashboard.html
- upload.html
- reports.html
- account.html
- admin_users.html
- change_password.html

JavaScript in static/js/script.js handles:
- sidebar interaction
- password visibility toggles
- alert dismissal
- upload UI and progress simulation
- expanding long messages

## 13. Security review

### Implemented protections
- Password hashing via werkzeug
- CSRF token validation on POST requests
- Session-based login state
- Account lockout after repeated failed attempts
- Disabled accounts in database
- XML parsing via defusedxml
- File extension validation
- HTTPOnly and SameSite session cookie settings

### Limitations and gaps
- SECRET_KEY has a development fallback in config.py
- No environment .env guidance is present in the repo
- No explicit SQLAlchemy ORM; schema is raw sqlite3
- Uploads are stored on disk and may be trusted without deep validation
- No user authorization RBAC beyond admin check on selected routes
- Dashboard and reports are tied to a single global events table and may be overwritten by a new upload
- No clear dataset retention or historical log archives
- No rate limiting on login or upload endpoints beyond lockout

## 14. Most likely viva questions

### Basic
1. What is your project?
2. What problem does it solve?
3. Why do organizations need log analysis?
4. What is Flask?
5. Why use Python?
6. What is a Windows Event log?
7. What does the dashboard show?
8. What is a security event?
9. What is authentication?
10. What is authorization?

### Project-specific
1. Where is the app initialized?
2. Where is CSRF protection implemented?
3. Which function validates uploaded XML?
4. What happens when a user logs in successfully?
5. Why does the app clear the events table before inserting new logs?
6. Which file contains the brute-force logic?
7. How does the app detect a possible account compromise?
8. What tables exist in the database?
9. What does reportlab do in this project?
10. Why do routes use login_required()?

## 15. 60-second explanation

This project is a Flask-based security log analyzer for Windows Event XML files. The system lets a user upload a log, parses the XML safely, stores the events in SQLite, and checks suspicious activity using predefined Windows security event rules. It can detect failed login bursts, successful logins after failed attempts, privilege changes, account creation activity, and log tampering. The app then shows the results in a dashboard and generates a PDF report. The main security focus is authentication, account lockout, CSRF protection, safe XML parsing, and controlled file handling.

## 16. Final checklist

- Understand Flask app startup and route flow
- Know database schema and purpose
- Understand login and session logic
- Be able to explain detection rules with examples
- Know upload validation and XML parsing
- Know PDF generation flow
- Be honest about security gaps and limitations
- Practice explaining why each module exists

## 17. Honest assessment

The project is a solid educational Flask security-monitoring app, but it is not production-grade in its current state. The architecture is understandable and follows a clear structure, but important limitations remain: default development secret, global event storage, limited historical analysis, and basic file validation. Those weaknesses are suitable to discuss explicitly in a viva.

## 18. Full viva question bank

### Level 1 — Basic (20 questions)

1. What is your project?
2. What problem does it solve?
3. Why is log analysis important?
4. What is a log file?
5. What is a Windows Event log?
6. What is Flask?
7. Why did you use Python?
8. What is authentication?
9. What is authorization?
10. What is a database?
11. What is a session?
12. What is a cookie?
13. What is a password hash?
14. What is a PDF report?
15. What is a web route?
16. What is a dashboard?
17. What is cybersecurity?
18. Why do companies monitor failed login attempts?
19. What is a web form?
20. What happens when a user uploads a file to a website?

### Level 2 — Project-specific (30 questions)

1. What is the main purpose of SecureLogAnalyzer?
2. Which file initializes the Flask app?
3. Which configuration file contains the app settings?
4. What is the purpose of the users table?
5. What is stored in the events table?
6. Which route handles user registration?
7. Which route handles user login?
8. How does the app check whether the user is logged in?
9. What does the login_required() function do?
10. Where is CSRF protection implemented?
11. Why does the app use generate_password_hash()?
12. Where does the app parse XML files?
13. Which library is used for safe XML parsing?
14. Which file handles threat detection logic?
15. What event IDs are tracked by the threat rules?
16. What is the detection threshold for failed logins?
17. What does detect_threats() return?
18. How is the dashboard populated?
19. What does the /upload route validate before saving a file?
20. Why does the app call clear_events() before insert_events()?
21. What happens when a file is set to the wrong extension?
22. Why is the report generated from reportlab?
23. Which route returns the PDF file to the browser?
24. What is the role of the database in this project?
25. What is the difference between the dashboard and the reports page?
26. Which JS file handles login password visibility and upload UI?
27. Why is the session cookie configured with HTTPOnly?
28. What is the purpose of admin_required()?
29. Which function blocks users from a page if they are not logged in?
30. Why does the app use a global events table instead of per-user storage?

### Level 3 — Code questions (30 questions)

1. Why is app.secret_key assigned from Config.SECRET_KEY?
2. What is the purpose of the before_request CSRF hook?
3. Why does validate_csrf_token() compare with session['_csrf_token']?
4. What is the purpose of the inject_csrf_token() function?
5. Why do the templates include csrf_token() in forms?
6. What does create_database() do at startup?
7. Why is sqlite3.Row used in database queries?
8. What does search_events() do with optional filters?
9. Why are filters combined with AND logic?
10. What does record_failed_login() update in the users table?
11. Why does a successful login call reset_failed_login()?
12. What exact condition makes a user account locked?
13. Why does parse_xml_log() use defusedxml instead of xml.etree.ElementTree?
14. What is the purpose of the THREAT_RULES mapping?
15. Why does detect_threats() sort events by time first?
16. Why do failed login events trigger a brute-force check only after 5 attempts?
17. How is a possible account compromise identified?
18. What is the role of the failed_login_sequence list?
19. Why is suspicious_before_log_clear reset after log clear detection?
20. Why is secure_filename() used in the upload route?
21. What is the purpose of allowed_file()?
22. Why does the upload route reject empty filenames?
23. What does file.save(filepath) do?
24. Why is XML parsing wrapped in a try/except inside upload()?
25. Why does the app clear the event table before inserting the latest data?
26. What is the purpose of format_timestamp() in app.py?
27. Why is the filter message list built in the dashboard route?
28. What is the role of generate_pdf() in report/pdf_report.py?
29. Why does the reports route call send_file()?
30. What happens if generate_pdf() raises an exception?

### Level 4 — Security questions (30 questions)

1. What threat is blocked by password hashing?
2. Why is hashing better than plain-text storage?
3. How does the app defend against brute-force attacks?
4. What is the effect of the failed login counter?
5. What happens when an account remains locked for 15 minutes?
6. What is the purpose of is_account_locked()?
7. Why is session data stored server-side in Flask?
8. Why is SESSION_COOKIE_HTTPONLY useful?
9. Why is same-site configuration relevant?
10. What is the threat model behind CSRF protection?
11. Why is the app checking a token on every POST request?
12. How does the app protect against malicious XML input?
13. Why is defusedxml important for XML parsers?
14. What is the risk of trusting uploaded XML files without validation?
15. Why are only .xml files allowed?
16. What is the risk of storing uploaded files permanently in uploads/?
17. What could happen if the SECRET_KEY is weak or defaulted?
18. How does the app protect admin routes?
19. Why is admin_required() separate from login_required()?
20. What is the difference between authentication and authorization here?
21. Why should password reset logic not reveal whether a username exists?
22. Why does the app show a generic invalid username or password message?
23. What is the security purpose of deactivating accounts?
24. How could an attacker abuse the reports feature?
25. What is the main limitation in the current event analysis design?
26. Why might it be dangerous to trust the uploaded data without context?
27. What does secure_filename() protect against?
28. Why is file extension validation not enough for security?
29. What is the security benefit of clearing the database before each upload?
30. What is the biggest weakness in the current configuration?

### Level 5 — Trick questions (20 questions)

1. If a user changes password successfully, why is the session cleared?
2. If a route is protected by login_required(), why is it still possible to be redirected to login repeatedly?
3. Why is the app able to display event data even before any upload?
4. Why can the app still accept a file with a valid extension but malicious content?
5. Why is a default SECRET_KEY a bad idea in production?
6. What is the security difference between validation and sanitization here?
7. If an attacker uploads a valid XML file with very large event count, what might happen?
8. Why does the app rely on a single events table instead of a history log?
9. If a user opens the same dashboard with different filters, why can the results vary dramatically?
10. Why is the account lockout threshold set to 5 in the code?
11. Why does the app not do full user authorization per resource?
12. What is the risk of treating all event messages as trusted text?
13. Why is the app not using a full production-grade ORM?
14. Why is the project easier to explain with direct SQLite than with Flask-SQLAlchemy?
15. If an attacker knows a valid username, what can they still do without the password?
16. What does the code do to reduce credential stuffing risk?
17. How would a malicious file affect the parser if it were not XML?
18. Why is it misleading to call the app a real-time SIEM?
19. Why does the app not automatically persist historical scans per user?
20. What is the most realistic interview weakness you should admit during a viva?

## 19. Mock viva

### Examiner: What is your project?
Student: My project is SecureLogAnalyzer, a Flask web application that uploads Windows Event XML logs, parses the events, analyzes possible security threats, displays them in a dashboard, and exports a PDF report.

### Examiner: Why did you build it?
Student: Because organizations generate large security logs, and it is difficult to review them manually. The app gives a simpler way to detect suspicious patterns such as multiple failed logins, successful logins after failures, and privilege escalation.

### Examiner: Where exactly is the Flask app initialized?
Student: In app.py, the app is created with Flask(__name__) and configured with app.config.from_object(Config). The secret key is loaded from the environment or a development fallback.

### Examiner: What is the role of config.py?
Student: It defines the application configuration, including the secret key, upload folder, report folder, allowed extension set, database path, and cookie security settings.

### Examiner: What happens in the login flow?
Student: The user submits a username and password to /login. The app fetches the user from the SQLite users table, checks if the account is active and not locked, verifies the password with check_password_hash(), and if the password matches, attaches user_id, username, and role to the Flask session and redirects to /dashboard.

### Examiner: How is the password stored?
Student: It is never stored in plain text. During registration, the app calls generate_password_hash(password) and stores the hash in the users.password_hash column.

### Examiner: Why do you store a hash instead of the raw password?
Student: If the database is stolen, the attacker cannot read user passwords directly. Hashing makes credential exposure much harder to exploit.

### Examiner: Where is CSRF protection implemented?
Student: In app.py, the before_request hook checks POST, PUT, PATCH, and DELETE requests for a valid csrf_token value. It validates it against a token stored in the Flask session.

### Examiner: Why is that important?
Student: It helps prevent cross-site request forgery, where a malicious site tricks a logged-in user into submitting a request to this app without their intention.

### Examiner: What happens when a file is uploaded?
Student: The /upload route checks whether a file exists, whether it has a filename, and whether the extension is allowed. It then saves the file to uploads and calls parse_xml_log(filepath). If parsing fails, the user gets an error message.

### Examiner: What does the parser do?
Student: It reads the XML safely using defusedxml, then loops through each Event node and extracts fields such as EventID, Level, Provider, Computer, and TimeCreated. It returns a list of dictionaries.

### Examiner: Why not parse XML with a normal library?
Student: The project specifically uses defusedxml to reduce XML external entity and unsafe parsing risk. The code explicitly mentions the security reason in parser/log_parser.py.

### Examiner: Where is threat detection implemented?
Student: In analyzer/threat_detector.py. The file defines THREAT_RULES and the detect_threats(events) function.

### Examiner: Give me one detection rule.
Student: One rule tracks failed logins. If there are 5 or more Event ID 4625 failures in a 10-minute window, the app raises Possible Brute Force Attack with Critical severity.

### Examiner: How is an account compromise detected?
Student: The app checks for a sequence of failed login events, followed by a successful login event 4624 within the same time window. If found, it flags Possible Account Compromise.

### Examiner: What is the database technology used?
Student: SQLite is used directly with Python’s sqlite3 module. The schema is created in database/database.py.

### Examiner: What are the two main tables?
Student: The users table stores account details and login security fields, and the events table stores parsed Windows security events.

### Examiner: Why does the app clear the events table before inserting new events?
Student: The app treats the current upload as the active dataset. Clearing the table keeps the dashboard and PDF report aligned with the latest uploaded log instead of a mix of historical data.

### Examiner: Is this a production-grade SIEM?
Student: No. It is a focused educational project that demonstrates log parsing and rule-based detection. It is useful for demonstration and learning, but it is limited compared to enterprise SIEM tools.

### Examiner: What is your biggest technical limitation?
Student: The app uses a single global events table and does not manage historical log sets per user or per project. It also uses a default development secret fallback and does not implement stronger production deployment controls.

### Examiner: What would you improve next?
Student: I would add per-user log histories, better file validation, stronger deployment security, environment-based secrets, and more advanced detection and reporting.

### Follow-up trick question
### Examiner: If a user uploads a valid XML file but the content is malicious, will your parser detect it?
Student: It can parse XML safely, but it does not perform deep semantic validation of the content beyond structure and event extraction. The project focuses on safe parsing, not full content trust analysis.

### Follow-up trick question
### Examiner: Why should an examiner not call this system perfect?
Student: Because the app still contains several limitations: default secret fallback, direct local storage of uploads, global event state, limited risk modeling, and basic access-control assumptions. Those are real weaknesses, and I should acknowledge them honestly.

## 20. Quick exam prep notes

- Practice explaining the flow: browser → route → validation → database → dashboard → report.
- Memorize the main files and their purpose: app.py, config.py, parser/log_parser.py, analyzer/threat_detector.py, database/database.py, report/pdf_report.py.
- Be ready to explain authentication and lockout logic in simple words.
- Be honest about limitations and security gaps.
- Practice a short 60-second explanation and a 3-minute explanation.
- Always tie your answer to the real code, not generic Flask knowledge.

## 21. Final viva-ready summary

SecureLogAnalyzer is a Flask-based security log analyzer for Windows Event XML files. It authenticates users, stores account data in SQLite, allows XML upload, parses events safely, detects suspicious patterns such as brute-force attempts and account compromise, displays findings in a dashboard, and exports a PDF report. The project is a good learning example of web security, log analysis, and rule-based detection, but it also has weaknesses that should be acknowledged clearly during presentation and viva.
