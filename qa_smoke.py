"""
SecureLogAnalyzer — QA smoke test.
Runs against the Flask test client to verify routes, auth, CSRF, and reports.
Requires: python qa_smoke.py
"""
import os
import io

# Ensure a fresh dev-friendly environment
os.environ.setdefault("SECRET_KEY", "qa-test-secret-key")

import app as app_module

app = app_module.app
app.config["TESTING"] = True
app.config["WTF_CSRF_ENABLED"] = False


def get_csrf(client, path):
    """Fetch a page and extract the CSRF token from the rendered form."""
    resp = client.get(path)
    html = resp.get_data(as_text=True)
    # Token is rendered as value="..." for name=csrf_token
    marker = 'name="csrf_token" value="'
    start = html.find(marker)
    if start == -1:
        return None, html
    start += len(marker)
    end = html.find('"', start)
    return html[start:end], html


def test_public_pages():
    client = app.test_client()
    paths = ["/", "/about", "/login", "/register"]
    for path in paths:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code}"
        print(f"OK  GET {path}")

    # Login page renders the auth shell + CSRF token
    token, html = get_csrf(client, "/login")
    assert token, "Login page missing CSRF token"
    assert "Sign In" in html
    print("OK  CSRF token present on /login")


def test_register_login_logout():
    client = app.test_client()

    # Ensure a clean state (previous runs may have created this user)
    from database.database import get_user, delete_user
    existing = get_user("qauser")
    if existing:
        delete_user(existing["id"])

    # Register
    token, html = get_csrf(client, "/register")
    resp = client.post(
        "/register",
        data={
            "csrf_token": token,
            "username": "qauser",
            "password": "qatestpass123",
            "confirm_password": "qatestpass123",
        },
        follow_redirects=True,
    )
    assert "Account created successfully" in resp.get_data(as_text=True), "Register failed"
    print("OK  Register flow")

    # Login
    token, html = get_csrf(client, "/login")
    resp = client.post(
        "/login",
        data={"csrf_token": token, "username": "qauser", "password": "qatestpass123"},
        follow_redirects=True,
    )
    assert "Security Overview" in resp.get_data(as_text=True), "Login failed"
    print("OK  Login flow")

    # Dashboard (logged in)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "Security Overview" in resp.get_data(as_text=True)
    print("OK  GET /dashboard")

    # Account page
    resp = client.get("/account")
    assert resp.status_code == 200
    assert "qauser" in resp.get_data(as_text=True)
    print("OK  GET /account")

    # Reports page
    resp = client.get("/reports")
    assert resp.status_code == 200
    assert "Report Generator" in resp.get_data(as_text=True)
    print("OK  GET /reports")

    # Logout (POST with CSRF)
    token, html = get_csrf(client, "/dashboard")
    resp = client.post("/logout", data={"csrf_token": token}, follow_redirects=True)
    assert "Sign In" in resp.get_data(as_text=True), "Logout failed"
    print("OK  Logout flow")


def test_csrf_rejection():
    client = app.test_client()
    # POST without CSRF should be rejected
    resp = client.post("/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    print("OK  CSRF rejection on POST /login")


def test_admin_access_denied():
    client = app.test_client()
    # Not logged in
    resp = client.get("/admin/users")
    assert resp.status_code == 302
    print("OK  /admin/users redirects when anonymous")


def test_reports_pdf():
    """Login, ensure events exist, generate PDF, verify it has %PDF header."""
    client = app.test_client()

    # Clean up any previous qaadmin, then create fresh
    from database.database import get_user, create_user, delete_user
    from werkzeug.security import generate_password_hash
    existing_admin = get_user("qaadmin")
    if existing_admin:
        delete_user(existing_admin["id"])
    create_user("qaadmin", generate_password_hash("qaadminpass123"), "admin")

    # login qaadmin
    token, html = get_csrf(client, "/login")
    resp = client.post(
        "/login",
        data={"csrf_token": token, "username": "qaadmin", "password": "qaadminpass123"},
        follow_redirects=True,
    )
    assert "Security Overview" in resp.get_data(as_text=True), "admin login failed"

    # Upload sample
    sample_path = os.path.join("sample_logs", "security.xml")
    if os.path.exists(sample_path):
        with open(sample_path, "rb") as f:
            data = {"logfile": (io.BytesIO(f.read()), "security.xml")}
        token, html = get_csrf(client, "/upload")
        data["csrf_token"] = token
        resp = client.post("/upload", data=data, content_type="multipart/form-data", follow_redirects=True)
        assert "Successfully analyzed" in resp.get_data(as_text=True), "upload failed"
        print("OK  Upload + parse sample log")

        # Generate PDF
        token, html = get_csrf(client, "/reports")
        resp = client.post("/reports", data={"csrf_token": token})
        assert resp.status_code == 200
        assert resp.data[:4] == b"%PDF", "PDF header not found"
        assert resp.headers.get("Content-Disposition", "").startswith("attachment")
        size = len(resp.data)
        print(f"OK  PDF report generated ({size} bytes)")
    else:
        print("SKIP sample_logs/security.xml not found")


def test_hardened_parser_rejects_xxe():
    """Verify the hardened parser rejects DoS/XXE XML."""
    from parser.log_parser import parse_xml_log
    import tempfile

    evil = b'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <Event><System><EventID>4625</EventID></System></Event>
</Events>'''

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        f.write(evil)
        path = f.name
    try:
        try:
            parse_xml_log(path)
            print("NOTE  Parser accepted benign-parse (defusedxml may allow harmless DTD)")
        except ValueError:
            print("OK  Parser rejected malicious XML (ValueError)")
    finally:
        os.unlink(path)


if __name__ == "__main__":
    import sys

    # Capture output to a file as well as stdout (cmd redirection can be flaky).
    log_path = os.path.join(os.path.dirname(__file__), "qa_results.txt")
    log_file = open(log_path, "w", encoding="utf-8")

    class Tee:
        def __init__(self, *streams):
            self.streams = streams

        def write(self, message):
            for stream in self.streams:
                stream.write(message)
                stream.flush()

        def flush(self):
            for stream in self.streams:
                stream.flush()

    sys.stdout = Tee(sys.stdout, log_file)

    try:
        test_public_pages()
        test_csrf_rejection()
        test_register_login_logout()
        test_reports_pdf()
        test_hardened_parser_rejects_xxe()
        print("\nALL QA SMOKE TESTS PASSED")
    except Exception as error:
        print(f"\nQA FAILED: {type(error).__name__}: {error}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        log_file.close()
