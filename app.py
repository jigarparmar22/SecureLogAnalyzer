import os
from datetime import datetime
from report.pdf_report import generate_pdf
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    flash,
    send_file,
    session,
    abort,
    url_for,
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from config import Config
from utils.helpers import allowed_file
from parser.log_parser import parse_xml_log
from analyzer.threat_detector import detect_threats
from database.database import (
    create_database,
    insert_events,
    clear_events,
    get_all_events,
    search_events,
    get_user,
    get_user_by_id,
    record_failed_login,
    reset_failed_login,
    is_account_locked,
    get_all_users,
    username_exists,
    create_user,
    update_user_password,
    activate_user,
    deactivate_user,
    delete_user,
)

app = Flask(__name__)
app.config.from_object(Config)

# Required for flash() messages
app.secret_key = app.config["SECRET_KEY"]

# CSRF protection using itsdangerous (already a Flask dependency).
# A per-session random token is generated and validated on every POST.
csrf_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])


def generate_csrf_token():
    """Generate (or reuse) a per-session CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = os.urandom(32).hex()
    return csrf_serializer.dumps(session["_csrf_token"])


def validate_csrf_token(token):
    """Validate a submitted CSRF token against the session token."""
    if not token:
        return False
    try:
        decoded = csrf_serializer.loads(token, max_age=3600)
    except (BadSignature, SignatureExpired):
        return False
    return decoded == session.get("_csrf_token")


@app.before_request
def csrf_protect():
    """Reject unsafe methods without a valid CSRF token."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if not validate_csrf_token(token):
            abort(400, description="Invalid or missing CSRF token.")


@app.context_processor
def inject_csrf_token():
    # Return the function itself so templates call {{ csrf_token() }}
    # to generate a fresh token each render.
    return {"csrf_token": generate_csrf_token}


# Create uploads folder if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["REPORT_FOLDER"], exist_ok=True)
create_database()


def login_required():
    if "user_id" not in session:
        return False
    return True


def admin_required():
    if "user_id" not in session:
        return False
    if session.get("role") != "admin":
        return False
    return True


def format_timestamp(value):
    """Format a raw timestamp string into a readable form."""
    if not value:
        return "N/A"
    value = str(value).strip()
    # Windows Event Log format: 2026-07-16T11:09:11.9240531Z
    try:
        if value.endswith("Z"):
            value = value[:-1]
        if "." in value:
            value = value.split(".", 1)[0]
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


app.jinja_env.filters["fmt_ts"] = format_timestamp


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", page_title="Bad Request", code=400, message=error.description or "Bad request."), 400


@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", page_title="Access Denied", code=403, message=error.description or "Access denied."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", page_title="Not Found", code=404, message="The requested page was not found."), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template("error.html", page_title="Server Error", code=500, message="An internal server error occurred."), 500


@app.route("/admin/users")
def admin_users():
    if not admin_required():
        flash("Administrator access required.", "danger")
        return redirect("/dashboard")

    users = get_all_users()

    return render_template("admin_users.html", users=users, page_title="User Management")


@app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
def admin_deactivate_user(user_id):
    if not admin_required():
        flash("Administrator access required.", "danger")
        return redirect("/dashboard")

    # Prevent admin from disabling themselves
    if user_id == session["user_id"]:
        flash("You cannot deactivate your own account.", "warning")
        return redirect("/admin/users")

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/admin/users")

    deactivate_user(user_id)
    flash(f"User account '{user['username']}' deactivated successfully.", "success")
    return redirect("/admin/users")


@app.route("/admin/users/<int:user_id>/activate", methods=["POST"])
def admin_activate_user(user_id):
    if not admin_required():
        flash("Administrator access required.", "danger")
        return redirect("/dashboard")

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/admin/users")

    activate_user(user_id)
    flash(f"User account '{user['username']}' activated successfully.", "success")
    return redirect("/admin/users")


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_delete_user(user_id):
    if not admin_required():
        flash("Administrator access required.", "danger")
        return redirect("/dashboard")

    # Prevent admin from deleting themselves
    if user_id == session["user_id"]:
        flash("You cannot delete your own account.", "warning")
        return redirect("/admin/users")

    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect("/admin/users")

    delete_user(user_id)
    flash(f"User account '{user['username']}' deleted successfully.", "success")
    return redirect("/admin/users")


@app.route("/admin/users/<int:user_id>/reset-password", methods=["GET", "POST"])
def admin_reset_password(user_id):
    if not admin_required():
        flash("Administrator access required.", "danger")
        return redirect("/dashboard")

    user = get_user_by_id(user_id)

    if not user:
        flash("User not found.", "danger")
        return redirect("/admin/users")

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect(url_for("admin_reset_password", user_id=user_id))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("admin_reset_password", user_id=user_id))

        password_hash = generate_password_hash(password)

        update_user_password(user_id, password_hash)

        # Reset failed login counter and lockout
        reset_failed_login(user["username"])

        flash(f"Password reset successfully for {user['username']}.", "success")
        return redirect("/admin/users")

    return render_template("admin_reset_password.html", user=user, page_title="Reset Password")


@app.route("/")
def home():
    return render_template("index.html", page_title="Home")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not login_required():
        flash("Please login to upload log files.", "warning")
        return redirect("/login")

    if request.method == "POST":
        if "logfile" not in request.files:
            flash("No file selected.", "danger")
            return redirect(request.url)

        file = request.files["logfile"]

        if file.filename == "":
            flash("Please choose a file.", "danger")
            return redirect(request.url)

        if allowed_file(file.filename, app.config["ALLOWED_EXTENSIONS"]):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            try:
                events = parse_xml_log(filepath)
            except ValueError as error:
                flash(str(error), "danger")
                return redirect("/upload")

            if not events:
                flash("No events were found in the uploaded file.", "warning")
                return redirect("/upload")

            clear_events()
            insert_events(events)

            flash(
                f"Successfully analyzed {len(events)} security events from '{filename}'.",
                "success",
            )
            return redirect("/dashboard")

        flash("Only .xml files are allowed.", "danger")

    return render_template("upload.html", page_title="Log Analyzer")


@app.route("/register", methods=["GET", "POST"])
def register():
    if login_required():
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Username validation
        if not username:
            flash("Username is required.", "danger")
            return redirect("/register")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "danger")
            return redirect("/register")

        # Password validation
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return redirect("/register")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect("/register")

        # Check duplicate username
        if username_exists(username):
            flash("Username already exists.", "danger")
            return redirect("/register")

        # Hash password
        password_hash = generate_password_hash(password)

        # Create normal user account
        create_user(username, password_hash, "user")

        flash("Account created successfully! Please login.", "success")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if login_required():
        return redirect("/dashboard")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)

        # Do not reveal whether a username exists.
        if not user:
            flash("Invalid username or password.", "danger")
            return render_template("login.html")

        # Check whether the account has been disabled.
        if not user["is_active"]:
            flash("This account has been disabled.", "danger")
            return render_template("login.html")

        # Check account lockout.
        if is_account_locked(username):
            flash(
                "Too many failed login attempts. Your account is temporarily locked. "
                "Please try again later.",
                "danger",
            )
            return render_template("login.html")

        # Check password.
        if check_password_hash(user["password_hash"], password):
            # Successful login.
            reset_failed_login(username)

            # Refresh user information.
            user = get_user(username)

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]

            flash("Login successful!", "success")
            return redirect("/dashboard")

        # Incorrect password.
        record_failed_login(username)

        # Get updated account information.
        user = get_user(username)

        if user["failed_login_attempts"] >= 5:
            flash(
                "Too many failed login attempts. Your account has been locked for 15 minutes.",
                "danger",
            )
        else:
            remaining = 5 - user["failed_login_attempts"]
            flash(
                f"Invalid username or password. {remaining} attempt(s) remaining.",
                "danger",
            )

    return render_template("login.html")


@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect("/login")


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not login_required():
        flash("Please login to change your password.", "warning")
        return redirect("/login")

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user = get_user(session["username"])

        # Verify current password
        if not user or not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
            return redirect("/change-password")

        # Password length
        if len(new_password) < 8:
            flash("New password must be at least 8 characters.", "danger")
            return redirect("/change-password")

        # Confirm password
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return redirect("/change-password")

        # Prevent using the same password
        if check_password_hash(user["password_hash"], new_password):
            flash("New password must be different from your current password.", "danger")
            return redirect("/change-password")

        # Hash new password
        password_hash = generate_password_hash(new_password)

        update_user_password(user["id"], password_hash)

        flash("Password changed successfully. Please login again.", "success")

        session.clear()
        return redirect("/login")

    return render_template("change_password.html")


@app.route("/dashboard")
def dashboard():
    if not login_required():
        flash("Please login to access the dashboard.", "warning")
        return redirect("/login")

    event_id = request.args.get("event_id", "").strip()
    level = request.args.get("level", "").strip()
    provider = request.args.get("provider", "").strip()
    start_time = request.args.get("start_time", "").strip()
    end_time = request.args.get("end_time", "").strip()

    # Combined filtering — all provided filters are AND-ed together.
    if any([event_id, level, provider, start_time, end_time]):
        events = search_events(
            event_id=event_id or None,
            level=level or None,
            provider=provider or None,
            start_time=start_time or None,
            end_time=end_time or None,
        )
    else:
        events = get_all_events()

    threats = detect_threats(events)

    critical_count = sum(1 for threat in threats if threat["severity"] == "Critical")
    high_count = sum(1 for threat in threats if threat["severity"] == "High")
    medium_count = sum(1 for threat in threats if threat["severity"] == "Medium")
    low_count = sum(1 for threat in threats if threat["severity"] == "Low")

    total_events = len(events)
    total_threats = len(threats)
    high_critical = sum(1 for threat in threats if threat["severity"] in ["High", "Critical"])
    unique_event_ids = len(set(event["event_id"] for event in events))

    # Active filter summary for the UI
    active_filters = []
    if event_id:
        active_filters.append(("Event ID", event_id))
    if level:
        active_filters.append(("Level", level))
    if provider:
        active_filters.append(("Provider", provider))
    if start_time:
        active_filters.append(("From", start_time))
    if end_time:
        active_filters.append(("To", end_time))

    return render_template(
        "dashboard.html",
        events=events[:200],
        total_events=total_events,
        threats=threats,
        total_threats=total_threats,
        high_critical=high_critical,
        unique_event_ids=unique_event_ids,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        active_filters=active_filters,
        page_title="Security Overview",
        breadcrumb="Dashboard",
    )


@app.route("/reports", methods=["GET", "POST"])
def reports():
    if not login_required():
        flash("Please login to access reports.", "warning")
        return redirect("/login")

    if request.method == "POST":
        events = get_all_events()

        if not events:
            flash("No events available to generate a report. Upload a log file first.", "warning")
            return redirect("/reports")

        threats = detect_threats(events)

        report_path = os.path.join(
            app.config["REPORT_FOLDER"],
            "security_report.pdf",
        )

        try:
            generate_pdf(events, threats, report_path)
        except Exception:
            flash("Failed to generate the report. Please try again.", "danger")
            return redirect("/reports")

        flash("Report generated successfully.", "success")
        return send_file(
            report_path,
            as_attachment=True,
            download_name="Secure_Log_Analyzer_Report.pdf",
        )

    # Show report overview with current data counts
    events = get_all_events()
    threats = detect_threats(events) if events else []

    return render_template(
        "reports.html",
        total_events=len(events),
        total_threats=len(threats),
        critical_count=sum(1 for t in threats if t["severity"] == "Critical"),
        high_count=sum(1 for t in threats if t["severity"] == "High"),
        medium_count=sum(1 for t in threats if t["severity"] == "Medium"),
        low_count=sum(1 for t in threats if t["severity"] == "Low"),
        page_title="Reports",
    )


@app.route("/account")
def account():
    if not login_required():
        flash("Please login to view your account.", "warning")
        return redirect("/login")

    user = get_user(session["username"])

    if not user:
        session.clear()
        flash("Account not found. Please login again.", "danger")
        return redirect("/login")

    return render_template("account.html", user=user, page_title="My Account")


@app.route("/about")
def about():
    return render_template("about.html", page_title="About")


if __name__ == "__main__":
    # Debug mode is controlled via environment; defaults to off in production.
    debug_enabled = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_enabled)