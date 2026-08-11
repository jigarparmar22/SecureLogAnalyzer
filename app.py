import os
from report.pdf_report import generate_pdf
from flask import Flask, render_template, request, redirect, flash, send_file, session
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from config import Config
from utils.helpers import allowed_file
from parser.log_parser import parse_xml_log
from analyzer.threat_detector import detect_threats
from database.database import (
    create_database,
    insert_events,
    clear_events,
    get_all_events,
    search_by_event_id,
    search_by_level,
    search_by_provider,
    get_user,
    search_by_datetime
)

app = Flask(__name__)
app.config.from_object(Config)

# Required for flash() messages
app.secret_key = app.config["SECRET_KEY"]

# Create uploads folder if it doesn't exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
create_database()
def login_required():

    if "user_id" not in session:
        return False

    return True

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():

    if not login_required():
         flash("Please login to upload log files.")
         return redirect("/login")

    if request.method == "POST":

        if "logfile" not in request.files:
            flash("No file selected.")
            return redirect(request.url)

        file = request.files["logfile"]

        if file.filename == "":
            flash("Please choose a file.")
            return redirect(request.url)

        if allowed_file(file.filename, app.config["ALLOWED_EXTENSIONS"]):

            filename = secure_filename(file.filename)

            filepath = os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )

            file.save(filepath)

            events = parse_xml_log(filepath)
            clear_events()
            insert_events(events)
            events = get_all_events()

            # Dashboard Statistics
            total_events = len(events)

            information_count = sum(
                1 for event in events
                if event["level"] == "Information"
            )

            warning_count = sum(
                1 for event in events
                if event["level"] == "Warning"
            )

            error_count = sum(
                1 for event in events
                if event["level"] in ["Error", "Critical", "Failure Audit"]
            )

            return redirect("/dashboard")

        flash("Only .xml files are allowed.")

    return render_template("upload.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        user = get_user(username)

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful!")

            return redirect("/dashboard")

        flash("Invalid username or password.")

    return render_template("login.html")

@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect("/login")

@app.route("/dashboard")
def dashboard():

    if not login_required():
        flash("Please login to access the dashboard.")
        return redirect("/login")

    event_id = request.args.get("event_id")
    level = request.args.get("level")
    provider = request.args.get("provider")
    start_time = request.args.get("start_time")
    end_time = request.args.get("end_time")

    if event_id:
        events = search_by_event_id(event_id)

    elif level:
        events = search_by_level(level)
    
    elif provider:
        events = search_by_provider(provider)
    
    elif start_time and end_time:
        events = search_by_datetime(
            start_time,
            end_time
        )
    
    else:
        events = get_all_events()
    
    threats = detect_threats(events)

    critical_count = sum(
        1 for threat in threats
        if threat["severity"] == "Critical"
    )

    high_count = sum(
        1 for threat in threats
        if threat["severity"] == "High"
    )

    medium_count = sum(
        1 for threat in threats
        if threat["severity"] == "Medium"
    )

    low_count = sum(
        1 for threat in threats
        if threat["severity"] == "Low"
    )

    total_events = len(events)

    total_threats = len(threats)

    high_critical = sum(
        1 for threat in threats
        if threat["severity"] in ["High", "Critical"]
    )

    unique_event_ids = len(
        set(event["event_id"] for event in events)
    )

    return render_template(
        "dashboard.html",
        events=events[:200],
        threats=threats,
        total_events=total_events,
        total_threats=total_threats,
        high_critical=high_critical,
        unique_event_ids=unique_event_ids,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )

@app.route("/reports")
def reports():

    if not login_required():
        flash("Please login to access reports.")
        return redirect("/login")

    return render_template("reports.html")
    events = get_all_events()

    threats = detect_threats(events)

    report_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        "security_report.pdf"
    )

    generate_pdf(
        events,
        threats,
        report_path
    )

    return send_file(
        report_path,
        as_attachment=True,
        download_name="Secure_Log_Analyzer_Report.pdf"
    )


@app.route("/about")
def about():
    return render_template("about.html")


if __name__ == "__main__":
    app.run(debug=True)