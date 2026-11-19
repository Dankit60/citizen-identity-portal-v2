"""
Fingerprint-Based Biometric Authentication System for Securing
Citizen Digital Identity Portals  (prototype)

Run with:   python app.py
Open:       http://127.0.0.1:5000
"""
import io
import os
import secrets
import sqlite3
import smtplib
import hashlib
from email.message import EmailMessage
from datetime import timedelta
from functools import wraps
from pathlib import Path

import cv2
import numpy as np
from cryptography.fernet import Fernet
from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

# ----------------------------------------------------------------------
# Settings (you can explain these in your presentation)
# ----------------------------------------------------------------------
BASE = Path(__file__).resolve().parent
# On Render, set PORTAL_DATA_DIR=/var/data and attach a persistent disk there.
# For local use, data remains alongside the application as before.
DATA_DIR = Path(os.environ.get("PORTAL_DATA_DIR", str(BASE)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB = DATA_DIR / "portal.db"
KEY_FILE = DATA_DIR / "template.key"          # encryption key for fingerprint templates
SECRET_FILE = DATA_DIR / "flask_secret.key"   # key that signs the login session cookie

MATCH_THRESHOLD = 15.0   # % of fingerprint features that must match to accept
MIN_FEATURES = 20        # fewer features than this = poor image / not a fingerprint
MAX_FAILS = 3            # consecutive failed logins before the account is locked
ADMIN_USER = "admin"
ADMIN_DEFAULT_PASSWORD = "Admin@123"   # change this before real use


def load_key(path, maker):
    if not path.exists():
        path.write_bytes(maker())
    return path.read_bytes()


fernet = Fernet(load_key(KEY_FILE, Fernet.generate_key))   # AES-based encryption

app = Flask(__name__)
# Image upload is hidden from normal users. Set PORTAL_DEMO_UPLOAD=1 to show it for demos and testing.
app.jinja_env.globals["DEMO_UPLOAD"] = os.environ.get("PORTAL_DEMO_UPLOAD") == "1"
app.secret_key = load_key(SECRET_FILE, lambda: secrets.token_hex(32).encode()).decode()
app.permanent_session_lifetime = timedelta(minutes=30)      # session expiry
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024


# ----------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        national_id TEXT UNIQUE NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'citizen',
        status TEXT NOT NULL DEFAULT 'pending',
        failed_count INTEGER NOT NULL DEFAULT 0,
        password_hash TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS fingerprint_templates (
        template_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        finger_index TEXT NOT NULL DEFAULT 'right index',
        encrypted_template BLOB NOT NULL,
        quality_score INTEGER NOT NULL,
        enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS face_templates (
        face_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE REFERENCES users(user_id),
        encrypted_template BLOB NOT NULL,
        enrolled_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS otp_challenges (
        challenge_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS citizen_records (
        record_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        record_type TEXT NOT NULL,
        details TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS login_attempts (
        attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER REFERENCES users(user_id),
        identifier_used TEXT,
        ip_address TEXT,
        match_score REAL,
        result TEXT NOT NULL,
        attempt_time TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);

    CREATE TABLE IF NOT EXISTS anomaly_alerts (
        alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
        attempt_id INTEGER REFERENCES login_attempts(attempt_id),
        user_id INTEGER REFERENCES users(user_id),
        reviewed_by INTEGER REFERENCES users(user_id),
        rule_triggered TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT);

    CREATE TABLE IF NOT EXISTS audit_logs (
        log_id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER REFERENCES users(user_id),
        action TEXT NOT NULL,
        target TEXT,
        ip_address TEXT,
        logged_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    """)
    admin = conn.execute("SELECT 1 FROM users WHERE national_id=?", (ADMIN_USER,)).fetchone()
    if not admin:
        conn.execute(
            "INSERT INTO users (national_id, full_name, email, phone, role, status, password_hash) "
            "VALUES (?, 'System Administrator', 'admin@portal.local', '0000000000', 'admin', 'active', ?)",
            (ADMIN_USER, generate_password_hash(ADMIN_DEFAULT_PASSWORD)))
    conn.commit()
    conn.close()


def backup_old_database():
    """If an old test database (from the first registration page) exists, set it aside."""
    if not DB.exists():
        return
    conn = sqlite3.connect(DB)
    try:
        conn.execute("SELECT failed_count FROM users LIMIT 1")
        old = False
    except sqlite3.OperationalError as err:
        old = "no such column" in str(err)
    finally:
        conn.close()
    if old:
        DB.replace(BASE / "portal_old_backup.db")


backup_old_database()
init_db()


def audit(conn, actor_id, action, target=None):
    conn.execute("INSERT INTO audit_logs (actor_id, action, target, ip_address) VALUES (?,?,?,?)",
                 (actor_id, action, target, request.remote_addr))


def log_attempt(conn, user_id, identifier, score, result):
    cur = conn.execute(
        "INSERT INTO login_attempts (user_id, identifier_used, ip_address, match_score, result) "
        "VALUES (?,?,?,?,?)", (user_id, identifier, request.remote_addr, score, result))
    return cur.lastrowid


# ----------------------------------------------------------------------
# Fingerprint processing
# ----------------------------------------------------------------------
def extract_features(image_bytes):
    """Turn a fingerprint image into feature vectors (SIFT). Returns (features, count)."""
    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None, 0
    img = cv2.resize(img, (300, 300))
    img = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(img)
    sift = cv2.SIFT_create(nfeatures=500)
    keypoints, descriptors = sift.detectAndCompute(img, None)
    if descriptors is None:
        return None, 0
    return descriptors.astype(np.float32), len(keypoints)


def protect_template(feature_list):
    """Encrypt the features (AES via Fernet). The raw image is never stored."""
    buf = io.BytesIO()
    np.savez(buf, *feature_list)
    return fernet.encrypt(buf.getvalue())


def open_template(blob):
    data = np.load(io.BytesIO(fernet.decrypt(blob)), allow_pickle=False)
    return [data[name] for name in data.files]


def match_percent(probe, template):
    """Percentage of probe features that have a good match in the stored template."""
    matcher = cv2.BFMatcher(cv2.NORM_L2)
    pairs = matcher.knnMatch(probe, template, k=2)
    good = sum(1 for p in pairs if len(p) == 2 and p[0].distance < 0.75 * p[1].distance)
    return 100.0 * good / len(probe)


def extract_face_features(image_bytes):
    """Detect a frontal face and extract ORB descriptors from its crop.

    This is a lightweight classroom prototype, not a production face matcher.
    """
    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
    detector = cv2.CascadeClassifier(cascade_path)
    faces = detector.detectMultiScale(img, scaleFactor=1.1, minNeighbors=5, minSize=(70, 70))
    if len(faces) == 0:
        return None
    x, y, width, height = max(faces, key=lambda box: box[2] * box[3])
    face = img[y:y + height, x:x + width]
    face = cv2.resize(face, (300, 300))
    orb = cv2.ORB_create(nfeatures=700)
    _keypoints, descriptors = orb.detectAndCompute(face, None)
    return descriptors


def face_match_percent(probe, enrolled):
    if probe is None or enrolled is None or len(probe) < 10 or len(enrolled) < 10:
        return 0.0
    matcher = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = matcher.match(probe, enrolled)
    if not matches:
        return 0.0
    good = sum(1 for item in matches if item.distance < 55)
    return 100.0 * good / max(1, min(len(probe), len(enrolled)))


def send_otp_email(destination, code):
    """Send OTP using SMTP environment settings; console mode is for local demos only."""
    host = os.getenv("SMTP_HOST")
    if not host:
        print(f"[DEMO ONLY] OTP for {destination}: {code}")
        return False
    msg = EmailMessage()
    msg["Subject"] = "Citizen Portal Login Verification Code"
    msg["From"] = os.getenv("SMTP_FROM", os.getenv("SMTP_USER", "no-reply@portal.local"))
    msg["To"] = destination
    msg.set_content(f"Your one-time login code is {code}. It expires in five minutes. Do not share it.")
    with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
        server.starttls()
        user = os.getenv("SMTP_USER")
        password = os.getenv("SMTP_PASSWORD")
        if user and password:
            server.login(user, password)
        server.send_message(msg)
    return True


def start_citizen_session(user, method):
    session.clear()
    session.permanent = True
    session["user_id"] = user["user_id"]
    session["role"] = "citizen"
    session["name"] = user["full_name"]
    session["auth_method"] = method


# ----------------------------------------------------------------------
# Login-anomaly monitoring
# ----------------------------------------------------------------------
def create_alert(conn, attempt_id, user_id, rule, severity):
    conn.execute("INSERT INTO anomaly_alerts (attempt_id, user_id, rule_triggered, severity) "
                 "VALUES (?,?,?,?)", (attempt_id, user_id, rule, severity))


def recent_alert_exists(conn, rule):
    row = conn.execute("SELECT 1 FROM anomaly_alerts WHERE rule_triggered=? AND status='open' "
                       "AND created_at >= datetime('now','-10 minutes')", (rule,)).fetchone()
    return row is not None


def run_ip_rules(conn, attempt_id, user_id):
    ip = request.remote_addr
    failed = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address=? AND result LIKE 'failed%' "
        "AND attempt_time >= datetime('now','-10 minutes')", (ip,)).fetchone()[0]
    if failed >= 5:
        rule = f"5 or more failed attempts from IP {ip} in 10 minutes"
        if not recent_alert_exists(conn, rule):
            create_alert(conn, attempt_id, user_id, rule, "High")
    unknown = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip_address=? AND user_id IS NULL "
        "AND result LIKE 'failed%' AND attempt_time >= datetime('now','-10 minutes')", (ip,)).fetchone()[0]
    if unknown >= 3:
        rule = f"Repeated attempts on non-existent accounts from IP {ip}"
        if not recent_alert_exists(conn, rule):
            create_alert(conn, attempt_id, user_id, rule, "Medium")


def handle_failure(conn, user, score, reason):
    """Record a failed login for a real account, lock it after MAX_FAILS."""
    attempt_id = log_attempt(conn, user["user_id"], user["national_id"], score, "failed: " + reason)
    fails = user["failed_count"] + 1
    conn.execute("UPDATE users SET failed_count=? WHERE user_id=?", (fails, user["user_id"]))
    left = MAX_FAILS - fails
    if fails >= MAX_FAILS:
        conn.execute("UPDATE users SET status='locked' WHERE user_id=?", (user["user_id"],))
        create_alert(conn, attempt_id, user["user_id"],
                     f"{MAX_FAILS} failed fingerprint attempts in a row - account locked", "High")
        audit(conn, user["user_id"], "Account locked after failed attempts", user["national_id"])
        flash("Fingerprint not matched. Your account is now locked. Contact the administrator.", "err")
    else:
        flash(f"Fingerprint not matched. Attempts left: {left}.", "err")
    run_ip_rules(conn, attempt_id, user["user_id"])


# ----------------------------------------------------------------------
# Access control
# ----------------------------------------------------------------------
def login_required(role):
    def wrapper(view):
        @wraps(view)
        def inner(*args, **kwargs):
            if session.get("user_id") is None or session.get("role") != role:
                flash("Please log in first.", "err")
                return redirect(url_for("login" if role == "citizen" else "admin_login"))
            return view(*args, **kwargs)
        return inner
    return wrapper


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403,
                           message="Access denied. You can only view your own records."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, message="File too large (max 8 MB)."), 413


# ----------------------------------------------------------------------
# Citizen pages
# ----------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """One-page sign-up: personal details + fingerprint scan(s) + optional face image.

    Everything is validated BEFORE the account is created, so a bad fingerprint
    image never leaves a half-finished ("pending") account behind.
    """
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        national_id = request.form.get("national_id", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        finger_files = [f for f in request.files.getlist("fingerprint") if f and f.filename][:3]
        face_file = request.files.get("face_image")
        has_face = bool(face_file and face_file.filename)

        if not (full_name and national_id and email and phone):
            flash("Please fill in all the details.", "err")
        elif not national_id.isdigit() or not 7 <= len(national_id) <= 8:
            flash("National ID must be 7 or 8 digits.", "err")
        elif "@" not in email:
            flash("Enter a valid email address.", "err")
        elif not phone.isdigit() or not 9 <= len(phone) <= 12:
            flash("Phone number must be 9 to 12 digits.", "err")
        elif not finger_files:
            flash("Upload at least one fingerprint scan (up to 3) to finish signing up.", "err")
        else:
            # --- process the biometrics first ---------------------------------
            feature_list, counts, problem = [], [], None
            for f in finger_files:
                des, n = extract_features(f.read())
                if des is None or n < MIN_FEATURES:
                    problem = f"'{f.filename}' is not a clear fingerprint image. Try another image."
                    break
                feature_list.append(des)
                counts.append(n)
            face_des = None
            if not problem and has_face:
                face_des = extract_face_features(face_file.read())
                if face_des is None or len(face_des) < 10:
                    problem = ("The face image is unclear. Use a well-lit, front-facing photo, "
                               "or leave the face box empty and add it later.")
            if problem:
                flash(problem, "err")
                return render_template("register.html")

            # --- everything is valid: create the account in one go ------------
            conn = get_db()
            try:
                cur = conn.execute(
                    "INSERT INTO users (national_id, full_name, email, phone, status) VALUES (?,?,?,?, 'active')",
                    (national_id, full_name, email, phone))
                uid = cur.lastrowid
                conn.executemany(
                    "INSERT INTO citizen_records (user_id, record_type, details) VALUES (?,?,?)",
                    [(uid, "Digital ID", "Active"),
                     (uid, "Contact details", f"{phone}, {email}"),
                     (uid, "Address record", "Not yet provided")])
                quality = int(sum(counts) / len(counts))
                conn.execute(
                    "INSERT INTO fingerprint_templates (user_id, encrypted_template, quality_score) VALUES (?,?,?)",
                    (uid, protect_template(feature_list), quality))
                audit(conn, uid, "Account registered", national_id)
                audit(conn, uid, "Fingerprint enrolled", national_id)
                if face_des is not None:
                    payload = io.BytesIO()
                    np.save(payload, face_des)
                    conn.execute("INSERT INTO face_templates (user_id, encrypted_template) VALUES (?,?)",
                                 (uid, fernet.encrypt(payload.getvalue())))
                    audit(conn, uid, "Face template enrolled", national_id)
                conn.commit()
                flash("Sign-up complete. Your fingerprint"
                      + (" and face image are" if face_des is not None else " is")
                      + " saved. You can now log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                conn.rollback()
                flash("That national ID is already registered.", "err")
            finally:
                conn.close()
    return render_template("register.html")


@app.route("/enrol", methods=["GET", "POST"])
def enrol():
    prefill = session.get("enrol_id", "")
    if request.method == "POST":
        national_id = request.form.get("national_id", "").strip()
        files = [f for f in request.files.getlist("fingerprint") if f and f.filename][:3]
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='citizen'",
                                (national_id,)).fetchone()
            if user is None:
                flash("No account found for that national ID. Register first.", "err")
            elif user["status"] != "pending":
                flash("This account is already enrolled. Please log in.", "err")
            elif not files:
                flash("Choose 1 to 3 fingerprint images.", "err")
            else:
                feature_list, counts = [], []
                for f in files:
                    des, n = extract_features(f.read())
                    if des is None or n < MIN_FEATURES:
                        flash(f"'{f.filename}' is not a clear fingerprint image. Try another image.", "err")
                        feature_list = []
                        break
                    feature_list.append(des)
                    counts.append(n)
                if feature_list:
                    quality = int(sum(counts) / len(counts))
                    conn.execute(
                        "INSERT INTO fingerprint_templates (user_id, encrypted_template, quality_score) "
                        "VALUES (?,?,?)", (user["user_id"], protect_template(feature_list), quality))
                    conn.execute("UPDATE users SET status='active' WHERE user_id=?", (user["user_id"],))
                    audit(conn, user["user_id"], "Fingerprint enrolled", national_id)
                    conn.commit()
                    session.pop("enrol_id", None)
                    flash(f"Fingerprint enrolled successfully ({len(files)} scan(s), quality {quality}). "
                          "You can now log in.", "ok")
                    return redirect(url_for("login"))
        finally:
            conn.close()
    return render_template("enrol.html", prefill=prefill)


@app.route("/face/enrol", methods=["GET", "POST"])
def face_enrol():
    if request.method == "POST":
        national_id = request.form.get("national_id", "").strip()
        photo = request.files.get("face_image")
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='citizen'", (national_id,)).fetchone()
            if not user or user["status"] != "active":
                flash("Complete citizen registration and fingerprint enrolment first.", "err")
            elif not photo or not photo.filename:
                flash("Choose a clear face image.", "err")
            else:
                descriptors = extract_face_features(photo.read())
                if descriptors is None or len(descriptors) < 10:
                    flash("The face image is unclear. Use a well-lit, front-facing image.", "err")
                else:
                    payload = io.BytesIO()
                    np.save(payload, descriptors)
                    encrypted = fernet.encrypt(payload.getvalue())
                    conn.execute("INSERT INTO face_templates (user_id, encrypted_template) VALUES (?,?) "
                                 "ON CONFLICT(user_id) DO UPDATE SET encrypted_template=excluded.encrypted_template",
                                 (user["user_id"], encrypted))
                    audit(conn, user["user_id"], "Face template enrolled", national_id)
                    conn.commit()
                    flash("Face image enrolled. You can now use face recognition as an alternative login method.", "ok")
                    return redirect(url_for("login"))
        finally:
            conn.close()
    return render_template("face_enrol.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method != "POST":
        return render_template("login.html", selected_method="fingerprint")

    method = request.form.get("method", "fingerprint")
    national_id = request.form.get("national_id", "").strip()

    if method == "otp":
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='citizen'", (national_id,)).fetchone()
            if not user or user["status"] != "active":
                flash("No active citizen account was found for that ID.", "err")
            elif request.form.get("action") == "send_otp":
                code = f"{secrets.randbelow(1000000):06d}"
                conn.execute("DELETE FROM otp_challenges WHERE user_id=?", (user["user_id"],))
                conn.execute("INSERT INTO otp_challenges (user_id, code_hash, expires_at) VALUES (?,?,?)",
                             (user["user_id"], hashlib.sha256(code.encode()).hexdigest(),
                              int(__import__('time').time()) + 300))
                conn.commit()
                try:
                    sent = send_otp_email(user["email"], code)
                    flash("Verification code sent to your registered email." if sent else
                          "Demo mode: the code was printed in the terminal running app.py. It expires in five minutes.", "ok")
                except Exception:
                    conn.execute("DELETE FROM otp_challenges WHERE user_id=?", (user["user_id"],))
                    conn.commit()
                    flash("Could not send the email code. Check SMTP settings and try again.", "err")
            else:
                code = request.form.get("otp_code", "").strip()
                challenge = conn.execute("SELECT * FROM otp_challenges WHERE user_id=? ORDER BY challenge_id DESC LIMIT 1",
                                         (user["user_id"],)).fetchone()
                if (challenge and int(__import__('time').time()) <= challenge["expires_at"] and
                    secrets.compare_digest(hashlib.sha256(code.encode()).hexdigest(), challenge["code_hash"])):
                    conn.execute("DELETE FROM otp_challenges WHERE user_id=?", (user["user_id"],))
                    log_attempt(conn, user["user_id"], national_id, None, "success")
                    audit(conn, user["user_id"], "OTP login success", national_id)
                    conn.commit()
                    start_citizen_session(user, "OTP")
                    return redirect(url_for("dashboard"))
                handle_failure(conn, user, None, "invalid or expired OTP")
                audit(conn, user["user_id"], "OTP verification failed", national_id)
                conn.commit()
                flash("The code is incorrect or has expired. Request a new code.", "err")
        finally:
            conn.close()
        return render_template("login.html", selected_method="otp")

    if method == "face":
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='citizen'", (national_id,)).fetchone()
            photo = request.files.get("face_image")
            if not user or user["status"] != "active":
                flash("No active citizen account was found for that ID.", "err")
            elif not photo or not photo.filename:
                flash("Choose a face image to verify.", "err")
            else:
                probe = extract_face_features(photo.read())
                saved = conn.execute("SELECT encrypted_template FROM face_templates WHERE user_id=?", (user["user_id"],)).fetchone()
                if probe is None or len(probe) < 10 or not saved:
                    flash("Face verification is unavailable. Enrol a face image or use another method.", "err")
                else:
                    enrolled = np.load(io.BytesIO(fernet.decrypt(saved["encrypted_template"])), allow_pickle=False)
                    score = face_match_percent(probe, enrolled)
                    if score >= 8.0:
                        log_attempt(conn, user["user_id"], national_id, round(score, 1), "success")
                        audit(conn, user["user_id"], "Face login success", national_id)
                        conn.commit()
                        start_citizen_session(user, "Face")
                        return redirect(url_for("dashboard"))
                    handle_failure(conn, user, round(score, 1), "face mismatch")
                    audit(conn, user["user_id"], "Face login failed", national_id)
                    conn.commit()
                    flash("Face did not match the enrolled image. Try again or use another method.", "err")
        finally:
            conn.close()
        return render_template("login.html", selected_method="face")

    # Original fingerprint authentication flow (kept as the primary method).
    f = request.files.get("fingerprint")
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='citizen'", (national_id,)).fetchone()
        if user is None:
            attempt_id = log_attempt(conn, None, national_id, None, "failed: unknown account")
            run_ip_rules(conn, attempt_id, None)
            conn.commit()
            flash("Login failed. Check your details and try again.", "err")
            return render_template("login.html", selected_method="fingerprint")
        if user["status"] == "locked":
            log_attempt(conn, user["user_id"], national_id, None, "blocked: account locked")
            conn.commit()
            flash("This account is locked. Contact the administrator.", "err")
            return render_template("login.html", selected_method="fingerprint")
        if user["status"] == "pending":
            flash("Finish fingerprint enrolment first.", "err")
            session["enrol_id"] = national_id
            return redirect(url_for("enrol"))
        if not f or not f.filename:
            flash("Choose a fingerprint image to scan.", "err")
            return render_template("login.html", selected_method="fingerprint")

        des, n = extract_features(f.read())
        if des is None or n < MIN_FEATURES:
            handle_failure(conn, user, None, "poor image quality")
            conn.commit()
            return render_template("login.html", selected_method="fingerprint")

        blob = conn.execute("SELECT encrypted_template FROM fingerprint_templates WHERE user_id=? ORDER BY template_id DESC LIMIT 1", (user["user_id"],)).fetchone()
        if not blob:
            flash("No fingerprint template is enrolled. Use another method or complete enrolment.", "err")
            return render_template("login.html", selected_method="fingerprint")
        templates = open_template(blob["encrypted_template"])
        score = max(match_percent(des, t) for t in templates)
        if score < MATCH_THRESHOLD:
            handle_failure(conn, user, round(score, 1), "no match")
            conn.commit()
            return render_template("login.html", selected_method="fingerprint")

        ip = request.remote_addr
        known_ips = [r[0] for r in conn.execute("SELECT DISTINCT ip_address FROM login_attempts WHERE user_id=? AND result='success'", (user["user_id"],))]
        attempt_id = log_attempt(conn, user["user_id"], national_id, round(score, 1), "success")
        if known_ips and ip not in known_ips:
            create_alert(conn, attempt_id, user["user_id"], f"Successful login from a new IP address ({ip})", "Low")
        conn.execute("UPDATE users SET failed_count=0 WHERE user_id=?", (user["user_id"],))
        audit(conn, user["user_id"], "Login success", national_id)
        conn.commit()
        start_citizen_session(user, "Fingerprint")
        return redirect(url_for("dashboard"))
    finally:
        conn.close()


@app.route("/dashboard")
@login_required("citizen")
def dashboard():
    conn = get_db()
    uid = session["user_id"]
    user = conn.execute("SELECT * FROM users WHERE user_id=?", (uid,)).fetchone()
    # ACCESS CONTROL: only this user's own records are fetched
    records = conn.execute(
        "SELECT record_id, record_type, details, datetime(updated_at,'+3 hours') AS updated "
        "FROM citizen_records WHERE user_id=? ORDER BY record_id", (uid,)).fetchall()
    last = conn.execute(
        "SELECT datetime(attempt_time,'+3 hours') AS t, ip_address FROM login_attempts "
        "WHERE user_id=? AND result='success' ORDER BY attempt_id DESC LIMIT 1 OFFSET 1",
        (uid,)).fetchone()
    conn.close()
    return render_template("dashboard.html", user=user, records=records, last=last)


@app.route("/record/<int:record_id>")
@login_required("citizen")
def record(record_id):
    conn = get_db()
    rec = conn.execute("SELECT * FROM citizen_records WHERE record_id=?", (record_id,)).fetchone()
    if rec is None:
        conn.close()
        abort(404)
    # ACCESS CONTROL: the logged-in user must own the record
    if rec["user_id"] != session["user_id"]:
        audit(conn, session["user_id"], "Blocked attempt to open another user's record",
              f"record {record_id}")
        conn.commit()
        conn.close()
        abort(403)
    conn.close()
    return render_template("record.html", rec=rec)


@app.route("/logout")
def logout():
    if session.get("user_id"):
        conn = get_db()
        audit(conn, session["user_id"], "Logout")
        conn.commit()
        conn.close()
    session.clear()
    flash("You have been logged out.", "ok")
    return redirect(url_for("home"))


# ----------------------------------------------------------------------
# Administrator pages
# ----------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        try:
            user = conn.execute("SELECT * FROM users WHERE national_id=? AND role='admin'",
                                (username,)).fetchone()
            if user and check_password_hash(user["password_hash"], password):
                log_attempt(conn, user["user_id"], username, None, "success")
                audit(conn, user["user_id"], "Admin login success", username)
                conn.commit()
                session.clear()
                session.permanent = True
                session["user_id"] = user["user_id"]
                session["role"] = "admin"
                session["name"] = user["full_name"]
                return redirect(url_for("admin_dashboard"))
            attempt_id = log_attempt(conn, user["user_id"] if user else None, username, None,
                                     "failed: admin password")
            run_ip_rules(conn, attempt_id, user["user_id"] if user else None)
            conn.commit()
            flash("Wrong username or password.", "err")
        finally:
            conn.close()
    return render_template("admin_login.html")


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    conn = get_db()
    stats = {
        "users": conn.execute("SELECT COUNT(*) FROM users WHERE role='citizen'").fetchone()[0],
        "logins": conn.execute("SELECT COUNT(*) FROM login_attempts WHERE result='success' "
                               "AND date(attempt_time,'+3 hours')=date('now','+3 hours')").fetchone()[0],
        "failed": conn.execute("SELECT COUNT(*) FROM login_attempts WHERE result LIKE 'failed%' "
                               "AND date(attempt_time,'+3 hours')=date('now','+3 hours')").fetchone()[0],
        "alerts": conn.execute("SELECT COUNT(*) FROM anomaly_alerts WHERE status='open'").fetchone()[0],
    }
    recent = conn.execute(
        "SELECT datetime(a.attempt_time,'+3 hours') AS t, COALESCE(u.full_name, a.identifier_used) AS who, "
        "a.ip_address, a.match_score, a.result FROM login_attempts a "
        "LEFT JOIN users u ON u.user_id=a.user_id ORDER BY a.attempt_id DESC LIMIT 10").fetchall()
    conn.close()
    return render_template("admin_dashboard.html", stats=stats, recent=recent)


@app.route("/admin/alerts")
@login_required("admin")
def admin_alerts():
    conn = get_db()
    alerts = conn.execute(
        "SELECT a.alert_id, datetime(a.created_at,'+3 hours') AS t, a.rule_triggered, a.severity, "
        "a.status, a.user_id, u.full_name, u.status AS user_status "
        "FROM anomaly_alerts a LEFT JOIN users u ON u.user_id=a.user_id "
        "ORDER BY a.alert_id DESC LIMIT 100").fetchall()
    conn.close()
    return render_template("admin_alerts.html", alerts=alerts)


@app.route("/admin/alerts/<int:alert_id>/<action>", methods=["POST"])
@login_required("admin")
def alert_action(alert_id, action):
    if action not in ("confirm", "dismiss", "unlock"):
        abort(404)
    conn = get_db()
    alert = conn.execute("SELECT * FROM anomaly_alerts WHERE alert_id=?", (alert_id,)).fetchone()
    if alert is None:
        conn.close()
        abort(404)
    if action == "unlock":
        if alert["user_id"]:
            conn.execute("UPDATE users SET status='active', failed_count=0 WHERE user_id=? "
                         "AND role='citizen' AND status='locked'", (alert["user_id"],))
        new_status = "reviewed"
        flash("Account unlocked and alert marked as reviewed.", "ok")
    else:
        new_status = "confirmed" if action == "confirm" else "dismissed"
        flash(f"Alert {new_status}.", "ok")
    conn.execute("UPDATE anomaly_alerts SET status=?, reviewed_by=?, reviewed_at=CURRENT_TIMESTAMP "
                 "WHERE alert_id=?", (new_status, session["user_id"], alert_id))
    audit(conn, session["user_id"], f"Alert {action}", f"alert {alert_id}")
    conn.commit()
    conn.close()
    return redirect(url_for("admin_alerts"))


@app.route("/admin/users")
@login_required("admin")
def admin_users():
    conn = get_db()
    users = conn.execute(
        "SELECT user_id, national_id, full_name, email, status, failed_count, "
        "datetime(created_at,'+3 hours') AS created FROM users WHERE role='citizen' "
        "ORDER BY user_id DESC").fetchall()
    conn.close()
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/<int:user_id>/unlock", methods=["POST"])
@login_required("admin")
def unlock_user(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET status='active', failed_count=0 WHERE user_id=? "
                 "AND role='citizen' AND status='locked'", (user_id,))
    audit(conn, session["user_id"], "Account unlocked", f"user {user_id}")
    conn.commit()
    conn.close()
    flash("Account unlocked.", "ok")
    return redirect(url_for("admin_users"))


@app.route("/admin/audit")
@login_required("admin")
def admin_audit():
    conn = get_db()
    logs = conn.execute(
        "SELECT datetime(l.logged_at,'+3 hours') AS t, COALESCE(u.full_name,'-') AS actor, "
        "l.action, COALESCE(l.target,'') AS target, l.ip_address FROM audit_logs l "
        "LEFT JOIN users u ON u.user_id=l.actor_id ORDER BY l.log_id DESC LIMIT 200").fetchall()
    conn.close()
    return render_template("admin_audit.html", logs=logs)


if __name__ == "__main__":
    app.run(debug=True)
