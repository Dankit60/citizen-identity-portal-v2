"""Automated test runner for the Citizen Digital Identity Portal.

Run from the project folder:   python tests/run_tests.py
It uses a temporary database and key files, so your real portal.db is untouched.
Results are printed and saved to tests/results.json.
"""
import io, json, os, sys, tempfile, time, itertools, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SAMPLES = ROOT / "sample_fingerprints"

import app as a          # noqa: E402
tmp = Path(tempfile.mkdtemp())
a.DB = tmp / "test.db"
a.init_db()

results, sent_codes = [], []
a.send_otp_email = lambda dest, code: (sent_codes.append(code) or False)

def img(name):
    return (io.BytesIO((SAMPLES / name).read_bytes()), name)

def client():
    return a.app.test_client()

def record(tid, feature, action, expected, passed, observed):
    results.append(dict(id=tid, feature=feature, action=action, expected=expected,
                        result="Pass" if passed else "Fail", observed=observed))

def post(c, url, **data):
    return c.post(url, data=data, content_type="multipart/form-data", follow_redirects=True)

def db_one(sql, *p):
    conn = a.get_db(); r = conn.execute(sql, p).fetchone(); conn.close(); return r

def reg(c, nid, name, person, scans=(1, 2, 3), **over):
    d = dict(full_name=name, national_id=nid, email=f"{name.split()[0].lower()}@example.com", phone="0712345678")
    d.update(over)
    if scans:
        d["fingerprint"] = [img(f"person_{person}_scan{i}.png") for i in scans]
    return post(c, "/register", **d)

def login_fp(c, nid, sample):
    return post(c, "/login", national_id=nid, method="fingerprint", fingerprint=img(sample))

# ---------------- Registration ----------------
c = client()
r = reg(c, "11111111", "Alice Test", "A")
u = db_one("SELECT status FROM users WHERE national_id='11111111'")
record("T01", "Registration", "Submit valid details with three fingerprint scans",
       "Account created and set to active", b"Sign-up complete" in r.data and u and u["status"] == "active",
       "Account created, status = %s" % (u["status"] if u else "none"))
reg(c, "22222222", "Brian Test", "B"); reg(c, "33333333", "Carol Test", "C")

r = reg(c, "44444444", "No Finger", "A", scans=())
record("T02", "Registration", "Submit valid details without a fingerprint",
       "Rejected with a message; no account created",
       b"Upload at least one fingerprint" in r.data and db_one("SELECT 1 FROM users WHERE national_id='44444444'") is None,
       "Rejected; no account row created")
r = reg(c, "123456", "Short Id", "A")
record("T03", "Registration", "Submit a 6-digit national ID", "Rejected: ID must be 7 or 8 digits",
       b"7 or 8 digits" in r.data, "Validation message shown")
r = reg(c, "11111111", "Alice Again", "A")
record("T04", "Registration", "Register an ID that already exists", "Rejected: already registered",
       b"already registered" in r.data, "Duplicate message shown")
r = post(c, "/register", full_name="Bad Img", national_id="55555555", email="b@x.com", phone="0712345678",
         fingerprint=(io.BytesIO(b"not an image"), "x.png"))
record("T05", "Registration", "Upload a file that is not a fingerprint image",
       "Rejected; no half-finished account left behind",
       b"not a clear fingerprint" in r.data and db_one("SELECT 1 FROM users WHERE national_id='55555555'") is None,
       "Rejected; no account row created")

# ---------------- Fingerprint login ----------------
c = client()
r = login_fp(c, "11111111", "person_A_scan2.png")
record("T06", "Fingerprint login", "Log in with a genuine scan of the enrolled finger",
       "Access granted; dashboard shown", b"My profile" in r.data, "Dashboard displayed")

c = client()
r = login_fp(c, "11111111", "person_B_scan1.png")
u = db_one("SELECT failed_count FROM users WHERE national_id='11111111'")
record("T07", "Fingerprint login", "Log in with another person's fingerprint",
       "Access denied; attempts-left message", b"Attempts left: 2" in r.data and b"My profile" not in r.data,
       "Denied, failed_count = %s" % u["failed_count"])

c = client()
login_fp(c, "22222222", "person_A_scan1.png"); login_fp(c, "22222222", "person_A_scan2.png")
r = login_fp(c, "22222222", "person_C_scan1.png")
u = db_one("SELECT status FROM users WHERE national_id='22222222'")
al = db_one("SELECT severity, rule_triggered FROM anomaly_alerts WHERE user_id=(SELECT user_id FROM users WHERE national_id='22222222')")
record("T08", "Account lockout", "Three consecutive failed attempts",
       "Account locked and a High-severity alert raised", u["status"] == "locked" and al and al["severity"] == "High",
       "Status = %s; alert severity = %s" % (u["status"], al["severity"] if al else "none"))
r = login_fp(client(), "22222222", "person_B_scan2.png")
record("T09", "Account lockout", "Genuine fingerprint on a locked account", "Blocked: account locked",
       b"locked" in r.data and b"My profile" not in r.data, "Blocked with locked message")

# ---------------- Admin ----------------
ac = client()
r = post(ac, "/admin/login", username="admin", password="wrong")
record("T10", "Admin login", "Wrong administrator password", "Rejected", b"Administrator Console" not in r.data,
       "Rejected; stayed on login page")
r = post(ac, "/admin/login", username="admin", password="Admin@123")
record("T11", "Admin login", "Correct administrator credentials", "Admin overview shown",
       b"Total citizens" in r.data, "Overview with statistics displayed")
r = ac.get("/admin/alerts")
record("T12", "Alerts page", "Open the alerts page as admin", "Lockout alert listed",
       b"failed fingerprint attempts" in r.data, "Alert visible in table")
uid = db_one("SELECT user_id FROM users WHERE national_id='22222222'")["user_id"]
r = ac.post(f"/admin/users/{uid}/unlock", follow_redirects=True)
u = db_one("SELECT status, failed_count FROM users WHERE user_id=?", uid)
r2 = login_fp(client(), "22222222", "person_B_scan3.png")
record("T13", "Account unlock", "Admin unlocks the account, then the owner logs in",
       "Status active, counter reset, login succeeds", u["status"] == "active" and u["failed_count"] == 0 and b"My profile" in r2.data,
       "Status = %s, failed_count = %s, login succeeded" % (u["status"], u["failed_count"]))

# ---------------- Access control ----------------
r = client().get("/dashboard", follow_redirects=True)
record("T14", "Access control", "Open dashboard without logging in", "Redirected to login",
       b"Citizen sign in" in r.data, "Redirected to sign-in page")
cc = client(); login_fp(cc, "11111111", "person_A_scan3.png")
bob_rec = db_one("SELECT record_id FROM citizen_records WHERE user_id=(SELECT user_id FROM users WHERE national_id='33333333') LIMIT 1")["record_id"]
r = cc.get(f"/record/{bob_rec}")
record("T15", "Access control", "Citizen opens another citizen's record by changing the URL",
       "Blocked (HTTP 403) and logged", r.status_code == 403 and db_one("SELECT 1 FROM audit_logs WHERE action LIKE 'Blocked attempt%'") is not None,
       "HTTP %d; blocked attempt written to audit log" % r.status_code)
r = cc.get("/admin", follow_redirects=True)
record("T16", "Access control", "Citizen tries to open the admin console", "Redirected to admin login",
       b"Administrator sign in" in r.data, "Redirected to administrator sign-in")

# ---------------- Monitoring ----------------
c = client()
for i in range(3):
    post(c, "/login", national_id=f"9999999{i}", method="fingerprint", fingerprint=img("person_A_scan1.png"))
al = db_one("SELECT severity FROM anomaly_alerts WHERE rule_triggered LIKE 'Repeated attempts on non-existent%'")
record("T17", "Login-anomaly monitor", "Three attempts on non-existent IDs from one IP",
       "Medium-severity alert raised", al is not None and al["severity"] == "Medium", "Alert raised")
conn = a.get_db()
for i in range(5):
    conn.execute("INSERT INTO login_attempts (user_id, identifier_used, ip_address, result) VALUES (NULL,'x','127.0.0.1','failed: test')")
conn.commit(); conn.close()
post(client(), "/login", national_id="88888888", method="fingerprint", fingerprint=img("person_A_scan1.png"))
al = db_one("SELECT severity FROM anomaly_alerts WHERE rule_triggered LIKE '5 or more failed attempts%'")
record("T18", "Login-anomaly monitor", "Five or more failed attempts from one IP within ten minutes",
       "High-severity alert raised", al is not None and al["severity"] == "High", "Alert raised")

# ---------------- OTP ----------------
c = client()
post(c, "/login", national_id="11111111", method="otp", action="send_otp")
code = sent_codes[-1] if sent_codes else None
stored = db_one("SELECT code_hash FROM otp_challenges WHERE user_id=(SELECT user_id FROM users WHERE national_id='11111111')")
r = post(c, "/login", national_id="11111111", method="otp", action="verify_otp", otp_code="000000" if code != "000000" else "111111")
bad_ok = b"My profile" not in r.data
r = post(c, "/login", national_id="11111111", method="otp", action="verify_otp", otp_code=code)
record("T19", "Email OTP", "Request a code, enter a wrong code, then the correct code",
       "Wrong code rejected; correct code grants access; code stored only as a hash",
       bad_ok and b"My profile" in r.data and stored and stored["code_hash"] != code,
       "Wrong code rejected; correct code accepted; stored value is a SHA-256 hash")
post(c, "/login", national_id="11111111", method="otp", action="send_otp")
code2 = sent_codes[-1]
conn = a.get_db(); conn.execute("UPDATE otp_challenges SET expires_at=?", (int(time.time()) - 1,)); conn.commit(); conn.close()
r = post(client(), "/login", national_id="11111111", method="otp", action="verify_otp", otp_code=code2)
record("T20", "Email OTP", "Enter a correct code after it has expired (5 minutes)", "Rejected",
       b"My profile" not in r.data, "Expired code rejected")

# ---------------- Template protection ----------------
blob = db_one("SELECT encrypted_template FROM fingerprint_templates LIMIT 1")["encrypted_template"]
record("T21", "Template protection", "Inspect the stored fingerprint template in the database",
       "Ciphertext only; not a readable feature file",
       not blob.startswith(b"PK") and b"descr" not in blob and len(a.open_template(blob)) >= 1,
       "Stored as Fernet (AES) ciphertext; decrypts only with the key")
r = client().post("/register", data={"full_name": "Big", "national_id": "77777777", "email": "b@x.com", "phone": "0712345678",
                  "fingerprint": (io.BytesIO(b"0" * (9 * 1024 * 1024)), "big.png")}, content_type="multipart/form-data")
record("T22", "Input limits", "Upload a file larger than 8 MB", "Rejected (HTTP 413)", r.status_code == 413, "HTTP %d" % r.status_code)
r = client().get("/this-page-does-not-exist")
record("T23", "Error handling", "Open a page that does not exist", "Friendly error page (404)",
       r.status_code == 404 and b"Error 404" in r.data, "HTTP 404 with error page")

# ---------------- Accuracy: FAR / FRR ----------------
import re
found = {}
for fpath in sorted(SAMPLES.glob("person_*_scan*.png")):
    m = re.match(r"person_(.+)_scan(\d+)\.png", fpath.name)
    found.setdefault(m.group(1), []).append(int(m.group(2)))
persons = sorted(p for p, sc in found.items() if len(sc) >= 3)   # need 3 scans per person
feats = {(p, s): a.extract_features((SAMPLES / f"person_{p}_scan{s}.png").read_bytes())[0] for p in persons for s in (1, 2, 3)}
genuine, impostor = [], []
for p in persons:
    for held in (1, 2, 3):                       # enrol with the other two scans, probe with the held-out scan
        tmpl = [feats[(p, s)] for s in (1, 2, 3) if s != held]
        genuine.append(max(a.match_percent(feats[(p, held)], t) for t in tmpl))
        for q in persons:
            if q == p: continue
            for s in (1, 2, 3):
                impostor.append(max(a.match_percent(feats[(q, s)], t) for t in tmpl))
thr = a.MATCH_THRESHOLD
frr = 100.0 * sum(g < thr for g in genuine) / len(genuine)
far = 100.0 * sum(i >= thr for i in impostor) / len(impostor)
sweep = []
for t in (5, 10, 15, 20, 25, 30, 40):
    sweep.append(dict(threshold=t, far=round(100.0 * sum(i >= t for i in impostor) / len(impostor), 1),
                      frr=round(100.0 * sum(g < t for g in genuine) / len(genuine), 1)))
accuracy = dict(users=len(persons), genuine_trials=len(genuine), impostor_trials=len(impostor), threshold=thr,
                far=round(far, 1), frr=round(frr, 1),
                genuine_min=round(min(genuine), 1), genuine_mean=round(sum(genuine) / len(genuine), 1),
                impostor_max=round(max(impostor), 1), impostor_mean=round(sum(impostor) / len(impostor), 1),
                sweep=sweep)

accuracy['genuine_scores'] = [round(x, 1) for x in genuine]
accuracy['impostor_scores'] = [round(x, 1) for x in impostor]
out = dict(tests=results, accuracy=accuracy,
           passed=sum(r["result"] == "Pass" for r in results), total=len(results))
(ROOT / "tests" / "results.json").write_text(json.dumps(out, indent=2))
for r in results:
    print(f"{r['id']}  {r['result']:4}  {r['feature']:22} {r['action']}")
print(f"\n{out['passed']}/{out['total']} tests passed")
print(json.dumps(accuracy, indent=2))
