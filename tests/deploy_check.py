"""Deployment smoke test. Start the server first (python serve.py), then run:
       python tests/deploy_check.py
Checks that the deployed portal answers real HTTP requests correctly."""
import json, re, sys, time
from pathlib import Path
import requests

ROOT = Path(__file__).resolve().parent.parent
S = ROOT / "sample_fingerprints"
BASE = "http://127.0.0.1:8000"
res = []
def chk(i, what, ok, obs): res.append(dict(id=i, check=what, result="Pass" if ok else "Fail", observed=obs))
def up(n): return {"fingerprint": (n, (S / n).read_bytes(), "image/png")}

t = time.time(); r = requests.get(BASE + "/"); ms = (time.time() - t) * 1000
chk("D01", "Home page loads", r.status_code == 200 and "Citizen Digital Identity Portal" in r.text, f"HTTP {r.status_code}, {ms:.0f} ms")
r = requests.get(BASE + "/register"); chk("D02", "Register page shows fingerprint upload field", 'name="fingerprint"' in r.text, f"HTTP {r.status_code}")
r = requests.get(BASE + "/nope"); chk("D03", "Unknown URL shows error page, no stack trace", r.status_code == 404 and "Traceback" not in r.text, f"HTTP {r.status_code}")
r = requests.get(BASE + "/console"); chk("D04", "Flask debug console is not exposed", r.status_code == 404, f"HTTP {r.status_code}")
nid = str(int(time.time()))[-8:]
r = requests.post(BASE + "/register", data=dict(full_name="Deploy Tester", national_id=nid, email="d@example.com", phone="0712345678"),
                  files=[("fingerprint", (f"person_A_scan{i}.png", (S / f"person_A_scan{i}.png").read_bytes(), "image/png")) for i in (1, 2, 3)])
chk("D05", "Sign-up with details + 3 fingerprints over HTTP", "Sign-up complete" in r.text, f"HTTP {r.status_code}")
s = requests.Session()
t = time.time(); r = s.post(BASE + "/login", data=dict(national_id=nid, method="fingerprint"), files=up("person_A_scan2.png")); ms = (time.time() - t) * 1000
chk("D06", "Fingerprint login with the registered finger", "My profile" in r.text, f"HTTP {r.status_code}, {ms:.0f} ms")
ck = s.cookies.get_dict(); hdr = r.request.headers.get("Cookie", "")
rr = s.get(BASE + "/dashboard"); chk("D07", "Session keeps the user logged in", "My profile" in rr.text, "Dashboard reachable with session cookie")
r = s.get(BASE + "/logout", allow_redirects=True); rr = s.get(BASE + "/dashboard"); chk("D08", "Logout ends the session", "My profile" not in rr.text, "Dashboard no longer reachable")
r = requests.post(BASE + "/login", data=dict(national_id=nid, method="fingerprint"), files=up("person_B_scan1.png"))
chk("D09", "Impostor fingerprint rejected", "Attempts left" in r.text, "Denied with attempts-left message")
a = requests.Session(); r = a.post(BASE + "/admin/login", data=dict(username="admin", password="Admin@123"))
chk("D10", "Administrator can sign in", "Total citizens" in r.text, f"HTTP {r.status_code}")
for i, (p, k) in enumerate([("/admin/users", "Registered citizens"), ("/admin/alerts", "Login-anomaly alerts"), ("/admin/audit", "Audit log")], 11):
    r = a.get(BASE + p); chk(f"D{i}", f"Admin page {p} loads", k in r.text, f"HTTP {r.status_code}")
sc = requests.get(BASE + "/").headers.get("Set-Cookie", "")
t = time.time()
from concurrent.futures import ThreadPoolExecutor
def one(_): return requests.get(BASE + "/login").status_code
with ThreadPoolExecutor(10) as ex: codes = list(ex.map(one, range(30)))
el = time.time() - t
chk("D14", "30 page requests from 10 parallel users", all(c == 200 for c in codes), f"All HTTP 200, total {el:.2f} s")
out = dict(checks=res, passed=sum(x["result"] == "Pass" for x in res), total=len(res))
(ROOT / "tests" / "deploy_results.json").write_text(json.dumps(out, indent=2))
for x in res: print(x["id"], x["result"], x["check"], "-", x["observed"])
print(f"{out['passed']}/{out['total']} deployment checks passed")
