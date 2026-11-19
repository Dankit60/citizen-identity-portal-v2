CITIZEN DIGITAL IDENTITY PORTAL - MULTI-METHOD AUTHENTICATION PROTOTYPE
=====================================================================

This version extends the original fingerprint portal with two alternative
verification methods while retaining the existing pages and administration:

1. Fingerprint recognition (primary): uploaded fingerprint images are processed
   with OpenCV SIFT and compared with encrypted stored templates.
2. Face recognition (alternative): a face image can be enrolled and later
   compared using OpenCV ORB descriptors. This is a classroom prototype only;
   it is not a certified face-recognition or liveness-detection system.
3. Email OTP (alternative): a six-digit code is sent to the registered email.
   Codes expire after five minutes.

SETUP
-----
1. Install Python 3.10 or later.
2. Open a terminal in this folder and run:
       python -m venv venv
       venv\Scripts\activate        (Windows)
       pip install -r requirements.txt
3. Run:
       python app.py
4. Open http://127.0.0.1:5000

ADMIN
-----
URL: http://127.0.0.1:5000/admin/login
Username: admin
Password: Admin@123
Change the default password before any deployment beyond a local demonstration.

SIGN-UP (UPDATED)
-----------------
The Register page is now a single form: personal details, 1-3 fingerprint scans
(required) and an optional face image. The account is created only if all
supplied biometrics are accepted. Email OTP needs no enrolment.

FACE ENROLMENT (LATER)
----------------------
If you skipped the face image at sign-up, open "Enrol face image" from the login
page, enter your National ID and upload a clear, front-facing image. Face recognition is an experimental alternative.
The ORB matching threshold requires evaluation with a proper dataset and does
not prove a person's identity to production standards.

EMAIL OTP CONFIGURATION
-----------------------
Set these environment variables before running the application:
  SMTP_HOST, SMTP_PORT (usually 587), SMTP_USER, SMTP_PASSWORD, SMTP_FROM
The app uses STARTTLS. If SMTP_HOST is not configured, OTP is printed in the
terminal for local demonstration only. Do not use console OTP mode in a real
system. Use an app password or provider-specific SMTP credential, not your
normal email password.

SAMPLE FINGERPRINTS
-------------------
The sample_fingerprints folder contains simulated sample scans because no
physical fingerprint scanner is integrated. The system accepts uploaded
images; it does not communicate with a USB fingerprint reader.

IMPORTANT LIMITATIONS
--------------------
- No physical fingerprint scanner integration.
- No face liveness / anti-spoofing detection.
- Face matching is a prototype feature, not a validated biometric algorithm.
- OTP delivery requires correctly configured SMTP for email delivery.
- Change default admin credentials, disable debug mode, use HTTPS, add CSRF
  protection, and improve encryption-key management before deployment.

TESTING AND DEPLOYMENT (MILESTONES 3-5)
---------------------------------------
Automated tests (23 cases + FAR/FRR):   python tests/run_tests.py
Deploy (production-style, debug off):   python serve.py     -> http://127.0.0.1:8000
Deployment checks (server running):     python tests/deploy_check.py
To test with more people, add files named person_D_scan1.png, scan2, scan3 ... to
sample_fingerprints/ and re-run run_tests.py; FAR/FRR is recalculated automatically.
Before real use: change ADMIN_DEFAULT_PASSWORD in app.py.

CAMERA FINGER SCAN
------------------
Register and Login now have a "Scan finger with camera" button: it opens the camera, shows a
scanning circle, and captures the fingertip image (up to 3 scans at registration, 1 at login).
The camera needs http://localhost or HTTPS. File upload is still available as a fallback.
