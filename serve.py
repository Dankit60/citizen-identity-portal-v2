"""Production-style launcher (Milestone 5: deployment).

Runs the portal on the Waitress WSGI server with Flask debug mode OFF.
Usage:   python serve.py          then open http://127.0.0.1:8000
"""
from waitress import serve
from app import app

app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", DEBUG=False)

if __name__ == "__main__":
    print("Portal running on http://127.0.0.1:8000  (press Ctrl+C to stop)")
    serve(app, host="127.0.0.1", port=8000, threads=4)
