"""
Gloamfire Vulnerable Web Target — intentionally vulnerable endpoints
for web attack simulation scenarios.

DO NOT deploy outside an isolated lab network.
"""

import os
import subprocess

from flask import Flask, jsonify, request

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Intentionally vulnerable endpoints (for lab/simulation use ONLY)
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    return jsonify({
        "name": "Gloamfire Vuln-Web Target",
        "description": "Intentionally vulnerable web app for attack simulation",
        "endpoints": [
            "/ping?host=<host>",
            "/echo?msg=<msg>",
            "/info",
        ],
    })


@app.route("/ping")
def ping():
    """Command injection surface — vulnerable by design for simulation."""
    host = request.args.get("host", "localhost")
    # INTENTIONALLY VULNERABLE: no sanitisation — for simulation only
    # A real injection payload (e.g. `; cat /etc/passwd`) would succeed here.
    # This is the artefact that IDS/WAF rules should detect.
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return jsonify({"host": host, "output": result.stdout, "rc": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "timeout"}), 504
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/echo")
def echo():
    """Reflected XSS surface — vulnerable by design."""
    msg = request.args.get("msg", "")
    # Returns raw user input — XSS by design
    return f"<html><body>{msg}</body></html>", 200, {"Content-Type": "text/html"}


@app.route("/info")
def info():
    return jsonify({
        "hostname": os.uname().nodename,
        "pid": os.getpid(),
        "env": {k: v for k, v in os.environ.items() if "SECRET" not in k.upper()},
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
