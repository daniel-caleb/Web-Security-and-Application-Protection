# bank_http_server.py -- DELIBERATELY PLAINTEXT demo bank (HTTP, no TLS). LAB USE ONLY.
# Simulates a legacy/misconfigured site that still accepts logins over plain HTTP.
# Run:  python bank_http_server.py      ->  http://127.0.0.1:6000
from flask import Flask, request, render_template_string

app = Flask(__name__)

LOGIN = """<h2>MiniBank (HTTP -- no encryption)</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form><p>{{ msg }}</p>"""

USERS = {"alice": "alice123"}


@app.route("/", methods=["GET"])
def home():
    return render_template_string(LOGIN, msg="")


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    pw = request.form.get("password", "")
    ok = USERS.get(u) == pw
    print(f"[SERVER] login attempt: username={u!r} password={pw!r} ok={ok}")
    return render_template_string(LOGIN, msg="Logged in!" if ok else "Invalid login")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=6000)
