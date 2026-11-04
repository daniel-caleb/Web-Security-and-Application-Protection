# bank_https_server.py -- the SAME bank, now correctly served over TLS. LAB USE ONLY.
# Uses certs/bank_cert.pem + certs/bank_key.pem (the bank's OWN, genuine key pair).
# Run:  python bank_https_server.py      ->  https://127.0.0.1:6443
import ssl
from flask import Flask, request, render_template_string

app = Flask(__name__)

LOGIN = """<h2>MiniBank (HTTPS -- encrypted)</h2>
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
    print(f"[REAL BANK] login attempt: username={u!r} password={pw!r} ok={ok}")
    return render_template_string(LOGIN, msg="Logged in!" if ok else "Invalid login")


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("certs/bank_cert.pem", "certs/bank_key.pem")
    app.run(host="127.0.0.1", port=6443, ssl_context=ctx)
