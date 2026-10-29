# secure_app.py  --  MiniBank with anti-CSRF protection (synchroniser token pattern)
# Run:  python secure_app.py      ->  http://localhost:5000
import hmac
import os
import secrets
from flask import Flask, request, session, redirect, render_template_string, abort

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-only-secret")

# Defence layer 1: hardened session cookie
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",                       # set explicitly, never rely on defaults
    SESSION_COOKIE_SECURE=os.environ.get("LAB_HTTPS") == "1",
)

USERS = {
    "alice":   {"password": "alice123",   "balance": 1000},
    "mallory": {"password": "mallory123", "balance": 50},
}


# ---------- Defence layer 2: synchroniser token ----------
def get_csrf_token():
    """Create a random token bound to this session (once) and return it."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token       # usable as {{ csrf_token() }}


@app.before_request
def csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return                                              # safe methods: no state change
    # Layer 3: Origin check (if the browser sent an Origin header it must be our own)
    origin = request.headers.get("Origin")
    if origin and origin != request.host_url.rstrip("/"):
        abort(403, "Cross-origin request blocked")
    # Layer 2: token must be present AND match the one stored in the session
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(403, "Invalid or missing CSRF token")        # fail closed


LOGIN = """<h2>MiniBank login (protected)</h2>
<form method="POST" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form><p>{{ msg }}</p>"""

HOME = """<h2>Welcome, {{ user }}</h2>
<p>Balance: KES {{ balance }}</p>
<h3>Send money</h3>
<form method="POST" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  To: <input name="to" value="mallory">
  Amount: <input name="amount" value="10">
  <button>Send</button>
</form>
<p>{{ msg }}</p>
<form method="POST" action="/logout">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <button>Log out</button>
</form>"""


@app.route("/")
def home():
    user = session.get("user")
    if not user:
        return redirect("/login")
    return render_template_string(HOME, user=user, balance=USERS[user]["balance"],
                                  msg=request.args.get("msg", ""))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("username", "")
        u = USERS.get(name)
        if u and u["password"] == request.form.get("password"):
            session.clear()                 # new session + new token after login
            session["user"] = name
            return redirect("/")
        return render_template_string(LOGIN, msg="Invalid username or password")
    return render_template_string(LOGIN, msg="")


@app.route("/transfer", methods=["POST"])   # state change: POST only
def transfer():
    user = session.get("user")
    if not user:
        return redirect("/login")
    to = request.form.get("to", "")
    try:
        amount = int(request.form.get("amount", "0"))
    except ValueError:
        return redirect("/?msg=Invalid+amount")
    if to not in USERS or amount <= 0 or amount > USERS[user]["balance"]:
        return redirect("/?msg=Transfer+refused")
    USERS[user]["balance"] -= amount
    USERS[to]["balance"] += amount
    print(f"[TRANSFER] {user} -> {to}: KES {amount}")
    return redirect("/?msg=Sent+KES+%d+to+%s" % (amount, to))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
