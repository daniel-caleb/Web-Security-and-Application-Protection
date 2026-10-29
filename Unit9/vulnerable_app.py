# vulnerable_app.py  --  DELIBERATELY VULNERABLE demo bank. LAB USE ONLY.
# Run:  python vulnerable_app.py      ->  http://localhost:5000
import os
from flask import Flask, request, session, redirect, render_template_string

app = Flask(__name__)
app.secret_key = "lab-only-secret"

# Legacy behaviour: no explicit SameSite attribute (browser defaults differ).
# For Chrome/Edge demos over HTTPS you may set COOKIE_SAMESITE=None and COOKIE_SECURE=1.
app.config["SESSION_COOKIE_SAMESITE"] = os.environ.get("COOKIE_SAMESITE") or None
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"

USERS = {
    "alice":   {"password": "alice123",   "balance": 1000},
    "mallory": {"password": "mallory123", "balance": 50},
}

LOGIN = """<h2>MiniBank login</h2>
<form method="POST" action="/login">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>Log in</button>
</form><p>{{ msg }}</p>"""

HOME = """<h2>Welcome, {{ user }}</h2>
<p>Balance: KES {{ balance }}</p>
<h3>Send money</h3>
<form method="POST" action="/transfer">
  To: <input name="to" value="mallory">
  Amount: <input name="amount" value="10">
  <button>Send</button>
</form>
<p>{{ msg }}</p><p><a href="/logout">Log out</a></p>"""


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
        u = USERS.get(request.form.get("username", ""))
        if u and u["password"] == request.form.get("password"):
            session["user"] = request.form["username"]
            return redirect("/")
        return render_template_string(LOGIN, msg="Invalid username or password")
    return render_template_string(LOGIN, msg="")


# VULNERABILITIES: (1) no anti-CSRF token, (2) state change allowed via GET,
# (3) authentication relies only on an automatically attached cookie.
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    user = session.get("user")
    if not user:
        return redirect("/login")
    to = request.values.get("to", "")
    try:
        amount = int(request.values.get("amount", "0"))
    except ValueError:
        return redirect("/?msg=Invalid+amount")
    if to not in USERS or amount <= 0 or amount > USERS[user]["balance"]:
        return redirect("/?msg=Transfer+refused")
    USERS[user]["balance"] -= amount
    USERS[to]["balance"] += amount
    print(f"[TRANSFER] {user} -> {to}: KES {amount}")
    return redirect("/?msg=Sent+KES+%d+to+%s" % (amount, to))


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
