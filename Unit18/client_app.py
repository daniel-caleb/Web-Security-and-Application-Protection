# client_app.py -- the OAuth 2.0 "Relying Party" / client application. LAB USE ONLY.
# Starts the Authorization Code + PKCE flow and exchanges the code for a token.
# Run:  python client_app.py      ->  http://127.0.0.1:7001
import base64
import hashlib
import secrets
import urllib.parse

import requests
from flask import Flask, request, redirect, session, render_template_string

app = Flask(__name__)
app.secret_key = "lab-only-secret"

AUTH_SERVER = "http://127.0.0.1:7000"
CLIENT_ID = "minibank-app"
REDIRECT_URI = "http://127.0.0.1:7001/callback"


@app.route("/")
def home():
    token = session.get("access_token")
    if not token:
        return '<a href="/login">Log in with MiniBank</a>'
    return render_template_string(
        "<h2>Logged in</h2><p>Access token (first 40 chars):<br>{{ t }}...</p>"
        '<p><a href="/call-api">Call the protected API</a></p>',
        t=token[:40])


@app.route("/login")
def login():
    # --- PKCE: generate a random verifier, derive the challenge, keep the verifier secret ---
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    session["pkce_verifier"] = verifier
    session["oauth_state"] = state

    params = {
        "client_id": CLIENT_ID, "redirect_uri": REDIRECT_URI, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "scope": "accounts:read", "response_type": "code",
    }
    return redirect(f"{AUTH_SERVER}/authorize?{urllib.parse.urlencode(params)}")


@app.route("/callback")
def callback():
    if request.args.get("state") != session.get("oauth_state"):
        return "State mismatch -- possible CSRF on the OAuth flow. Aborting.", 400
    code = request.args.get("code")
    resp = requests.post(f"{AUTH_SERVER}/token", data={
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT_URI, "client_id": CLIENT_ID,
        "code_verifier": session.pop("pkce_verifier"),
    })
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.text}", 400
    session["access_token"] = resp.json()["access_token"]
    return redirect("/")


@app.route("/call-api")
def call_api():
    token = session.get("access_token")
    resp = requests.get("http://127.0.0.1:7002/accounts",
                        headers={"Authorization": f"Bearer {token}"})
    return f"<pre>Resource server said ({resp.status_code}):\n{resp.text}</pre>"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7001)
