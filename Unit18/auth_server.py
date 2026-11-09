# auth_server.py -- a minimal OAuth 2.0 Authorization Server. LAB USE ONLY, not production code.
# Implements: Authorization Code flow with PKCE (S256), RS256-signed JWT access tokens,
# a JWKS endpoint so resource servers can fetch the public key by "kid".
# Run:  python auth_server.py      ->  http://127.0.0.1:7000
import base64
import hashlib
import json
import secrets
import time

import jwt
from flask import Flask, request, redirect, jsonify, render_template_string

app = Flask(__name__)

PRIVATE_KEY = open("as_private.pem").read()
PUBLIC_KEY = open("as_public.pem").read()
KID = "as-key-1"
ISSUER = "http://127.0.0.1:7000"

# --- "database" (in-memory, for the lab only) ---
REGISTERED_CLIENTS = {
    "minibank-app": {"redirect_uris": ["http://127.0.0.1:7001/callback"]}
}
USERS = {"alice": "alice123"}
AUTH_CODES = {}     # code -> {client_id, redirect_uri, code_challenge, user, aud, scope, expires}

LOGIN_PAGE = """<h2>MiniBank Identity Provider</h2>
<p>The app <b>{{ client_id }}</b> wants to access: <b>{{ scope }}</b></p>
<form method="POST">
  <input type="hidden" name="client_id" value="{{ client_id }}">
  <input type="hidden" name="redirect_uri" value="{{ redirect_uri }}">
  <input type="hidden" name="state" value="{{ state }}">
  <input type="hidden" name="code_challenge" value="{{ code_challenge }}">
  <input type="hidden" name="code_challenge_method" value="{{ code_challenge_method }}">
  <input type="hidden" name="scope" value="{{ scope }}">
  <input name="username" placeholder="username" value="alice">
  <input name="password" type="password" placeholder="password" value="alice123">
  <button>Log in and authorise</button>
</form>"""


@app.route("/authorize", methods=["GET", "POST"])
def authorize():
    if request.method == "GET":
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        state = request.args.get("state", "")
        code_challenge = request.args.get("code_challenge", "")
        code_challenge_method = request.args.get("code_challenge_method", "")
        scope = request.args.get("scope", "accounts:read")

        client = REGISTERED_CLIENTS.get(client_id)
        if not client or redirect_uri not in client["redirect_uris"]:
            return "Unknown client_id or redirect_uri not registered", 400
        if code_challenge_method != "S256" or not code_challenge:
            return "PKCE required: code_challenge (S256) missing", 400

        return render_template_string(LOGIN_PAGE, client_id=client_id, redirect_uri=redirect_uri,
                                      state=state, code_challenge=code_challenge,
                                      code_challenge_method=code_challenge_method, scope=scope)

    # POST: user logged in and approved
    u = request.form.get("username", "")
    pw = request.form.get("password", "")
    if USERS.get(u) != pw:
        return "Invalid login", 401

    code = secrets.token_urlsafe(24)
    AUTH_CODES[code] = {
        "client_id": request.form["client_id"],
        "redirect_uri": request.form["redirect_uri"],
        "code_challenge": request.form["code_challenge"],
        "user": u,
        "scope": request.form.get("scope", "accounts:read"),
        "expires": time.time() + 60,         # codes are single-use and short-lived
        "used": False,
    }
    qs = f"code={code}&state={request.form.get('state', '')}"
    return redirect(f"{request.form['redirect_uri']}?{qs}")


@app.route("/token", methods=["POST"])
def token():
    grant_type = request.form.get("grant_type")
    if grant_type != "authorization_code":
        return jsonify(error="unsupported_grant_type"), 400

    code = request.form.get("code")
    verifier = request.form.get("code_verifier", "")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")

    entry = AUTH_CODES.get(code)
    if not entry or entry["used"] or entry["expires"] < time.time():
        return jsonify(error="invalid_grant", error_description="code unknown, used, or expired"), 400
    if entry["client_id"] != client_id or entry["redirect_uri"] != redirect_uri:
        return jsonify(error="invalid_grant", error_description="client_id/redirect_uri mismatch"), 400

    # --- PKCE verification: THIS is what stops a stolen authorization code from being redeemed ---
    computed = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    if computed != entry["code_challenge"]:
        return jsonify(error="invalid_grant", error_description="PKCE verification failed"), 400

    entry["used"] = True   # one-time use

    now = int(time.time())
    access_payload = {
        "iss": ISSUER,
        "sub": entry["user"],
        "aud": "http://127.0.0.1:7002",      # the ONE resource server this token is for
        "iat": now,
        "exp": now + 300,                     # short-lived access token: 5 minutes
        "scope": entry["scope"],
        "client_id": client_id,
    }
    access_token = jwt.encode(access_payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": KID})
    return jsonify(access_token=access_token, token_type="Bearer", expires_in=300,
                   scope=entry["scope"])


@app.route("/.well-known/jwks.json")
def jwks():
    # Expose the PUBLIC key only, in JWKS format, so resource servers can verify signatures
    # without ever holding the authorization server's private key.
    from cryptography.hazmat.primitives import serialization
    pub = serialization.load_pem_public_key(PUBLIC_KEY.encode())
    numbers = pub.public_numbers()

    def b64(n, length):
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    jwk = {
        "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
        "n": b64(numbers.n, 256), "e": b64(numbers.e, 3),
    }
    return jsonify(keys=[jwk])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7000)
