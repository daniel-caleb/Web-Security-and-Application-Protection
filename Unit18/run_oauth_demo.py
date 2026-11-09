# run_oauth_demo.py -- runs the full Authorization Code + PKCE flow against the
# live auth_server.py and resource_server.py, acting as the browser/client would.
# Start both servers first (see run_lab_demo.sh), then run this script.
import base64, hashlib, secrets, re, sys
import requests

AUTH = "http://127.0.0.1:7000"
RS = "http://127.0.0.1:7002"
CLIENT_ID = "minibank-app"
REDIRECT = "http://127.0.0.1:7001/callback"


def step(n, title):
    print(f"\n[{n}] {title}")


verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

step(1, "Client generates PKCE verifier/challenge and sends the user to /authorize")
r = requests.get(f"{AUTH}/authorize", params={
    "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "xyz",
    "code_challenge": challenge, "code_challenge_method": "S256", "scope": "accounts:read"})
print(f"    GET /authorize -> {r.status_code} (login/consent page shown)")

step(2, "User logs in and approves -- authorization server issues a one-time code")
r2 = requests.post(f"{AUTH}/authorize", data={
    "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "xyz",
    "code_challenge": challenge, "code_challenge_method": "S256", "scope": "accounts:read",
    "username": "alice", "password": "alice123"}, allow_redirects=False)
code = re.search(r"code=([^&]+)", r2.headers["Location"]).group(1)
print(f"    POST /authorize -> {r2.status_code}, redirected with code={code[:12]}...")

step(3, "Client exchanges the code for an access token, proving it holds the PKCE verifier")
r3 = requests.post(f"{AUTH}/token", data={
    "grant_type": "authorization_code", "code": code,
    "redirect_uri": REDIRECT, "client_id": CLIENT_ID, "code_verifier": verifier})
token = r3.json()["access_token"]
print(f"    POST /token -> {r3.status_code}")
print(f"    access_token = {token[:50]}...")

step(4, "Client calls the protected API with the access token")
r4 = requests.get(f"{RS}/accounts", headers={"Authorization": f"Bearer {token}"})
print(f"    GET /accounts -> {r4.status_code}  {r4.json()}")

step(5, "Attacker intercepts a FRESH authorization CODE and tries to redeem it "
        "without the (secret, browser-held) verifier")
r5a = requests.post(f"{AUTH}/authorize", data={
    "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "state": "xyz",
    "code_challenge": challenge, "code_challenge_method": "S256", "scope": "accounts:read",
    "username": "alice", "password": "alice123"}, allow_redirects=False)
stolen_code = re.search(r"code=([^&]+)", r5a.headers["Location"]).group(1)
r5 = requests.post(f"{AUTH}/token", data={
    "grant_type": "authorization_code", "code": stolen_code,
    "redirect_uri": REDIRECT, "client_id": CLIENT_ID, "code_verifier": "guessed-wrong"})
print(f"    POST /token (correct fresh code, WRONG verifier) -> {r5.status_code}  {r5.json()}")

step(6, "Legitimate client tries to reuse its OWN already-spent code a second time")
r6 = requests.post(f"{AUTH}/token", data={
    "grant_type": "authorization_code", "code": code,
    "redirect_uri": REDIRECT, "client_id": CLIENT_ID, "code_verifier": verifier})
print(f"    POST /token (code reuse) -> {r6.status_code}  {r6.json()}")

print("\nDemo complete: PKCE blocked a stolen/guessed code, and the code was single-use.")
