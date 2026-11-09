# resource_server.py -- a protected API that validates JWT access tokens PROPERLY.
# LAB USE ONLY. Fetches the authorization server's public key via JWKS and pins
# the algorithm, issuer and audience -- this is the combination that defeats the
# pitfalls demonstrated in jwt_pitfalls.py.
# Run:  python resource_server.py      ->  http://127.0.0.1:7002
import jwt
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

AUTH_SERVER = "http://127.0.0.1:7000"
EXPECTED_ISSUER = "http://127.0.0.1:7000"
EXPECTED_AUDIENCE = "http://127.0.0.1:7002"

ACCOUNTS = {"alice": [{"id": "AC-001", "balance": 1000}]}

_jwks_cache = None


def get_signing_key(kid):
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = requests.get(f"{AUTH_SERVER}/.well-known/jwks.json").json()
    for k in _jwks_cache["keys"]:
        if k["kid"] == kid:
            return jwt.PyJWK(k).key
    raise jwt.InvalidKeyError(f"No key found for kid={kid}")


@app.route("/accounts")
def accounts():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify(error="missing bearer token"), 401
    token = auth[len("Bearer "):]

    try:
        unverified_header = jwt.get_unverified_header(token)
        key = get_signing_key(unverified_header.get("kid"))
        claims = jwt.decode(
            token, key,
            algorithms=["RS256"],          # <-- PIN the algorithm, never trust the token's own header
            audience=EXPECTED_AUDIENCE,    # <-- this token must be FOR this API
            issuer=EXPECTED_ISSUER,        # <-- and must come FROM our trusted authorization server
        )
    except jwt.ExpiredSignatureError:
        return jsonify(error="token expired"), 401
    except jwt.InvalidTokenError as e:
        return jsonify(error="invalid token", detail=str(e)), 401

    user = claims["sub"]
    return jsonify(user=user, scope=claims["scope"], accounts=ACCOUNTS.get(user, []))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7002)
