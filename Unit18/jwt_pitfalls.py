# jwt_pitfalls.py -- demonstrates common JWT verification MISTAKES, each as a real,
# runnable exploit against a VULNERABLE verifier, followed by the SAME exploit
# failing against a SECURE verifier. LAB USE ONLY.
#
# Run:  python jwt_pitfalls.py
import base64
import hashlib
import hmac as hmac_mod
import json
import time

import jwt
from cryptography.hazmat.primitives import serialization

PRIVATE_KEY = open("as_private.pem").read()
PUBLIC_KEY = open("as_public.pem").read()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def genuine_token(include_aud=True, **overrides):
    now = int(time.time())
    payload = {"sub": "alice", "role": "user", "iss": "https://auth.minibank.local",
               "iat": now, "exp": now + 300}
    if include_aud:
        payload["aud"] = "https://api.minibank.local"
    payload.update(overrides)
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256", headers={"kid": "as-key-1"})


# ======================================================================
# PITFALL 1: alg=none -- accepting a token that claims to need no signature
# ======================================================================
def pitfall_1():
    print("\n--- PITFALL 1: alg=none ---")

    def vulnerable_verify(token):
        # BUG: decodes using whatever algorithm the TOKEN ITSELF claims in its header
        header = jwt.get_unverified_header(token)
        return jwt.decode(token, options={"verify_signature": False}) if header["alg"] == "none" \
            else jwt.decode(token, PUBLIC_KEY, algorithms=[header["alg"]])

    def secure_verify(token):
        # FIX: the ALLOWED algorithm list is fixed by the SERVER, never read from the token
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])

    # Attacker forges a token with alg=none and an EMPTY signature, granting themselves admin
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "attacker", "role": "admin",
                                 "exp": int(time.time()) + 3600}).encode())
    forged_token = f"{header}.{payload}."       # note: empty signature segment

    try:
        claims = vulnerable_verify(forged_token)
        print(f"  VULNERABLE verifier: ACCEPTED forged token -> role={claims['role']}  *** EXPLOIT WORKS ***")
    except Exception as e:
        print(f"  VULNERABLE verifier: rejected ({e})  -- unexpected, check the code")

    try:
        secure_verify(forged_token)
        print("  SECURE verifier: ACCEPTED forged token -- THIS SHOULD NOT HAPPEN")
    except jwt.InvalidTokenError as e:
        print(f"  SECURE verifier: REJECTED forged token ({type(e).__name__}: {e})  -- attack blocked")


# ======================================================================
# PITFALL 2: RS256/HS256 "algorithm confusion" (key confusion)
# ======================================================================
def pitfall_2():
    print("\n--- PITFALL 2: RS256/HS256 algorithm confusion ---")
    print("  (modern PyJWT (2.x) actually blocks this by default if you pass a PEM string to")
    print("   algorithms=[\"RS256\",\"HS256\"] -- a real defence-in-depth improvement. The bug")
    print("   below is written the way many hand-rolled or older verifiers still do it: by")
    print("   HAND-checking the signature with hmac, trusting the 'alg' the token itself claims.)")

    def vulnerable_verify_by_hand(token, public_key_pem):
        # BUG: trusts the token's OWN header to decide how to verify it, and for "HS256"
        # treats the (public, publishable) RSA key bytes as if they were a private HMAC secret
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(h_b64 + "=="))
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = base64.urlsafe_b64decode(s_b64 + "==")
        if header["alg"] == "HS256":
            expected = hmac_mod.new(public_key_pem.encode(), signing_input, hashlib.sha256).digest()
            if not hmac_mod.compare_digest(sig, expected):
                raise jwt.InvalidSignatureError("bad HMAC signature")
        else:
            jwt.decode(token, public_key_pem, algorithms=["RS256"])  # delegate RS256 properly
        return json.loads(base64.urlsafe_b64decode(p_b64 + "=="))

    def secure_verify(token, public_key_pem):
        # FIX: only RS256 is ever allowed for tokens meant to be asymmetrically signed,
        # and verification is delegated entirely to a trusted library -- never hand-rolled
        return jwt.decode(token, public_key_pem, algorithms=["RS256"])

    # The RSA PUBLIC key is, by design, PUBLIC -- published at /.well-known/jwks.json.
    # An attacker who only ever had the public key can still forge a token IF the
    # verifier will accept HS256, because HMAC just needs "a secret", and the
    # verifier will feed it the public key bytes as that secret.
    public_key_bytes = PUBLIC_KEY.encode()
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "attacker", "role": "admin", "exp": int(time.time()) + 3600}
    h_b64 = b64url(json.dumps(header).encode())
    p_b64 = b64url(json.dumps(payload).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    forged_sig = hmac_mod.new(public_key_bytes, signing_input, hashlib.sha256).digest()
    forged_token = f"{h_b64}.{p_b64}.{b64url(forged_sig)}"

    try:
        claims = vulnerable_verify_by_hand(forged_token, PUBLIC_KEY)
        print(f"  VULNERABLE hand-rolled verifier: ACCEPTED forged token -> role={claims['role']}  *** EXPLOIT WORKS ***")
    except Exception as e:
        print(f"  VULNERABLE hand-rolled verifier: rejected ({e})")

    try:
        secure_verify(forged_token, PUBLIC_KEY)
        print("  SECURE verifier: ACCEPTED forged token -- THIS SHOULD NOT HAPPEN")
    except jwt.InvalidTokenError as e:
        print(f"  SECURE verifier: REJECTED forged token ({type(e).__name__}: {e})  -- attack blocked")


# ======================================================================
# PITFALL 3: not checking expiry (or not checking it at all)
# ======================================================================
def pitfall_3():
    print("\n--- PITFALL 3: ignoring token expiry ---")

    expired_token = genuine_token(include_aud=False, exp=int(time.time()) - 3600)   # expired one hour ago

    def vulnerable_verify(token):
        # BUG: verify_exp explicitly turned off (seen in real code "to make testing easier")
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
                          options={"verify_exp": False})

    def secure_verify(token):
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])   # exp checked by default

    claims = vulnerable_verify(expired_token)
    print(f"  VULNERABLE verifier: ACCEPTED an hour-old EXPIRED token -> sub={claims['sub']}  *** EXPLOIT WORKS ***")
    try:
        secure_verify(expired_token)
        print("  SECURE verifier: ACCEPTED expired token -- THIS SHOULD NOT HAPPEN")
    except jwt.ExpiredSignatureError as e:
        print(f"  SECURE verifier: REJECTED expired token ({e})  -- attack blocked")


# ======================================================================
# PITFALL 4: weak / guessable HMAC secret
# ======================================================================
def pitfall_4():
    print("\n--- PITFALL 4: weak HMAC secret (brute-forceable) ---")

    WEAK_SECRET = "secret123"    # a real secret someone actually used
    token = jwt.encode({"sub": "alice", "role": "user", "exp": int(time.time()) + 3600},
                       WEAK_SECRET, algorithm="HS256")
    print(f"  A token signed with a short, common HS256 secret: {token[:50]}...")

    candidates = ["password", "123456", "changeme", "minibank", "letmein", "secret123", "admin"]
    cracked = None
    for guess in candidates:
        try:
            jwt.decode(token, guess, algorithms=["HS256"])
            cracked = guess
            break
        except jwt.InvalidSignatureError:
            continue
    if cracked:
        forged = jwt.encode({"sub": "attacker", "role": "admin", "exp": int(time.time()) + 3600},
                            cracked, algorithm="HS256")
        claims = jwt.decode(forged, cracked, algorithms=["HS256"])
        print(f"  Secret CRACKED from a {len(candidates)}-word list: {cracked!r}")
        print(f"  Attacker now MINTS their own valid token -> role={claims['role']}  *** EXPLOIT WORKS ***")
    print("  FIX: use a long, random secret (32+ bytes from a CSPRNG), or prefer RS256/ES256")
    print("       (asymmetric signing) so the verifying party never needs the signing secret at all.")


# ======================================================================
# PITFALL 5: missing audience / issuer check (token confusion between services)
# ======================================================================
def pitfall_5():
    print("\n--- PITFALL 5: missing audience/issuer check ---")

    # A token correctly issued by OUR auth server, but for a DIFFERENT API
    # (e.g. a "notifications" service), not the "accounts" service.
    token_for_other_service = genuine_token(aud="https://notifications.minibank.local")

    def vulnerable_verify(token):
        # BUG: a developer hit PyJWT's "Invalid audience" error during testing (because no
        # audience= was supplied) and "fixed" it by turning the check off -- a very real,
        # very common pattern -- instead of supplying the correct expected audience.
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
                          options={"verify_aud": False})

    def secure_verify(token):
        # FIX: pin the expected audience AND issuer -- never disable the check
        return jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"],
                          audience="https://api.minibank.local",
                          issuer="https://auth.minibank.local")

    claims = vulnerable_verify(token_for_other_service)
    print(f"  VULNERABLE verifier (accounts API): ACCEPTED a token meant for "
          f"{claims['aud']!r}  *** EXPLOIT WORKS (token confusion) ***")
    try:
        secure_verify(token_for_other_service)
        print("  SECURE verifier: ACCEPTED mismatched-audience token -- THIS SHOULD NOT HAPPEN")
    except jwt.InvalidAudienceError as e:
        print(f"  SECURE verifier: REJECTED mismatched-audience token ({e})  -- attack blocked")


if __name__ == "__main__":
    pitfall_1()
    pitfall_2()
    pitfall_3()
    pitfall_4()
    pitfall_5()
    print("\nAll five pitfalls demonstrated: each VULNERABLE verifier was fooled,")
    print("and each SECURE verifier correctly rejected the same forged/misused token.")
