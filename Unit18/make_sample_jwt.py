import jwt, datetime, json
priv = open("as_private.pem").read()
now = datetime.datetime.utcnow()
payload = {
    "iss": "https://auth.minibank.local",
    "sub": "user-1001",
    "aud": "https://api.minibank.local",
    "iat": int(now.timestamp()),
    "exp": int((now + datetime.timedelta(minutes=5)).timestamp()),
    "scope": "accounts:read",
    "name": "Alice",
}
token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "as-key-1"})
print(token)
open("sample.jwt", "w").write(token)
