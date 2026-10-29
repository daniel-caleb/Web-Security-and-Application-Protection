# test_csrf.py -- automated checks for both apps.   Run:  python test_csrf.py
import importlib

def login_vuln(client):
    client.post("/login", data={"username": "alice", "password": "alice123"})

def login_secure(client):
    client.get("/login")                                    # creates the pre-login token
    with client.session_transaction() as s:
        tok = s["csrf_token"]
    client.post("/login", data={"username": "alice", "password": "alice123", "csrf_token": tok})
    client.get("/")                                         # page render creates the new token
    with client.session_transaction() as s:
        return s["csrf_token"]

def test_vulnerable():
    m = importlib.import_module("vulnerable_app")
    c = m.app.test_client(); login_vuln(c)
    # Forged request: valid session cookie, NO token, "from another site"
    r = c.post("/transfer", data={"to": "mallory", "amount": "500"},
               headers={"Origin": "http://127.0.0.1:8000"})
    assert m.USERS["alice"]["balance"] == 500, "forged POST should succeed on the vulnerable app"
    c.get("/transfer?to=mallory&amount=300")
    assert m.USERS["alice"]["balance"] == 200, "forged GET should succeed on the vulnerable app"
    print("VULNERABLE app: forged POST and GET both moved money  (attack works)")

def test_secure():
    m = importlib.import_module("secure_app")
    c = m.app.test_client(); tok = login_secure(c)
    start = m.USERS["alice"]["balance"]
    # 1 no token
    assert c.post("/transfer", data={"to": "mallory", "amount": "500"}).status_code == 403
    # 2 wrong token
    assert c.post("/transfer", data={"to": "mallory", "amount": "500", "csrf_token": "x" * 43}).status_code == 403
    # 3 right token but foreign Origin
    assert c.post("/transfer", data={"to": "mallory", "amount": "500", "csrf_token": tok},
                  headers={"Origin": "http://127.0.0.1:8000"}).status_code == 403
    # 4 GET no longer changes state
    assert c.get("/transfer?to=mallory&amount=300").status_code == 405
    assert m.USERS["alice"]["balance"] == start, "no forged request may change the balance"
    # 5 legitimate request
    r = c.post("/transfer", data={"to": "mallory", "amount": "10", "csrf_token": tok},
               headers={"Origin": "http://localhost"})
    assert r.status_code == 302 and m.USERS["alice"]["balance"] == start - 10
    # 6 another user's token must not work
    c2 = m.app.test_client(); c2.get("/login")
    with c2.session_transaction() as s: other = s["csrf_token"]
    assert c.post("/transfer", data={"to": "mallory", "amount": "10", "csrf_token": other}).status_code == 403
    # 7 header token (AJAX style)
    r = c.post("/transfer", data={"to": "mallory", "amount": "5"}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 302
    # 8 cookie flags
    hdr = m.app.test_client().get("/login").headers.get("Set-Cookie", "")
    assert "SameSite=Lax" in hdr and "HttpOnly" in hdr, hdr
    print("SECURE app: all checks passed; Set-Cookie ->", hdr.split(";", 1)[1].strip() if ";" in hdr else hdr)

if __name__ == "__main__":
    test_vulnerable(); test_secure(); print("ALL TESTS PASSED")
