# secure_client.py -- a client that validates the server certificate PROPERLY. LAB USE ONLY.
# It trusts only certs/bank_cert.pem (standing in for "the real bank's cert, as trusted
# via the CA chain in a real browser"), and checks that the certificate's name matches
# the host it asked for (hostname verification). This is what a correctly configured
# HTTPS client (a browser, curl, a mobile app) does by default.
import socket
import ssl
import sys

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 6443

ctx = ssl.create_default_context(cafile="certs/bank_cert.pem")  # our trusted CA/cert
# ctx.check_hostname and ctx.verify_mode are ON by default -- we do NOT weaken them

raw = socket.create_connection((HOST, PORT))
try:
    tls = ctx.wrap_socket(raw, server_hostname="bank.local")
except ssl.SSLCertVerificationError as e:
    print(f"CONNECTION REFUSED by the client: certificate validation failed.\n  -> {e}")
    sys.exit(1)

body = "username=alice&password=alice123"
req = (f"POST /login HTTP/1.1\r\nHost: bank.local\r\n"
       f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
       f"Connection: close\r\n\r\n{body}")
tls.sendall(req.encode())
tls.settimeout(3)
chunks = []
try:
    while True:
        d = tls.recv(4096)
        if not d:
            break
        chunks.append(d)
except socket.timeout:
    pass
resp = b"".join(chunks).decode(errors="replace")
print("Connected and logged in successfully.")
print("Server said:", "Logged in!" if "Logged in!" in resp else resp.splitlines()[0])
tls.close()
