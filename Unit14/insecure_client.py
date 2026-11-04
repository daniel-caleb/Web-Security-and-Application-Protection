# insecure_client.py -- a client that DISABLES certificate validation. LAB USE ONLY.
# This simulates the common real-world mistake: verify=False in requests,
# "accept all certificates" in a mobile app, or a user clicking through a
# browser warning. It will happily complete a TLS handshake with ANYONE.
import socket
import ssl
import sys

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 6443

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False      # <-- the mistake
ctx.verify_mode = ssl.CERT_NONE  # <-- the mistake

raw = socket.create_connection((HOST, PORT))
tls = raw
tls = ctx.wrap_socket(raw, server_hostname="bank.local")
peer_cert_der = tls.getpeercert(binary_form=True)
print(f"TLS handshake completed with NO certificate validation "
      f"(received a {len(peer_cert_der)}-byte certificate and accepted it blindly).")

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
print("Server said:", "Logged in!" if "Logged in!" in resp else resp.splitlines()[0])
tls.close()
