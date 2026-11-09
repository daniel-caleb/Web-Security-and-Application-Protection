# jwt_inspect.py -- decode a JWT by hand, no library, to show there is NO secret
# needed to READ a JWT's header and payload. Run: python jwt_inspect.py <token>
import base64
import json
import sys


def b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def main():
    token = sys.argv[1] if len(sys.argv) > 1 else open("sample.jwt").read().strip()
    parts = token.split(".")
    if len(parts) != 3:
        print("Not a JWT (expected 3 dot-separated parts)")
        return
    header_b64, payload_b64, signature_b64 = parts

    header = json.loads(b64url_decode(header_b64))
    payload = json.loads(b64url_decode(payload_b64))

    print("=== HEADER (base64url-decoded, anyone can read this) ===")
    print(json.dumps(header, indent=2))
    print("\n=== PAYLOAD (base64url-decoded, anyone can read this) ===")
    print(json.dumps(payload, indent=2))
    print(f"\n=== SIGNATURE ===\n{len(b64url_decode(signature_b64))} raw bytes "
          f"-- this is the ONLY part that proves the token is genuine")
    print("\nNOTE: base64url is an ENCODING, not ENCRYPTION. No key was needed")
    print("to read everything above. A JWT's contents are PUBLIC; only its")
    print("SIGNATURE is secret. Never put secrets you don't want read inside a JWT.")


if __name__ == "__main__":
    main()
