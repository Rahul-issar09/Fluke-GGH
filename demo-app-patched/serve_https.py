"""Serve the demo app over HTTPS (port 5443) with the TLS settings in ``app/tls.py``.

Test fixture only. A throwaway self-signed certificate is generated at start-up into a temporary
folder (no private key is stored in the repository).

    python serve_https.py [--host 127.0.0.1] [--port 5443]
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import tempfile
from pathlib import Path

import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.main import create_app
from app.tls import server_context


def self_signed(folder: Path) -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = folder / "cert.pem", folder / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return str(certfile), str(keyfile)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5443)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="demo-tls-") as tmp:
        certfile, keyfile = self_signed(Path(tmp))
        config = uvicorn.Config(create_app(), host=args.host, port=args.port, ssl_certfile=certfile, ssl_keyfile=keyfile)
        config.load()
        config.ssl = server_context(certfile, keyfile)  # the app's own TLS settings, not uvicorn's defaults
        uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
