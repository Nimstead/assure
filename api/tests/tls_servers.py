"""Real local TLS servers for handshake tests: one that rejects every cipher a client offers, one that speaks only TLS 1.0."""

import datetime as dt
import socket
import ssl
import tempfile
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _cert_files(days: int = -30) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "www.example.com")])
    t = dt.datetime.now(dt.UTC)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
         .not_valid_before(t - dt.timedelta(days=400)).not_valid_after(t + dt.timedelta(days=days)).sign(key, hashes.SHA256()))
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(d / "c.pem"), str(d / "k.pem")


def serve(setup, connections: int = 4) -> tuple[int, socket.socket]:
    """A TLS server on 127.0.0.1 whose context setup(ctx) configures; returns (port, listening socket to close)."""
    cert, key = _cert_files()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def run():
        for _ in range(connections):
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                setup(ctx)
                ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ValueError):
                pass
            finally:
                conn.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], srv


def serve_then_reset(ok: int) -> tuple[int, socket.socket]:
    """A TLS 1.2+ server for the first ok connections; every later one is reset before any reply (a flaky path, not a refusal)."""
    import struct
    cert, key = _cert_files(days=90)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def run():
        n = 0
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            n += 1
            try:
                if n <= ok:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    ctx.load_cert_chain(cert, key)
                    ctx.wrap_socket(conn, server_side=True).close()
                else:
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            except (OSError, ValueError):
                pass
            finally:
                conn.close()
    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1], srv


def modern_only(ctx):
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # answers a TLS 1.0/1.1 offer with a protocol-version alert: a real refusal


def no_shared_cipher(ctx):
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("PSK")  # a real TLS server that answers every client offer with a handshake-failure alert


def tls10_only(ctx):
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
