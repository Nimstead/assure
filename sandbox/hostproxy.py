"""A minimal logging HTTP forward proxy on this host for the Windows proxy proof (plan T44, wine2e.py --proxy).

Plain-HTTP requests in absolute form (the sandbox server) and CONNECT tunnels (Windows Update over HTTPS). The guest
reaches this host as 10.0.2.2 (VirtualBox NAT); requests for 10.0.2.2 are sent to 127.0.0.1, where the server listens.
Every request is logged as (method, target) so the proof can show the agent's traffic went through the proxy.
shortcut: no keep-alive, one request per client connection for plain HTTP; enough for the agent's urllib calls.
"""

import select
import socket
import socketserver
import threading

GUEST_HOST = "10.0.2.2"


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = c.recv(65536)
            if not chunk:
                return
            head += chunk
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        method, target, _ = line.split(" ", 2)
        self.server.log.append((method, target))
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
            up = socket.create_connection(("127.0.0.1" if host == GUEST_HOST else host, int(port)), timeout=30)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            rest = head.split(b"\r\n\r\n", 1)[1]
            if rest:
                up.sendall(rest)
        else:
            assert target.startswith("http://"), target
            hostport, _, path = target[7:].partition("/")
            host, _, port = hostport.partition(":")
            up = socket.create_connection(("127.0.0.1" if host == GUEST_HOST else host, int(port or 80)), timeout=30)
            first, _, tail = head.partition(b"\r\n")
            lines = [ln for ln in tail.split(b"\r\n") if not ln.lower().startswith((b"proxy-connection:", b"connection:"))]
            up.sendall(f"{method} /{path} HTTP/1.1".encode() + b"\r\n" + b"\r\n".join(lines).replace(b"\r\n\r\n", b"\r\nConnection: close\r\n\r\n", 1))
        self._pipe(c, up)

    @staticmethod
    def _pipe(a, b):
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 120)
                if not r:
                    return
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (b if s is a else a).sendall(data)
        except OSError:
            return
        finally:
            b.close()


def server_cert(folder):
    """A throwaway self-signed certificate for the sandbox server at 10.0.2.2 (the agent never sends its key to a
    plain-http server through a proxy). Returns (cert path, key path); the guest trusts the cert as a root."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nimstead sandbox (disposable)")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(GUEST_HOST)),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    c, k = folder / "sandbox-cert.pem", folder / "sandbox-key.pem"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return c, k


class Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = allow_reuse_address = True

    def __init__(self, port=3128):
        super().__init__(("127.0.0.1", port), _Handler)
        self.log: list[tuple[str, str]] = []
        threading.Thread(target=self.serve_forever, daemon=True).start()


if __name__ == "__main__":  # self-check: a plain-HTTP request and a CONNECT tunnel through the proxy
    import http.server
    import urllib.request

    web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    threading.Thread(target=web.serve_forever, daemon=True).start()
    p = Proxy(0)
    pp = p.server_address[1]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{pp}"}))
    assert opener.open(f"http://{GUEST_HOST}:{web.server_address[1]}/", timeout=10).status == 200
    s = socket.create_connection(("127.0.0.1", pp))
    s.sendall(f"CONNECT 127.0.0.1:{web.server_address[1]} HTTP/1.1\r\n\r\n".encode())
    assert s.recv(100).startswith(b"HTTP/1.1 200")
    s.sendall(b"GET / HTTP/1.0\r\n\r\n")
    assert s.recv(100).startswith(b"HTTP/1.0 200")
    assert [m for m, _ in p.log] == ["GET", "CONNECT"], p.log
    import ssl
    import tempfile
    from pathlib import Path
    c, k = server_cert(Path(tempfile.mkdtemp()))
    tls = http.server.ThreadingHTTPServer(("127.0.0.1", 0), http.server.SimpleHTTPRequestHandler)
    sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sc.load_cert_chain(c, k)
    tls.socket = sc.wrap_socket(tls.socket, server_side=True)
    threading.Thread(target=tls.serve_forever, daemon=True).start()
    https = urllib.request.build_opener(urllib.request.ProxyHandler({"https": f"http://127.0.0.1:{pp}"}),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=c)))
    assert https.open(f"https://{GUEST_HOST}:{tls.server_address[1]}/", timeout=10).status == 200  # CONNECT to the guest's name
    assert p.log[-1] == ("CONNECT", f"{GUEST_HOST}:{tls.server_address[1]}"), p.log
    print("ok", p.log)
