"""Local certificate authority for the Airlock edge.

The edge terminates the agent's TLS connections so it can see the exact request (method, URL, body) it
authorises, and injects credentials only into authorised requests. The CA certificate is trusted only by
processes that `airlock run` starts (through SSL_CERT_FILE and friends); it is never installed system-wide.
The CA key never leaves the Airlock home.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .home import ca_dir


class LocalCA:
    def __init__(self, directory: Path | None = None):
        self.dir = directory or ca_dir()
        self.cert_path = self.dir / "airlock-ca.pem"
        self.key_path = self.dir / "airlock-ca.key"
        self._leaf_dir = self.dir / "leaf"
        self._leaf_dir.mkdir(exist_ok=True, mode=0o700)
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        if not (self.cert_path.exists() and self.key_path.exists()):
            self._create()
        self._key = serialization.load_pem_private_key(self.key_path.read_bytes(), None)
        self._cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())

    def _create(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Airlock local edge CA"),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Airlock (this machine only)")])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                    serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _leaf(self, host: str) -> tuple[Path, Path]:
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in host)
        cert_p, key_p = self._leaf_dir / f"{safe}.pem", self._leaf_dir / f"{safe}.key"
        if cert_p.exists() and key_p.exists():
            cert = x509.load_pem_x509_certificate(cert_p.read_bytes())
            if cert.not_valid_after_utc > _dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=1):
                return cert_p, key_p
        key = ec.generate_private_key(ec.SECP256R1())
        now = _dt.datetime.now(_dt.timezone.utc)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
            .issuer_name(self._cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=90))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._cert.public_key()), critical=False)
            .sign(self._key, hashes.SHA256())
        )
        key_p.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        key_p.chmod(0o600)
        cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + self.cert_path.read_bytes())
        return cert_p, key_p

    def server_context(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is None:
                cert_p, key_p = self._leaf(host)
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(cert_p, key_p)
                ctx.set_alpn_protocols(["http/1.1"])
                self._contexts[host] = ctx
            return ctx

    def bundle_for_agent(self, out: Path, *, extra_cafiles: list[str] | None = None) -> Path:
        """A CA bundle for the agent: the Airlock CA only.

        The agent only ever talks TLS to the edge, so it needs to trust nothing else. Extra CA files are
        appended only when explicitly requested (for loopback services that use their own certificates).
        """
        data = self.cert_path.read_bytes()
        for f in extra_cafiles or []:
            data += b"\n" + Path(f).read_bytes()
        out.write_bytes(data)
        return out
