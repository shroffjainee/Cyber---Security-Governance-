"""TLS certificate compliance checks.

Added in response to the internal review comment "Certificate Authority issues".
For each host:port the server certificate is fetched and four controls are
evaluated (see catalog.CERT_RULES):
  tls_certificate_not_expired   - certificate is still valid today
  tls_certificate_not_expiring  - more than 15 days of validity left
  tls_certificate_trusted_ca    - chain verifies against the system CA store
                                  (fails for self-signed / unknown CA)
  tls_key_strength_2048         - RSA >= 2048 bits or EC >= 256 bits
"""
import datetime as dt
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ..catalog import CERT_RULES

EXPIRY_WARNING_DAYS = 15


def _allow_weak(ctx):
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:
        pass


def _fetch(host, port, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    _allow_weak(ctx)  # we must be able to SEE weak certificates in order to report them
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            der = ss.getpeercert(binary_form=True)
    trusted = True
    try:
        vctx = ssl.create_default_context()
        vctx.check_hostname = False
        _allow_weak(vctx)
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with vctx.wrap_socket(sock, server_hostname=host):
                pass
    except ssl.SSLCertVerificationError:
        trusted = False
    return x509.load_der_x509_certificate(der), trusted


def check(target):
    """target = 'host:port'. Returns (rule rows, details dict)."""
    host, port = target.rsplit(":", 1)
    cert, trusted = _fetch(host, int(port))
    now = dt.datetime.now(dt.timezone.utc)
    not_after = cert.not_valid_after_utc
    days_left = (not_after - now).days
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        strong = key.key_size >= 2048
        key_desc = f"RSA-{key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        strong = key.curve.key_size >= 256
        key_desc = f"EC-{key.curve.key_size}"
    else:
        strong, key_desc = True, type(key).__name__
    results = {
        "tls_certificate_not_expired": days_left >= 0,
        "tls_certificate_not_expiring": days_left > EXPIRY_WARNING_DAYS,
        "tls_certificate_trusted_ca": trusted,
        "tls_key_strength_2048": strong,
    }
    rows = [dict(rule_id=r, severity=CERT_RULES[r]["severity"], result="pass" if ok else "fail")
            for r, ok in results.items()]
    details = dict(target=target, days_left=days_left, trusted=trusted, key=key_desc,
                   self_signed=cert.issuer == cert.subject)
    return rows, details
