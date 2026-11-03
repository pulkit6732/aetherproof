"""RFC 3161 time stamps from an independent Time Stamping Authority (TSA).

A receipt's timestamp_ms is the signer's own clock: whoever holds the key can
backdate it. A TSA token is a statement, signed by a third party, that a given
digest existed at genTime. Checkpoints (anchor.py) get one, which bounds every
receipt the checkpoint covers.

Verification is done here, not delegated: the token is only worth something if
every link is checked - imprint, nonce, signed attributes, the ESS
signing-certificate binding, the signature, the timeStamping EKU, and a chain to
a root the caller chose. Needs the optional dependency: pip install aetherproof[timestamp]
"""

import hashlib
import secrets
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512, "sha1": hashes.SHA1}


class TimestampError(Exception):
    """The token is missing, malformed, or fails a verification step."""


@dataclass
class TimestampResult:
    gen_time: datetime
    tsa_subject: str
    serial_number: int
    policy: str


def _asn1():
    try:
        from asn1crypto import cms, tsp
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise TimestampError("RFC 3161 support needs: pip install aetherproof[timestamp]") from e
    return cms, tsp


def build_request(digest: bytes, nonce: int) -> bytes:
    """DER TimeStampReq for a SHA-256 digest, asking the TSA to include its certificate."""
    _, tsp = _asn1()
    if len(digest) != 32:
        raise ValueError("digest must be a 32-byte SHA-256 value")
    return tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": digest},
        "nonce": nonce,
        "cert_req": True,
    }).dump()


def token_from_response(response_der: bytes) -> bytes:
    """Extract the token (a CMS ContentInfo) from a TimeStampResp, checking the status."""
    _, tsp = _asn1()
    from asn1crypto import core

    # RFC 3161 makes the token OPTIONAL (absent on refusal); asn1crypto's
    # TimeStampResp requires it, so a real refusal parsed as "malformed".
    class _Resp(core.Sequence):
        _fields = [("status", tsp.PKIStatusInfo), ("token", core.Any, {"optional": True})]

    try:
        resp = _Resp.load(response_der)
        status = resp["status"]["status"].native
    except Exception as e:
        raise TimestampError(f"not a TimeStampResp: {e}") from e
    if status not in ("granted", "granted_with_mods"):
        texts = resp["status"]["status_string"].native or []
        raise TimestampError(f"TSA refused the request: {status} {' '.join(texts)}".strip())
    if isinstance(resp["token"], core.Void):
        raise TimestampError("TSA granted the request but sent no token")
    return resp["token"].dump()


def request_timestamp(url: str, digest: bytes, timeout: float = 15.0):
    """Ask a TSA to time stamp `digest`. Returns (token_der, nonce)."""
    nonce = secrets.randbits(63)
    req = urllib.request.Request(url, data=build_request(digest, nonce),
                                 headers={"Content-Type": "application/timestamp-query"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except OSError as e:
        raise TimestampError(f"could not reach TSA {url}: {e}") from e
    return token_from_response(body), nonce


def _load_cert(cert) -> x509.Certificate:
    return x509.load_der_x509_certificate(cert.dump())


def _verify_sig(cert: x509.Certificate, signature: bytes, data: bytes, digest_name: str, sig_algo: str) -> None:
    key = cert.public_key()
    algo = _HASHES[digest_name]()
    if isinstance(key, rsa.RSAPublicKey):
        pad = (padding.PSS(mgf=padding.MGF1(algo), salt_length=padding.PSS.AUTO)
               if sig_algo == "rsassa_pss" else padding.PKCS1v15())
        key.verify(signature, data, pad, algo)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(algo))
    else:
        raise TimestampError(f"unsupported TSA key type {type(key).__name__}")


def _chain_to_root(leaf: x509.Certificate, pool: List[x509.Certificate],
                   roots: List[x509.Certificate], at: datetime) -> None:
    """Walk issuer links from the TSA certificate to one of `roots`."""
    root_fps = {r.fingerprint(hashes.SHA256()) for r in roots}
    current = leaf
    for _ in range(10):
        if not (current.not_valid_before_utc <= at <= current.not_valid_after_utc):
            raise TimestampError(f"certificate {current.subject.rfc4514_string()} not valid at genTime")
        if current.fingerprint(hashes.SHA256()) in root_fps:
            return
        issuers = [c for c in pool + roots if c.subject == current.issuer]
        for issuer in issuers:
            try:
                current.verify_directly_issued_by(issuer)
            except (ValueError, TypeError, InvalidSignature):
                continue
            if issuer.fingerprint(hashes.SHA256()) in root_fps:
                if not (issuer.not_valid_before_utc <= at <= issuer.not_valid_after_utc):
                    raise TimestampError("trusted root not valid at genTime")
                return
            current = issuer
            break
        else:
            raise TimestampError(f"no trusted issuer for {current.subject.rfc4514_string()}")
    raise TimestampError("certificate chain too long")


def verify_token(token_der: bytes, digest: bytes, trust_roots: Iterable[x509.Certificate],
                 nonce: Optional[int] = None) -> TimestampResult:
    """Verify an RFC 3161 token over `digest` and return the TSA's time.

    `trust_roots`: the CA certificates you trust for time stamping. Nothing is
    trusted by default - a token is only independent if you chose the TSA.
    """
    cms, tsp = _asn1()
    roots = list(trust_roots)
    if not roots:
        raise TimestampError("no trusted TSA root given")
    try:
        content = cms.ContentInfo.load(token_der)
        signed = content["content"]
        encap = signed["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise TimestampError("token does not carry TSTInfo")
        tst_bytes = encap["content"].parsed.dump()
        tst = tsp.TSTInfo.load(tst_bytes)
        signer_info = signed["signer_infos"][0]
    except TimestampError:
        raise
    except Exception as e:
        raise TimestampError(f"malformed token: {e}") from e

    imprint = tst["message_imprint"]
    if imprint["hash_algorithm"]["algorithm"].native != "sha256" or imprint["hashed_message"].native != digest:
        raise TimestampError("token is for a different digest")
    if nonce is not None and tst["nonce"].native != nonce:
        raise TimestampError("nonce mismatch (replayed or substituted response)")

    certs = [c.chosen for c in signed["certificates"] or [] if c.name == "certificate"]
    sid = signer_info["sid"]
    if sid.name == "issuer_and_serial_number":
        want = (sid.chosen["issuer"].dump(), sid.chosen["serial_number"].native)
        match = [c for c in certs if (c.issuer.dump(), c.serial_number) == want]
    else:
        match = [c for c in certs if c.key_identifier == sid.chosen.native]
    if not match:
        raise TimestampError("TSA certificate not included in token")
    tsa_cert_asn1 = match[0]
    tsa_cert = _load_cert(tsa_cert_asn1)

    digest_name = signer_info["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise TimestampError(f"unsupported digest {digest_name}")
    attrs = signer_info["signed_attrs"]
    if not attrs:
        raise TimestampError("token has no signed attributes")
    by_type = {a["type"].native: a["values"][0] for a in attrs}
    if by_type.get("content_type") is None or by_type["content_type"].native != "tst_info":
        raise TimestampError("signed content-type is not TSTInfo")
    if by_type.get("message_digest") is None or by_type["message_digest"].native != hashlib.new(digest_name, tst_bytes).digest():
        raise TimestampError("signed message-digest does not match TSTInfo (token altered)")

    # ESS signing-certificate binds the signature to this exact certificate (RFC 3161 s2.4.1, RFC 5816)
    cert_der = tsa_cert_asn1.dump()
    if "signing_certificate_v2" in by_type:
        ess = by_type["signing_certificate_v2"]["certs"][0]
        algo = ess["hash_algorithm"]["algorithm"].native if ess["hash_algorithm"] else "sha256"
        bound = ess["cert_hash"].native == hashlib.new(algo, cert_der).digest()
    elif "signing_certificate" in by_type:
        bound = by_type["signing_certificate"]["certs"][0]["cert_hash"].native == hashlib.sha1(cert_der).digest()
    else:
        bound = False
    if not bound:
        raise TimestampError("signing-certificate attribute missing or names a different certificate")

    signed_attrs_der = b"\x31" + attrs.dump()[1:]   # signature covers the SET OF, not the [0] tag
    sig_algo = signer_info["signature_algorithm"]["algorithm"].native
    try:
        _verify_sig(tsa_cert, signer_info["signature"].native, signed_attrs_der, digest_name, sig_algo)
    except InvalidSignature as e:
        raise TimestampError("TSA signature does not verify") from e

    try:
        eku = tsa_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as e:
        raise TimestampError("TSA certificate has no extended key usage") from e
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise TimestampError("TSA certificate is not authorised for time stamping")

    gen_time = tst["gen_time"].native
    _chain_to_root(tsa_cert, [_load_cert(c) for c in certs], roots, gen_time)
    return TimestampResult(gen_time=gen_time, tsa_subject=tsa_cert.subject.rfc4514_string(),
                           serial_number=tst["serial_number"].native, policy=tst["policy"].native)
