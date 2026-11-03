"""RFC 3161 tokens and signed checkpoints.

A local Time Stamping Authority is built from scratch (root CA, TSA certificate
with the timeStamping EKU, CMS SignedData over TSTInfo) so every verification
step is exercised offline, including each way a token can be wrong.
"""

import base64
import hashlib
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

asn1crypto = pytest.importorskip("asn1crypto")
from asn1crypto import cms, tsp
from asn1crypto import x509 as ax509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aetherproof.core.anchor import Checkpoint, create_checkpoint, verify_checkpoint
from aetherproof.core.keystore import issue_receipt
from aetherproof.core.log import ReceiptLog
from aetherproof.core.signer import Signer
from aetherproof.core.timestamp import (TimestampError, build_request, request_timestamp,
                                        token_from_response, verify_token)

NOW = datetime.now(timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert


def _tsa_cert(ca_key, ca_cert, eku=ExtendedKeyUsageOID.TIME_STAMPING):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name("Test TSA")).issuer_name(ca_cert.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=30))
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return key, cert


class LocalTSA:
    def __init__(self, eku=ExtendedKeyUsageOID.TIME_STAMPING):
        self.root_key, self.root = _ca("Test Root CA")
        self.key, self.cert = _tsa_cert(self.root_key, self.root, eku)

    def respond(self, req_der, *, gen_time=None, nonce=None, ess_cert=None, imprint=None):
        req = tsp.TimeStampReq.load(req_der)
        mi = req["message_imprint"]
        if imprint is not None:
            mi = {"hash_algorithm": {"algorithm": "sha256"}, "hashed_message": imprint}
        tst = tsp.TSTInfo({
            "version": "v1", "policy": "1.3.6.1.4.1.99999.1", "message_imprint": mi,
            "serial_number": 42, "gen_time": gen_time or datetime.now(timezone.utc),
            "nonce": req["nonce"].native if nonce is None else nonce,
        })
        cert_der = self.cert.public_bytes(serialization.Encoding.DER)
        cert_asn1 = ax509.Certificate.load(cert_der)
        attrs = cms.CMSAttributes([
            {"type": "content_type", "values": ["tst_info"]},
            {"type": "message_digest", "values": [hashlib.sha256(tst.dump()).digest()]},
            {"type": "signing_certificate_v2",
             "values": [{"certs": [{"cert_hash": hashlib.sha256(ess_cert or cert_der).digest()}]}]},
        ])
        sig = self.key.sign(attrs.dump(), ec.ECDSA(hashes.SHA256()))
        signer = cms.SignerInfo({
            "version": "v1",
            "sid": cms.SignerIdentifier({"issuer_and_serial_number": {
                "issuer": cert_asn1.issuer, "serial_number": cert_asn1.serial_number}}),
            "digest_algorithm": {"algorithm": "sha256"},
            "signed_attrs": attrs,
            "signature_algorithm": {"algorithm": "sha256_ecdsa"},
            "signature": sig,
        })
        signed = cms.SignedData({
            "version": "v3", "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {"content_type": "tst_info", "content": tst},
            "certificates": [cert_asn1], "signer_infos": [signer],
        })
        token = cms.ContentInfo({"content_type": "signed_data", "content": signed})
        return tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump()


DIGEST = hashlib.sha256(b"checkpoint").digest()
# Fixed test values: the local TSA always issues serial 42; requests use nonce 7,
# so a response carrying 8 is a substituted reply.


@pytest.fixture(scope="module")
def tsa():
    return LocalTSA()


def _token(tsa, **kw):
    return token_from_response(tsa.respond(build_request(DIGEST, 7), **kw))


def test_valid_token_verifies_and_reports_tsa_time(tsa):
    res = verify_token(_token(tsa), DIGEST, [tsa.root], nonce=7)
    assert abs((res.gen_time - datetime.now(timezone.utc)).total_seconds()) < 60
    assert "Test TSA" in res.tsa_subject and res.serial_number == 42


def test_token_for_another_digest_is_rejected(tsa):
    with pytest.raises(TimestampError, match="different digest"):
        verify_token(_token(tsa), hashlib.sha256(b"other").digest(), [tsa.root])


def test_nonce_mismatch_is_rejected(tsa):
    with pytest.raises(TimestampError, match="nonce"):
        verify_token(_token(tsa, nonce=8), DIGEST, [tsa.root], nonce=7)


def test_untrusted_root_is_rejected(tsa):
    _, stranger = _ca("Someone Else")
    with pytest.raises(TimestampError, match="no trusted issuer"):
        verify_token(_token(tsa), DIGEST, [stranger])


def test_no_roots_means_no_trust(tsa):
    with pytest.raises(TimestampError, match="no trusted TSA root"):
        verify_token(_token(tsa), DIGEST, [])


def test_tampered_token_bytes_are_rejected(tsa):
    tok = bytearray(_token(tsa))
    idx = tok.find(b"Test TSA")          # inside the embedded TSA certificate, under the ESS hash
    tok[idx] ^= 0x01
    with pytest.raises(TimestampError):
        verify_token(bytes(tok), DIGEST, [tsa.root])


def test_altered_gen_time_breaks_the_signature(tsa):
    tok = _token(tsa)
    ci = cms.ContentInfo.load(tok)
    tst = ci["content"]["encap_content_info"]["content"].parsed
    year = str(datetime.now(timezone.utc).year).encode()
    raw = tst.dump()
    forged = raw.replace(year, b"2001", 1)   # backdate genTime to an arbitrary earlier year
    assert forged != raw
    with pytest.raises(TimestampError, match="message-digest"):
        verify_token(tok.replace(raw, forged), DIGEST, [tsa.root])


def test_signing_certificate_binding_is_enforced(tsa):
    with pytest.raises(TimestampError, match="signing-certificate"):
        verify_token(_token(tsa, ess_cert=b"not this certificate"), DIGEST, [tsa.root])


def test_certificate_without_timestamping_eku_is_rejected():
    bad = LocalTSA(eku=ExtendedKeyUsageOID.CODE_SIGNING)
    with pytest.raises(TimestampError, match="time stamping"):
        verify_token(_token(bad), DIGEST, [bad.root])


def test_refused_request_raises():
    # TimeStampResp{ status: PKIStatusInfo{ status: 2 (rejection) } } with no token;
    # hand-encoded because asn1crypto will not emit a response without one
    refused = bytes.fromhex("3005" "3003" "020102")
    with pytest.raises(TimestampError, match="refused"):
        token_from_response(refused)


def test_granted_response_without_token_raises():
    with pytest.raises(TimestampError, match="no token"):
        token_from_response(bytes.fromhex("3005" "3003" "020100"))   # status 0 = granted


@pytest.mark.parametrize("junk", [b"", b"\x30", b"not asn1 at all"])
def test_garbage_response_is_a_clear_error(junk):
    with pytest.raises(TimestampError):
        token_from_response(junk)


@pytest.mark.parametrize("cut", [0, 1, 40, -20])
def test_empty_or_truncated_token_is_rejected(tsa, cut):
    tok = _token(tsa)
    with pytest.raises(TimestampError):
        verify_token(tok[:cut] if cut else b"", DIGEST, [tsa.root])


def test_tsa_certificate_expired_at_gen_time_is_rejected(tsa):
    # a token claiming a time after the TSA certificate expired (cert is valid 30 days)
    late = datetime.now(timezone.utc) + timedelta(days=60)
    with pytest.raises(TimestampError, match="not valid at genTime"):
        verify_token(_token(tsa, gen_time=late), DIGEST, [tsa.root])


@pytest.fixture
def tsa_server(tsa):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            out = tsa.respond(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/timestamp-reply")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/tsr"
    srv.shutdown()


def test_request_timestamp_over_http(tsa, tsa_server):
    token, nonce = request_timestamp(tsa_server, DIGEST)
    assert verify_token(token, DIGEST, [tsa.root], nonce=nonce).serial_number == 42


def test_unreachable_tsa_is_a_clear_error():
    with pytest.raises(TimestampError, match="could not reach"):
        request_timestamp("http://127.0.0.1:9/tsr", DIGEST, timeout=2)


# ---------------------------------------------------------------- checkpoints

@pytest.fixture
def filled_log(tmp_path):
    signer = Signer.generate()
    log = ReceiptLog(str(tmp_path / "log.db"))
    for i in range(5):
        issue_receipt(signer, log, model_weight_root="m" * 64, output_hash=f"{i:064d}",
                      receipts_dir=tmp_path / "r")
    yield signer, log
    log.close()


def test_checkpoint_round_trip(filled_log):
    signer, log = filled_log
    cp = Checkpoint.from_json(create_checkpoint(log, signer).to_json())
    rep = verify_checkpoint(cp, log, signer.get_public_key())
    assert rep.ok, rep.problems
    assert any("signer's own clock" in n for n in rep.notes)


def test_deleting_newest_receipts_passes_the_chain_but_not_the_checkpoint(filled_log):
    signer, log = filled_log
    cp = create_checkpoint(log, signer)
    log.close()
    with sqlite3.connect(log.db_path) as c:
        c.execute("DELETE FROM receipts WHERE sequence > 3")
    assert log.verify_integrity(), "chain alone cannot see truncation - that is the gap"
    rep = verify_checkpoint(cp, log, signer.get_public_key())
    assert not rep.ok and any("truncated" in p for p in rep.problems)


def test_rewritten_history_is_detected(filled_log):
    signer, log = filled_log
    cp = create_checkpoint(log, signer)
    log.close()
    with sqlite3.connect(log.db_path) as c:
        c.execute("UPDATE receipts SET entry_hash = ? WHERE sequence = 5", ("f" * 64,))
    rep = verify_checkpoint(cp, log, signer.get_public_key())
    assert any("rewritten" in p for p in rep.problems)


def test_forged_checkpoint_signature_is_rejected(filled_log):
    signer, log = filled_log
    cp = create_checkpoint(log, signer)
    cp.log_size = 2
    rep = verify_checkpoint(cp, log, signer.get_public_key())
    assert "checkpoint signature invalid" in rep.problems


def test_checkpoint_from_untrusted_key_is_rejected(filled_log):
    signer, log = filled_log
    rep = verify_checkpoint(create_checkpoint(log, signer), log, Signer.generate().get_public_key())
    assert any("no trusted key" in p for p in rep.problems)


def test_new_entries_after_checkpoint_are_noted_not_failed(filled_log, tmp_path):
    signer, log = filled_log
    cp = create_checkpoint(log, signer)
    issue_receipt(signer, log, model_weight_root="m" * 64, output_hash="9" * 64, receipts_dir=tmp_path / "r")
    rep = verify_checkpoint(cp, log, signer.get_public_key())
    assert rep.ok and any("1 entries added" in n for n in rep.notes)


def test_single_entry_log_checkpoint_and_truncation_to_zero(tmp_path):
    signer = Signer.generate()
    with ReceiptLog(str(tmp_path / "one.db")) as log:
        issue_receipt(signer, log, model_weight_root="m" * 64, output_hash="1" * 64, receipts_dir=tmp_path / "r")
        cp = create_checkpoint(log, signer)
        assert cp.log_size == 1 and verify_checkpoint(cp, log, signer.get_public_key()).ok
        log.close()
        with sqlite3.connect(log.db_path) as c:
            c.execute("DELETE FROM receipts")
        assert any("log has 0 entries" in p for p in verify_checkpoint(cp, log, signer.get_public_key()).problems)


def test_checkpoint_file_of_another_type_is_refused():
    with pytest.raises(ValueError, match="not an AetherProof checkpoint"):
        Checkpoint.from_json('{"type": "something/else", "log_size": 1}')


def test_empty_log_cannot_be_checkpointed(tmp_path):
    with ReceiptLog(str(tmp_path / "empty.db")) as log:
        with pytest.raises(ValueError, match="empty"):
            create_checkpoint(log, Signer.generate())


def test_checkpoint_with_tsa_time(filled_log, tsa, tsa_server):
    signer, log = filled_log
    cp = create_checkpoint(log, signer, tsa_url=tsa_server)
    rep = verify_checkpoint(cp, log, signer.get_public_key(), tsa_roots=[tsa.root])
    assert rep.ok, rep.problems
    assert rep.tsa_time and "Test TSA" in rep.tsa_subject


def test_tsa_token_without_trusted_root_is_not_accepted_silently(filled_log, tsa_server):
    signer, log = filled_log
    rep = verify_checkpoint(create_checkpoint(log, signer, tsa_url=tsa_server), log, signer.get_public_key())
    assert rep.tsa_time is None and any("not checked" in n for n in rep.notes)


def test_backdated_checkpoint_is_exposed_by_tsa_time(filled_log, tsa):
    signer, log = filled_log
    cp = create_checkpoint(log, signer)
    cp.created_at_ms -= 3 * 3600 * 1000           # signer claims three hours earlier
    cp.signature = signer.sign(cp.signing_bytes())  # and re-signs, which the key holder can do
    tok = token_from_response(tsa.respond(build_request(cp.digest(), 1)))
    cp.timestamp_token = base64.b64encode(tok).decode()
    rep = verify_checkpoint(cp, log, signer.get_public_key(), tsa_roots=[tsa.root])
    assert any("signer clock differs from TSA time" in p for p in rep.problems)


def test_token_moved_to_another_checkpoint_is_rejected(filled_log, tsa, tsa_server, tmp_path):
    signer, log = filled_log
    first = create_checkpoint(log, signer, tsa_url=tsa_server)
    issue_receipt(signer, log, model_weight_root="m" * 64, output_hash="8" * 64, receipts_dir=tmp_path / "r")
    second = create_checkpoint(log, signer)
    second.timestamp_token = first.timestamp_token
    rep = verify_checkpoint(second, log, signer.get_public_key(), tsa_roots=[tsa.root])
    assert any("different digest" in p for p in rep.problems)
