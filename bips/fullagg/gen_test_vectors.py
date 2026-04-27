#!/usr/bin/env python3
"""
Generate test vectors for signature aggregation of BIP 340 signatures
per the DahLIAS interactive signing protocol.

Usage:
    python gen_test_vectors.py

Outputs:
    - vectors/test_vectors_sign.csv   (end-to-end signing with fixed nonces)
    - vectors/test_vectors_verify.csv (Verify: success and failure cases)
"""

import csv
import os
from pathlib import Path
from typing import List, Tuple

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import bytes_from_int, int_from_bytes

from reference import (
    NonceAgg, Sign, SigAgg, Verify, PartialSigVerify, has_even_y, n,
)


VECTORS_DIR = Path(__file__).resolve().parent / "vectors"
SIGN_VECTORS = VECTORS_DIR / "test_vectors_sign.csv"
VERIFY_VECTORS = VECTORS_DIR / "test_vectors_verify.csv"
PARTIAL_SIG_VERIFY_VECTORS = VECTORS_DIR / "test_vectors_partial_sig_verify.csv"


def scalar_from_byte(b: int) -> Scalar:
    """Scalar whose 32-byte big-endian encoding is bytes([b]*32). Safe for 0x01..0xee."""
    assert 1 <= b <= 0xee
    return Scalar(int_from_bytes(bytes([b] * 32)))


def make_signer(i: int):
    """Deterministic (sk, pk, msg, secnonce, pubnonce). sk is normalized so pk has even y."""
    sk = scalar_from_byte(i * 3 + 1)
    pk = sk * G
    if not has_even_y(pk):
        sk = -sk
        pk = sk * G
    r1 = scalar_from_byte(i * 3 + 2)
    r2 = scalar_from_byte(i * 3 + 3)
    R1, R2 = r1 * G, r2 * G
    msg = bytes([0x80 + i] * 32)
    return sk, pk, msg, (r1, r2), (R1, R2)


def make_same_pk_signers():
    """Two signers sharing one key, signing different messages."""
    sk = scalar_from_byte(1)
    pk = sk * G
    if not has_even_y(pk):
        sk = -sk
        pk = sk * G
    msg_a = bytes([0xA0] * 32)
    msg_b = bytes([0xA1] * 32)
    r1_a, r2_a = scalar_from_byte(11), scalar_from_byte(12)
    r1_b, r2_b = scalar_from_byte(13), scalar_from_byte(14)
    return [
        (sk, pk, msg_a, (r1_a, r2_a), (r1_a * G, r2_a * G)),
        (sk, pk, msg_b, (r1_b, r2_b), (r1_b * G, r2_b * G)),
    ]


def serialize_pubnonce(pubnonce) -> bytes:
    R1, R2 = pubnonce
    return R1.to_bytes_compressed() + R2.to_bytes_compressed()


def serialize_secnonce(secnonce) -> bytes:
    r1, r2 = secnonce
    return bytes_from_int(int(r1)) + bytes_from_int(int(r2))


def serialize_sig(sig) -> bytes:
    R, s = sig
    return R.to_bytes_xonly() + bytes_from_int(int(s))


def serialize_pk(pk: GE) -> bytes:
    return pk.to_bytes_xonly()


def format_list(items: List[bytes], sep: str = ";") -> str:
    if not items:
        return ""
    return sep.join(item.hex().upper() for item in items)


def sign_session(signers):
    """Run NonceAgg -> Sign (per signer) -> SigAgg with deterministic inputs."""
    sks = [s[0] for s in signers]
    pks = [s[1] for s in signers]
    msgs = [s[2] for s in signers]
    secnonces = [s[3] for s in signers]
    pubnonces = [s[4] for s in signers]
    aggnonce = NonceAgg(pubnonces)
    psigs = [
        Sign(secnonces[i], sks[i], msgs[i], aggnonce, pks, msgs, pubnonces)
        for i in range(len(sks))
    ]
    sig = SigAgg(aggnonce, pks, msgs, pubnonces, psigs)
    return aggnonce, psigs, sig


def gen_sign_vectors(f):
    writer = csv.writer(f)
    writer.writerow((
        "index",
        "secret_keys",
        "messages",
        "secnonces",
        "expected_aggnonce",
        "expected_partial_sigs",
        "expected_sig",
        "comment",
    ))

    def write_row(idx, signers, comment):
        aggnonce, psigs, sig = sign_session(signers)
        writer.writerow((
            idx,
            format_list([bytes_from_int(int(s[0])) for s in signers]),
            format_list([s[2] for s in signers]),
            format_list([serialize_secnonce(s[3]) for s in signers]),
            serialize_pubnonce(aggnonce).hex().upper(),
            format_list([bytes_from_int(p) for p in psigs]),
            serialize_sig(sig).hex().upper(),
            comment,
        ))
        pks = [s[1] for s in signers]
        msgs = [s[2] for s in signers]
        pubnonces = [s[4] for s in signers]
        for i in range(len(signers)):
            assert PartialSigVerify(psigs[i], aggnonce, pks, msgs, pubnonces, i), \
                f"generated psig failed self-verification: {comment}"
        assert Verify(pks, msgs, sig), \
            f"generated sig failed self-verification: {comment}"

    write_row(0, [make_signer(0)], "Single signer")
    write_row(1, [make_signer(i) for i in range(2)], "Two signers")
    write_row(2, [make_signer(i) for i in range(3)], "Three signers")
    write_row(3, [make_signer(i) for i in range(5)], "Five signers")
    write_row(4, make_same_pk_signers(), "Same pubkey signs two different messages")


def gen_verify_vectors(f):
    writer = csv.writer(f)
    writer.writerow((
        "index", "pubkeys", "messages", "sig", "expected_result", "comment",
    ))

    idx = 0

    signers = [make_signer(i) for i in range(2)]
    _, _, sig = sign_session(signers)
    pks = [serialize_pk(s[1]) for s in signers]
    msgs = [s[2] for s in signers]
    sig_bytes = serialize_sig(sig)

    writer.writerow((idx, format_list(pks), format_list(msgs),
                     sig_bytes.hex().upper(), "TRUE",
                     "Two-signer valid aggregate"))
    idx += 1

    signers3 = [make_signer(i) for i in range(3)]
    _, _, sig3 = sign_session(signers3)
    pks3 = [serialize_pk(s[1]) for s in signers3]
    msgs3 = [s[2] for s in signers3]
    sig3_bytes = serialize_sig(sig3)
    writer.writerow((idx, format_list(pks3), format_list(msgs3),
                     sig3_bytes.hex().upper(), "TRUE",
                     "Three-signer valid aggregate"))
    idx += 1

    wrong_msgs = [msgs[0], bytes([0xff] * 32)]
    writer.writerow((idx, format_list(pks), format_list(wrong_msgs),
                     sig_bytes.hex().upper(), "FALSE",
                     "Wrong message for second signer"))
    idx += 1

    writer.writerow((idx, format_list([pks[1], pks[0]]), format_list(msgs),
                     sig_bytes.hex().upper(), "FALSE",
                     "Pubkey order swapped"))
    idx += 1

    writer.writerow((idx, format_list([pks[0]]), format_list([msgs[0]]),
                     sig_bytes.hex().upper(), "FALSE",
                     "Dropped second signer"))
    idx += 1

    s_int = int_from_bytes(sig_bytes[32:64])
    tampered = sig_bytes[:32] + bytes_from_int(s_int ^ 1)
    writer.writerow((idx, format_list(pks), format_list(msgs),
                     tampered.hex().upper(), "FALSE",
                     "Tampered s (bit flip)"))
    idx += 1

    s_zero = sig_bytes[:32] + bytes(32)
    writer.writerow((idx, format_list(pks), format_list(msgs),
                     s_zero.hex().upper(), "FALSE",
                     "s = 0 (in range, wrong)"))
    idx += 1

    s_eq_n = sig_bytes[:32] + bytes_from_int(n)
    writer.writerow((idx, format_list(pks), format_list(msgs),
                     s_eq_n.hex().upper(), "FALSE",
                     "s = n (out of range)"))
    idx += 1

    s_max = sig_bytes[:32] + bytes([0xff] * 32)
    writer.writerow((idx, format_list(pks), format_list(msgs),
                     s_max.hex().upper(), "FALSE",
                     "s = 2^256 - 1"))
    idx += 1

    def find_off_curve_x() -> bytes:
        for i in range(1, 256):
            cand = bytes([i] * 32)
            try:
                GE.from_bytes_xonly(cand)
            except Exception:
                return cand
        raise RuntimeError("could not find an off-curve x")

    off_curve = find_off_curve_x()

    bad_R_sig = off_curve + sig_bytes[32:64]
    writer.writerow((idx, format_list(pks), format_list(msgs),
                     bad_R_sig.hex().upper(), "FALSE",
                     "R x-coord not on curve"))
    idx += 1

    writer.writerow((idx, format_list([off_curve, pks[1]]), format_list(msgs),
                     sig_bytes.hex().upper(), "FALSE",
                     "Public key not on curve"))
    idx += 1

    writer.writerow((idx, format_list(pks), format_list(msgs),
                     sig_bytes[:-1].hex().upper(), "FALSE",
                     "Signature too short"))
    idx += 1

    writer.writerow((idx, format_list(pks), format_list(msgs),
                     (sig_bytes + b"\x00").hex().upper(), "FALSE",
                     "Signature too long"))
    idx += 1


def gen_partial_sig_verify_vectors(f):
    writer = csv.writer(f)
    writer.writerow((
        "index", "signer_index", "psig", "aggnonce",
        "pubkeys", "messages", "pubnonces",
        "expected_result", "comment",
    ))

    signers = [make_signer(i) for i in range(2)]
    aggnonce, psigs, _ = sign_session(signers)
    pks_hex = format_list([serialize_pk(s[1]) for s in signers])
    msgs_hex = format_list([s[2] for s in signers])
    pubnonces_hex = format_list([serialize_pubnonce(s[4]) for s in signers])
    aggnonce_hex = serialize_pubnonce(aggnonce).hex().upper()

    def write_row(idx, signer_index, psig_bytes, expected, comment):
        writer.writerow((
            idx, signer_index, psig_bytes.hex().upper(), aggnonce_hex,
            pks_hex, msgs_hex, pubnonces_hex,
            expected, comment,
        ))

    idx = 0
    write_row(idx, 0, bytes_from_int(psigs[0]), "TRUE", "Honest partial sig (signer 0)")
    idx += 1
    write_row(idx, 1, bytes_from_int(psigs[1]), "TRUE", "Honest partial sig (signer 1)")
    idx += 1
    write_row(idx, 1, bytes_from_int(psigs[0]), "FALSE",
              "Honest psig verified at the wrong signer_index")
    idx += 1
    write_row(idx, 0, bytes_from_int(psigs[0] ^ 1), "FALSE",
              "Tampered partial sig (bit flip)")
    idx += 1
    write_row(idx, 0, bytes(32), "FALSE", "psig = 0 (in range, wrong)")
    idx += 1
    write_row(idx, 0, bytes_from_int(n), "FALSE", "psig = n (out of range)")


if __name__ == "__main__":
    os.makedirs(VECTORS_DIR, exist_ok=True)

    print(f"Generating {SIGN_VECTORS}")
    with open(SIGN_VECTORS, "w", newline="", encoding="utf-8") as f:
        gen_sign_vectors(f)

    print(f"Generating {VERIFY_VECTORS}")
    with open(VERIFY_VECTORS, "w", newline="", encoding="utf-8") as f:
        gen_verify_vectors(f)

    print(f"Generating {PARTIAL_SIG_VERIFY_VECTORS}")
    with open(PARTIAL_SIG_VERIFY_VECTORS, "w", newline="", encoding="utf-8") as f:
        gen_partial_sig_verify_vectors(f)

    print("Done.")
