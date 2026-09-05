"""Reference implementation of Full Aggregation of BIP 340 Signatures
per the DahLIAS interactive signing protocol.

WARNING: This implementation is for demonstration purposes only and is not
optimized for production use.
"""

from typing import List, Tuple, Optional
import secrets

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import int_from_bytes, tagged_hash

n = GE.ORDER


#
# Helpers
#

def has_even_y(P: GE) -> bool:
    assert not P.infinity
    return int(P.y) % 2 == 0


def cbytes(P: GE) -> bytes:
    assert not P.infinity
    return (b'\x02' if has_even_y(P) else b'\x03') + P.to_bytes_xonly()


def xbytes(P: GE) -> bytes:
    return P.to_bytes_xonly()


#
# Key Generation and Tweaking
#

def KeyGen() -> Tuple[Scalar, GE]:
    sk = Scalar(secrets.randbelow(n - 1) + 1)
    return sk, sk * G


def TweakSK(sk: Scalar, t: Scalar) -> Scalar:
    return sk + t


def TweakPK(pk: GE, t: Scalar) -> GE:
    return pk + t * G


#
# Nonce Generation and Aggregation
#

def NonceGen(sk: Optional[Scalar] = None,
             extra_in: bytes = b'') -> Tuple[Tuple[Scalar, Scalar], Tuple[GE, GE]]:
    rand_prime = secrets.token_bytes(32)
    if sk is not None:
        sk_bytes = int(sk).to_bytes(32, 'big')
        rand = bytes(a ^ b for a, b in zip(sk_bytes, tagged_hash("FullAgg/aux", rand_prime)))
    else:
        rand = rand_prime
    r1 = int_from_bytes(tagged_hash("FullAgg/nonce", rand + extra_in + b'\x00')) % n
    r2 = int_from_bytes(tagged_hash("FullAgg/nonce", rand + extra_in + b'\x01')) % n
    assert r1 != 0 and r2 != 0
    R1, R2 = r1 * G, r2 * G
    return (Scalar(r1), Scalar(r2)), (R1, R2)


def NonceAgg(pubnonces: List[Tuple[GE, GE]]) -> Tuple[GE, GE]:
    u = len(pubnonces)
    R1, R2 = pubnonces[0]
    for i in range(1, u):
        R1 = R1 + pubnonces[i][0]
        R2 = R2 + pubnonces[i][1]
    assert not R1.infinity and not R2.infinity
    return R1, R2


#
# Session Values
#

def GetSessionValues(aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
                     pubnonces: List[Tuple[GE, GE]]) -> Tuple[GE, int]:
    R1, R2 = aggnonce
    u = len(pks)
    nonce_data = cbytes(R1) + cbytes(R2)
    for i in range(u):
        nonce_data += xbytes(pks[i]) + msgs[i] + cbytes(pubnonces[i][1])
    b = int_from_bytes(tagged_hash("FullAgg/nonce", nonce_data)) % n
    R = R1 + b * R2
    assert not R.infinity
    return R, b


#
# Signing
#

def Sign(secnonce: Tuple[Scalar, Scalar], sk: Scalar, m: bytes,
         aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
         pubnonces: List[Tuple[GE, GE]]) -> int:
    r1, r2 = int(secnonce[0]), int(secnonce[1])
    assert r1 != 0 and r2 != 0
    d = int(sk)
    assert d != 0
    P = sk * G
    R2_local = r2 * G

    # Index lookup and uniqueness check
    matches = [j for j in range(len(pubnonces)) if pubnonces[j][1] == R2_local]
    assert len(matches) == 1
    j = matches[0]
    assert pks[j] == P and msgs[j] == m

    R, b = GetSessionValues(aggnonce, pks, msgs, pubnonces)
    e = 1 if has_even_y(R) else n - 1
    d_prime = d if has_even_y(P) else n - d

    L = b''
    for i in range(len(pks)):
        L += xbytes(pks[i]) + msgs[i]
    c_j = int_from_bytes(tagged_hash("FullAgg/sig", L + xbytes(R) + xbytes(pks[j]) + msgs[j])) % n
    s_j = (e * (r1 + b * r2) + c_j * d_prime) % n
    return s_j


#
# Aggregation
#

def SigAgg(aggnonce: Tuple[GE, GE], pks: List[GE], msgs: List[bytes],
           pubnonces: List[Tuple[GE, GE]], psigs: List[int]) -> Tuple[GE, int]:
    R, _ = GetSessionValues(aggnonce, pks, msgs, pubnonces)
    for s_i in psigs:
        assert s_i < n
    s = sum(psigs) % n
    return R, s


#
# Partial Signature Verification
#

def PartialSigVerify(psig: int, aggnonce: Tuple[GE, GE], pks: List[GE],
                     msgs: List[bytes], pubnonces: List[Tuple[GE, GE]],
                     signer_index: int) -> bool:
    i = signer_index
    assert psig < n
    R1_i, R2_i = pubnonces[i]
    P_i = GE.lift_x(int_from_bytes(xbytes(pks[i])))
    assert P_i is not None
    R, b = GetSessionValues(aggnonce, pks, msgs, pubnonces)
    e = 1 if has_even_y(R) else n - 1

    L = b''
    for k in range(len(pks)):
        L += xbytes(pks[k]) + msgs[k]
    c_i = int_from_bytes(tagged_hash("FullAgg/sig", L + xbytes(R) + xbytes(pks[i]) + msgs[i])) % n
    R_eff_i = R1_i + b * R2_i
    return psig * G == e * R_eff_i + c_i * P_i


#
# Aggregate Signature Verification
#

def Verify(pks: List[GE], msgs: List[bytes], sig: Tuple[GE, int]) -> bool:
    R_point, s = sig
    u = len(pks)
    if s >= n:
        return False
    R = GE.lift_x(int_from_bytes(xbytes(R_point)))
    if R is None:
        return False
    Ps = []
    for i in range(u):
        if pks[i].infinity:
            return False
        P_i = GE.lift_x(int_from_bytes(xbytes(pks[i])))
        if P_i is None:
            return False
        Ps.append(P_i)

    L = b''
    for i in range(u):
        L += xbytes(pks[i]) + msgs[i]
    rhs = R
    for i in range(u):
        c_i = int_from_bytes(tagged_hash("FullAgg/sig", L + xbytes(R_point) + xbytes(pks[i]) + msgs[i])) % n
        rhs = rhs + c_i * Ps[i]
    return s * G == rhs


#
# Tests
#

if __name__ == "__main__":
    # Key generation
    sk1, pk1 = KeyGen()
    sk2, pk2 = KeyGen()
    sk3, pk3 = KeyGen()
    m1 = tagged_hash("message", b"first")
    m2 = tagged_hash("message", b"second")
    m3 = tagged_hash("message", b"third")

    sks = [sk1, sk2, sk3]
    pks = [pk1, pk2, pk3]
    msgs = [m1, m2, m3]

    # First round: nonce generation
    secnonces, pubnonces = [], []
    for sk in sks:
        sec, pub = NonceGen(sk=sk)
        secnonces.append(sec)
        pubnonces.append(pub)

    # Nonce aggregation
    aggnonce = NonceAgg(pubnonces)

    # Second round: signing
    psigs = []
    for i in range(3):
        psig = Sign(secnonces[i], sks[i], msgs[i], aggnonce, pks, msgs, pubnonces)
        psigs.append(psig)

    # Partial signature verification
    for i in range(3):
        assert PartialSigVerify(psigs[i], aggnonce, pks, msgs, pubnonces, i)

    # Signature aggregation
    sig = SigAgg(aggnonce, pks, msgs, pubnonces, psigs)

    # Aggregate signature verification
    assert Verify(pks, msgs, sig)

    # Tweaked keys
    tweaks = [Scalar(secrets.randbelow(n - 1) + 1) for _ in range(3)]
    tweaked_sks = [TweakSK(sks[i], tweaks[i]) for i in range(3)]
    tweaked_pks = [TweakPK(pks[i], tweaks[i]) for i in range(3)]
    tweaked_msgs = [tagged_hash("message", bytes([i])) for i in range(3, 6)]

    all_sks = sks + tweaked_sks
    all_pks = pks + tweaked_pks
    all_msgs = msgs + tweaked_msgs

    secnonces2, pubnonces2 = [], []
    for sk in all_sks:
        sec, pub = NonceGen(sk=sk)
        secnonces2.append(sec)
        pubnonces2.append(pub)
    aggnonce2 = NonceAgg(pubnonces2)
    psigs2 = [Sign(secnonces2[i], all_sks[i], all_msgs[i], aggnonce2,
                   all_pks, all_msgs, pubnonces2) for i in range(6)]
    for i in range(6):
        assert PartialSigVerify(psigs2[i], aggnonce2, all_pks, all_msgs, pubnonces2, i)
    sig2 = SigAgg(aggnonce2, all_pks, all_msgs, pubnonces2, psigs2)
    assert Verify(all_pks, all_msgs, sig2)

    # Failure: wrong key order
    assert not Verify([pk2, pk1, pk3], msgs, sig)
    # Failure: bogus signature
    assert not Verify(pks, msgs, (Scalar(42) * G, 42))
    # Failure: incomplete list
    assert not Verify(pks[:2], msgs[:2], sig)

    print("All tests passed.")
