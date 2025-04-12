from typing import (
    List,
    Tuple,
)
import secrets
import random

from bip340_reference import (
    bytes_from_point,
    G,
    int_from_bytes,
    is_infinite,
    n,
    Point,
    point_add,
    point_mul,
    tagged_hash,
)


# Public Key of signer
# "pk"/"X"
PublicKey = Point
# Private Key of signer
# "sk"
SecretKey = int
# Message of signer
# "m"
Message = bytes
# Schnorr signature
# "sig"
Signature = Tuple[Point, int]
# Secret nonce
# "r"/"r_i"
SecretNonce = int
# Public nonce
# "R"/"R_i"
PublicNonce = Point
# Signer output containing their R1 and R2
# "out_i"
SignerOutput = Tuple[PublicNonce, PublicNonce]
# Signer state containing their r1, r2 and R2
# "st_i"
SignerState = Tuple[SecretNonce, SecretNonce, PublicNonce]
# Context
# "ctx"
Context = List[Tuple[PublicKey, Message, PublicNonce, PublicNonce]]
# List of the signers public keys and messages
SignersList = List[Tuple[PublicKey, Message]]
# Nonce hash
# "b"
NonceHash = int
# Signer challenge
# "c_i"
SignerChallenge = int


def Sign() -> Tuple[SignerOutput, SignerState]:
    r1_i = secrets.randbelow(n-1) + 1
    r2_i = secrets.randbelow(n-1) + 1
    R1_i = point_mul(G, r1_i)
    R2_i = point_mul(G, r2_i)

    out_i = (R1_i, R2_i)
    st_i = (r1_i, r2_i, R2_i)

    return (out_i, st_i)


def hash_nonce(ctx: Context) -> NonceHash:
    """ Hnon """
    R1, R2, signer_triples = ctx

    data = bytes_from_point(R1) + bytes_from_point(R2)
    for X_i, m_i, R2_i in signer_triples:
        data += bytes_from_point(X_i) + m_i + bytes_from_point(R2_i)

    hash_bytes = tagged_hash("FullAgg/nonce", data)
    return int_from_bytes(hash_bytes) % n


def Coord(signer_inputs: List[Tuple[PublicKey, Message, SignerOutput]]) -> Tuple[Context, PublicNonce]:
    R1_list = [out[0] for _, _, out in signer_inputs]
    R2_list = [out[1] for _, _, out in signer_inputs]

    R1 = R1_list[0]
    for R1_i in R1_list[1:]:
        R1 = point_add(R1, R1_i)

    R2 = R2_list[0]
    for R2_i in R2_list[1:]:
        R2 = point_add(R2, R2_i)

    signer_triples = [(pk, msg, out[1]) for pk, msg, out in signer_inputs]
    ctx = (R1, R2, signer_triples)

    b = hash_nonce(ctx)
    R = point_add(R1, point_mul(R2, b))

    return (ctx, R)


def hash_sig(L: SignersList, R: PublicNonce, X: PublicKey, m: Message) -> SignerChallenge:
    """ Hsig """
    data = bytes_from_point(R)
    for X_i, m_i in L:
        data += bytes_from_point(X_i) + m_i
    data += bytes_from_point(X) + m

    hash_bytes = tagged_hash("FullAgg/sig", data)
    return int_from_bytes(hash_bytes) % n


def Sign2(sk_i: SecretKey, st_i: SignerState, m_i: Message, ctx: Context) -> int:
    """ Sign' """
    r1_i, r2_i, R2_i = st_i
    R1, R2, signer_triples = ctx

    X_i = point_mul(G, sk_i)

    U = set()
    for j, (_, _, R2_j) in enumerate(signer_triples):
        if R2_j == R2_i:
            U.add(j)

    assert len(U) == 1, "This signers' R2 does not appear exactly once in the context"

    u = next(iter(U))
    X_u, m_u, _ = signer_triples[u]
    assert X_u == X_i and m_u == m_i, "Public key or message doesn't match"

    L = [(X_j, m_j) for X_j, m_j, _ in signer_triples]
    b = hash_nonce(ctx)
    R = point_add(R1, point_mul(R2, b))

    c_i = hash_sig(L, R, X_i, m_i)
    s = (r1_i + b * r2_i + c_i * sk_i) % n

    return s


def Coord2(st: PublicNonce, challenges: List[SignerChallenge]) -> Signature:
    """ Coord' """
    R = st

    s = 0
    for s_i in challenges:
        s = (s + s_i) % n

    return (R, s)


def Ver(L: SignersList, sig: Signature) -> bool:
    R, s = sig

    for X_i, _ in L:
        assert not is_infinite(X_i), "Public key is the point at infinity"

    lhs = point_mul(G, s)

    C = None
    for X_i, m_i in L:
        c_i = hash_sig(L, R, X_i, m_i)
        C_i = point_mul(X_i, c_i)
        if C is None:
            C = C_i
        else:
            C = point_add(C, C_i)

    rhs = point_add(R, C)
    return lhs == rhs


def test_fullagg_scheme():
    sk1, sk2, sk3 = secrets.randbelow(n-1) + 1, secrets.randbelow(n-1) + 1, secrets.randbelow(n-1) + 1
    pk1, pk2, pk3 = point_mul(G, sk1), point_mul(G, sk2), point_mul(G, sk3)
    m1, m2, m3 = b"jonas", b"tim", b"yannick"

    # First signing round
    out1, st1 = Sign()
    out2, st2 = Sign()
    out3, st3 = Sign()

    # First coordinator round
    signer_triples = [(pk1, m1, out1), (pk2, m2, out2), (pk3, m3, out3)]
    ctx, R = Coord(signer_triples)

    # Second signing round
    s1 = Sign2(sk1, st1, m1, ctx)
    s2 = Sign2(sk2, st2, m2, ctx)
    s3 = Sign2(sk3, st3, m3, ctx)

    # Second coordinator round
    sig = Coord2(R, [s1, s2, s3])

    # Verification success
    L = [(pk1, m1), (pk2, m2), (pk3, m3)]
    valid = Ver(L, sig)
    assert valid

    # Verification failures
    fail_vectors = [
        ([(pk1, m1), (pk1, m2), (pk3, m3)], sig),  # pk2 wrong
        ([(pk1, m1), (pk1, m2), (pk3, b'')], sig),  # m3 wrong
        ([(pk2, m2), (pk1, m1), (pk3, m3)], sig),  # L order changed
        ([(pk1, m1), (pk3, m3)], sig),  # L incomplete
        ([(pk1, m1), (pk2, m2), (pk3, m3)], (point_mul(G, random.randint(1, n-1)), random.randint(1, n-1))),  # bogus sig
    ]

    for L, sig in fail_vectors:
        valid = Ver(L, sig)
        assert not valid

    print("Looks like it works!")


if __name__ == "__main__":
    test_fullagg_scheme()
