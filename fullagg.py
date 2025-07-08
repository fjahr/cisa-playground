from typing import (
    List,
    NamedTuple,
    Tuple,
)
import secrets

from secp256k1lab.secp256k1 import (
    G,
    GE,
    Scalar,
)
from secp256k1lab.util import (
    int_from_bytes,
    tagged_hash,
)


# Group order
n = GE.ORDER
# Public Key of signer
# "pk"/"X"
PublicKey = GE
# Private Key of signer
# "sk"
SecretKey = Scalar
# Message of signer
# "m"
Message = bytes
# Schnorr signature
# "sig"
Signature = Tuple[GE, Scalar]
# Secret nonce
# "r"/"r_i"
SecretNonce = Scalar
# Public nonce
# "R"/"R_i"
PublicNonce = GE
# Coordinator state
# "st"
CoordinatorState = PublicNonce
# Signer output containing their R1 and R2
# "out_i"
class SignerOutput(NamedTuple):
    R1_i: PublicNonce
    R2_i: PublicNonce
# Signer state containing their r1, r2 and R2
# "st_i"
class SignerState(NamedTuple):
    r1_i: SecretNonce
    r2_i: SecretNonce
    R2_i: PublicNonce
# Context
# "ctx"
class ContextItem(NamedTuple):
    pk_i: PublicKey
    m_i: Message
    R2_i: PublicNonce
Context = Tuple[PublicNonce, PublicNonce, List[ContextItem]]
# List of the signers public keys and messages
class Signer(NamedTuple):
    pk_i: PublicKey
    m_i: Message
SignersList = List[Signer]
# Nonce hash
# "b"
NonceHash = Scalar
# Signer challenge
# "c_i"
SignerChallenge = Scalar
# Tweak
# "τ"
Tweak = Scalar
# Participants of the scheme
class Participant(NamedTuple):
    sk_i: SecretKey
    pk_i: PublicKey
    m_i: Message
ParticipantsList = List[Participant]


### Helper functions (not part of protocol)

def _rand_int() -> int:
    return secrets.randbelow(n-1) + 1

def _rand_scalar() -> Scalar:
    return Scalar(_rand_int())


### Hash functions
def hash_nonce(ctx: Context) -> NonceHash:
    """ (aka Hnon)
    A tagged hash of R1 || R2 || X_i || m_i || R2_i for all signers.
    For i signers we would have i concatenations of X_i || m_i || R2_i.
    """
    R1, R2, signer_triples = ctx

    data = R1.to_bytes_xonly() + R2.to_bytes_xonly()
    for X_i, m_i, R2_i in signer_triples:
        data += X_i.to_bytes_xonly() + m_i + R2_i.to_bytes_xonly()

    hash_bytes = tagged_hash("FullAgg/nonce", data)
    return int_from_bytes(hash_bytes) % n

def hash_sig(L: SignersList, R: PublicNonce, X: PublicKey, m: Message) -> SignerChallenge:
    """ (aka Hsig)
    Computes ci := Hsig(L, R, Xi, mi)
    """
    data = b''
    for X_i, m_i in L:
        data += X_i.to_bytes_xonly() + m_i
    data += R.to_bytes_xonly() + X.to_bytes_xonly() + m

    hash_bytes = tagged_hash("FullAgg/sig", data)
    return int_from_bytes(hash_bytes) % n


### Signer functions

def Sign() -> Tuple[SignerOutput, SignerState]:
    """Signer i generates their secret nonces r1_i and r2_i and computes the
    public nonces R1_i and R2_i from them. Then they store state st_i and send
    out_i to the coordinator."""

    r1_i = _rand_scalar()
    r2_i = _rand_scalar()
    R1_i = r1_i * G
    R2_i = r2_i * G

    out_i = (R1_i, R2_i)
    st_i = (r1_i, r2_i, R2_i)

    return (out_i, st_i)

def Sign2(sk_i: SecretKey, st_i: SignerState, m_i: Message, ctx: Context) -> int:
    """ (aka Sign') On input a message (m_i) and the coordinator first round
    output ctx, signer i, which has public key pk_i and state st_i, parses ctx
    and checks whether their own R2_i is only included once. If not (i.e., if
    it is missing or included multiple times), then it aborts the session.
    Otherwise, the signer also checks that their R2_i is also paired with their
    correct public key and message. If not, then it aborts the session.
    Then it extracts from ctx the public key/message pairs list (L) and computes
    R, the common nonce. It also calculates their challenge s_i and sends it to
    the coordinator."""

    X_i = sk_i * G
    r1_i, r2_i, R2_i = st_i
    R1, R2, signer_triples = ctx

    U = set()

    for j, (_, _, R2_j) in enumerate(signer_triples):
        if R2_j == R2_i:
            U.add(j)

    assert len(U) == 1, "This signers' R2 does not appear exactly once in the context"

    u = next(iter(U))
    X_u, m_u, _ = signer_triples[u]
    assert X_u == X_i and m_u == m_i, "Public key or message doesn't match"

    L = [(X_j, m_j) for X_j, m_j, _ in signer_triples]

    # if a signer is the Coordinator, they already know R 
    b = hash_nonce(ctx)
    R = R1 + (b * R2)

    c_i = hash_sig(L, R, X_i, m_i)
    br2_i = b * r2_i
    cx_i = c_i * sk_i
    s_i = int(r1_i + br2_i + cx_i) % n

    return s_i

def TweakSK(x: SecretKey, t: Tweak) -> SecretKey:
    return x + t

def TweakPK(X: PublicKey, t: Tweak) -> PublicKey:
    return X + t * G


### Coordinator functions

def Coord(signer_inputs: List[Tuple[PublicKey, Message, SignerOutput]]) -> Tuple[Context, CoordinatorState]:
    """Given all signers’ public key (pk), message (m) and first round output
    (out), the coordinator computes R1 and R2 by summing up all the signers'
    R1_i and R2_i. Then they define the context (ctx) and calculate the nonce
    hash (b). Using b they calculate R. The value R is the “common” nonce that
    will be used by all signers to derive their signing challenge. Then, the
    coordinator stores state (st) and sends ctx to all signers."""

    R1_list = [out[0] for _, _, out in signer_inputs]
    R2_list = [out[1] for _, _, out in signer_inputs]

    R1 = R1_list[0]
    for R1_i in R1_list[1:]:
        R1 = R1 + R1_i

    R2 = R2_list[0]
    for R2_i in R2_list[1:]:
        R2 = R2 + R2_i

    signer_triples = [(pk, msg, out[1]) for pk, msg, out in signer_inputs]
    ctx = (R1, R2, signer_triples)

    b = hash_nonce(ctx)
    R = R1 + (b * R2)

    st = R

    return (ctx, st)

def Coord2(st: PublicNonce, challenges: List[SignerChallenge]) -> Signature:
    """ (aka Coord') On input of all the signer challenges, the coordinator,
    calculates the common challenge s and returns it together with R as the
    finalized signature."""

    R = st

    s = 0
    for s_i in challenges:
        s = (s + s_i) % n

    return (R, s)


### Verification function (for anyone)

def Ver(L: SignersList, sig: Signature) -> bool:
    """ Given a list of public key/message pairs (L) and the signature, check
    the signature is valid."""

    R, s = sig

    for X_i, _ in L:
        assert not X_i.infinity, "Public key is the point at infinity"

    lhs = s * G

    C = None
    for X_i, m_i in L:
        c_i = hash_sig(L, R, X_i, m_i)
        C_i = c_i * X_i
        if C is None:
            C = C_i
        else:
            C = C + C_i

    rhs = R + C
    return lhs == rhs


### Full DahLIAS scheme

def DahLIAS(signers: ParticipantsList) -> Signature:
    """ Each signer generates a key pair and sends their public key
    and message to the Coordinator. For testing purposes, we include
    the signers private keys in the ParticipantsList input. """

    # First signing round
    first_round = []
    for _ in signers:
        out_i, st_i = Sign()
        first_round.append((out_i, st_i))

    # First coordinator round
    signer_triples = []
    for i, (_, pk_i, m_i) in enumerate(signers):
        out_i = first_round[i][0]
        # each signer runs (out_i, st_i) ← Sign() and sends out_i to the
        # coordinator (note that pk_i, out_i, and m_i can be sent separately
        # or all together to the coordinator);
        signer_triples.append((pk_i, m_i, out_i))

    ctx, st = Coord(signer_triples)

    # Second signing round
    out_list = []
    for i, (sk_i, _, m_i) in enumerate(signers):
        st_i = first_round[i][1]
        s_i = Sign2(sk_i, st_i, m_i, ctx)
        out_list.append(s_i)

    # Second coordinator round
    sig = Coord2(st, out_list)

    return sig


def KeyGen() -> Tuple[SecretKey, PublicKey]:
    """ Each signer generates a key pair (sk_i, pk_i) """
    sk = _rand_scalar()
    pk = sk * G
    return (sk, pk)


def test_fullagg_scheme():
    # Generate dummy keys and messages for testing purposes
    (sk1, pk1), (sk2, pk2), (sk3, pk3) = KeyGen(), KeyGen(), KeyGen()
    m1, m2, m3 = b"jonas", b"tim", b"yannick"

    # DahLIAS round
    # each signer runs (out_i, st_i) ← Sign() and sends out_i to the
    # coordinator (note that pk_i, out_i, and m_i can be sent separately
    # or all together to the coordinator);
    signers = [(sk1, pk1, m1), (sk2, pk2, m2), (sk3, pk3, m3)]

    sig = DahLIAS(signers)
    L = [(pk, m) for _, pk, m in signers]
    valid = Ver(L, sig)
    assert valid

    # DahLIAS round with tweaking
    tweaks = [_rand_scalar(), _rand_scalar(), _rand_scalar()]
    tweaked_signers = [(TweakSK(sk, tweaks[i]), TweakPK(pk, tweaks[i]), m) for i, (sk, pk, m) in enumerate(signers)]
    signers2 = signers + tweaked_signers
    sig2 = DahLIAS(signers2)
    L2 = [(pk, m) for _, pk, m in signers2]
    valid = Ver(L2, sig2)
    assert valid

    # Failure cases
    fail_vectors = [
        ([(pk1, m1), (pk1, m2), (pk3, m3)], sig),  # pk2 wrong
        ([(pk1, m1), (pk1, m2), (pk3, b'')], sig),  # m3 wrong
        ([(pk2, m2), (pk1, m1), (pk3, m3)], sig),  # L order changed
        ([(pk1, m1), (pk3, m3)], sig),  # L incomplete
        ([(pk1, m1), (pk2, m2), (pk3, m3)], (_rand_scalar() * G, _rand_scalar())),  # bogus sig
    ]

    for L, sig in fail_vectors:
        valid = Ver(L, sig)
        assert not valid

    print("Looks like it works!")


if __name__ == "__main__":
    test_fullagg_scheme()
