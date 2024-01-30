import os

from bip340_reference import (
    bytes_from_int,
    bytes_from_point,
    int_from_bytes,
    G,
    lift_x,
    n,
    point_add,
    point_mul,
    pubkey_gen,
    schnorr_sign,
    schnorr_verify,
    tagged_hash,
)


"""
A python implementation of Schnorr signature half-aggregation following the
specifiction at the BIP draft: https://github.com/BlockstreamResearch/cross-input-aggregation/blob/master/half-aggregation.mediawiki
"""


def Aggregate(pms):
    """
    Aggregates an array of triples (public key, message, signature) into a single aggregate signature.

    :param pms: An array of triples (public key, message, signature).
    :return: The aggregate signature.
    """

    # Let aggsig = bytes(0)
    aggsig = bytes([0] * 32)

    pm_aggd = []
    if not VerifyAggregate(aggsig, pm_aggd):
        raise

    # Return IncAggregate(aggsig, pms0..u-1); fail if that fails.
    return IncAggregate(aggsig, pm_aggd, pms)


# IncAggregate(aggsig, pm_aggd0..v-1, pms_to_agg0..u-1)
def IncAggregate(aggsig, pm_aggd, pms_to_agg):
    """
    Incrementally aggregates an additional array of triples (public key, message, signature)
    into an existing aggregate signature.

    :param aggsig: A byte array representing the aggregate signature.
    :param pm_aggd: An array of tuples (public key, message).
    :param pms_to_agg: An array of triples (public key, message, signature).
    :return: The new aggregate signature.
    """

    # Fail if v + u ≥ 2^16
    v = len(pm_aggd)
    u = len(pms_to_agg)
    if v + u >= 2**16:
        raise ValueError("v + u must be less than 2^16")

    # Fail if len(aggsig) ≠ 32 * (v + 1)
    if len(aggsig) != 32 * (v + 1):
        raise ValueError("Length of aggsig must be 32 * (v + 1)")

    r_values = []
    pmr_to_agg = []

    # For i = 0 .. v-1:
    for i in range(v):
        # Let (pki, mi) = pm_aggdi
        (pki, mi) = pm_aggd[i]

        # Let ri = aggsig[i⋅32:(i+1)⋅32]
        ri = aggsig[i * 32:(i + 1) * 32]
        r_values.append(ri)

        pmr_to_agg.append((pki, mi, ri))

    z_values = []
    s_values = []

    # For i = v .. v+u-1:
    for i in range(v, v + u):
        # Let (pki, mi, sigi) = pms_to_aggi-v
        (pki, mi, sigi) = pms_to_agg[i - v]

        # Let ri = sigi[0:32]
        ri = sigi[0:32]
        r_values.append(ri)

        # Let si = int(sigi[32:64]); fail if si ≥ n
        si = int_from_bytes(sigi[32:64])
        if si >= n:
            raise ValueError("si must be less than n")
        s_values.append(si)

        # If i = 0:
        #     Let zi = 1
        # Else:
        #     Let zi = int(hashHalfAgg/randomizer(r0 || pk0 || m0 || ... || ri || pki || mi)) mod n
        pmr_to_agg += [(pki, mi, sigi[0:32]) for (pki, mi, sigi) in pms_to_agg]
        z_values.append(hashHalfAgg_randomizer(pmr_to_agg, i))

    # Let s = int(aggsig[(v⋅32:(v+1)⋅32]) + zv⋅sv + ... + zv+u-1⋅sv+u-1 mod n
    s = int_from_bytes(aggsig[v * 32:(v + 1) * 32])
    if s >= n:
        raise ValueError("s must be less than n")

    for i in range(u):
        s = (s + z_values[i] * s_values[i]) % n

    # Return r0 || ... || rv+u-1 || bytes(s)
    return b''.join(r_values) + bytes_from_int(s)


# VerifyAggregate(aggsig, pm_aggd0..u-1)
def VerifyAggregate(aggsig, pm_aggd):
    """
    Verifies an aggregate signature against an array of public key and message tuples.

    :param aggsig: A byte array representing the aggregate signature.
    :param pm_aggd: An array of tuples (public key, message).
    :return: Boolean indicating whether the verification is successful.
    """

    # Fail if u ≥ 216
    u = len(pm_aggd)
    if u >= 2**16:
        raise ValueError("u must be less than 2^16")

    # Fail if len(aggsig) ≠ 32 * (u + 1)
    if len(aggsig) != 32 * (u + 1):
        raise ValueError("Length of aggsig must be 32 * (u + 1)")

    z_values = []
    R_values = []
    P_values = []
    e_values = []
    r_values = []

    # For i = 0 .. u-1:
    for i in range(u):
        # Let (pki, mi) = pm_aggdi
        (pki, mi) = pm_aggd[i]

        # Let Pi = lift_x(int(pki)); fail if that fails
        Pi = lift_x(int_from_bytes(pki))
        if Pi is None:
            return False
        P_values.append(Pi)

        # Let ri = aggsig[i⋅32:(i+1)⋅32]
        ri = aggsig[i * 32:(i + 1) * 32]
        # Let Ri = lift_x(int(ri)); fail if that fails
        Ri = lift_x(int_from_bytes(ri))
        if Ri is None:
            return False
        R_values.append(Ri)
        r_values.append(ri)

        # TODO: BIP-style
        # Let ei = int(hashBIP0340/challenge(bytes(ri) || pki || mi)) mod n
        # ei = int_from_bytes(hashBIP0340_challenge(ri, bytes_from_point(pki), mi)) % n
        # e_values.append(ei)

        # hacspec-style
        ei = int_from_bytes(hashBIP0340_challenge(ri, bytes_from_point(Pi), mi)) % n
        e_values.append(ei)

        # If i = 0:
        #     Let zi = 1
        # Else:
        #     Let zi = int(hashHalfAgg/randomizer(r0 || pk0 || m0 || ... || ri || pki || mi)) mod n
        pmr = [(pki, mi, ri) for (pki, mi), ri in zip(pm_aggd, r_values)]
        z_values.append(hashHalfAgg_randomizer(pmr, i))

    # Let s = int(aggsig[u⋅32:(u+1)⋅32]); fail if s ≥ n
    s = int_from_bytes(aggsig[u * 32:(u + 1) * 32])
    if s >= n:
        return False

    # Fail if s⋅G ≠ z0⋅(R0 + e0⋅P0) + ... + zu-1⋅(Ru-1 + eu-1⋅Pu-1)
    lhs = point_mul(G, s)
    rhs = None
    for i in range(u):
        rhsi = point_add(R_values[i], point_mul(P_values[i], e_values[i]))
        rhsi = point_mul(rhsi, z_values[i])
        rhs = point_add(rhs, rhsi)

    return lhs == rhs


def hashBIP0340_challenge(sig, pubkey, msg):
    return tagged_hash("BIP0340/challenge", sig + pubkey + msg)


def hashHalfAgg_randomizer(pmr, index):
    if index == 0:
        return 1

    random_input = bytes()
    for i in range(index + 1):
        (pki, mi, ri) = pmr[i]
        random_input += ri
        random_input += pki
        random_input += mi

    return int_from_bytes(tagged_hash("HalfAgg/randomizer", random_input)) % n


"""
Test cases from https://github.com/BlockstreamResearch/cross-input-aggregation/blob/master/hacspec-halfagg/tests/tests.rs
"""


def test_verify_vectors():
    vectors_raw = [
        ([],
         "0000000000000000000000000000000000000000000000000000000000000000"),
        ([("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "0202020202020202020202020202020202020202020202020202020202020202")],
         "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa80e066c34819936549ff49b6fd4d41edfc401a367b87ddd59fee38177961c225f"),
        ([("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "0202020202020202020202020202020202020202020202020202020202020202"),
          ("462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b", "0505050505050505050505050505050505050505050505050505050505050505")],
         "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa8a3afbdb45a6a34bf7c8c00f1b6d7e7d375b54540f13716c87b62e51e2f4f22ffbf8913ec53226a34892d60252a7052614ca79ae939986828d81d2311957371ad"),
    ]

    for v in vectors_raw:
        pm = [(bytes.fromhex(pk), bytes.fromhex(m)) for pk, m in v[0]]
        aggsig = bytes.fromhex(v[1])
        assert VerifyAggregate(aggsig, pm)

    print("Test verify vectors passed")


def test_aggregate_verify():
    pms = []
    aggsigs = []
    for i in range(3):
        sk = bytes([i + 1] * 32)
        msg = bytes([i + 2] * 32)
        rand = bytes([i + 3] * 32)
        sig = schnorr_sign(msg, sk, rand)
        pms.append((pubkey_gen(sk), msg, sig))
        aggsig = Aggregate(pms)
        aggsigs.append(aggsig)
        pm = [(x, y) for x, y, _ in pms]
        assert VerifyAggregate(aggsig, pm)

        for j in range(i):
            aggsig = IncAggregate(
                aggsigs[j],
                pm[:j + 1],
                pms[j + 1:i + 1]
            )
            assert VerifyAggregate(aggsig, pm)

    print("Test aggregate verify passed")


def test_aggregate_verify_strange():
    pms = []
    for i in range(2):
        sk = bytes([i + 1] * 32)
        msg = bytes([i + 2] * 32)
        aux_rand = bytes([i + 3] * 32)
        sig = schnorr_sign(msg, sk, aux_rand)
        pms.append((pubkey_gen(sk), msg, sig))

    aggsig = Aggregate(pms)
    pm = [(x, y) for x, y, _ in pms]
    assert VerifyAggregate(aggsig, pm)

    pmr = []
    z = []
    for i in range(2):
        pk, msg, sig = pms[i]
        pmr.append((pk, msg, sig[:32]))
        z.append(hashHalfAgg_randomizer(pmr, i))

    sagg = int_from_bytes(aggsig[64:96])
    s1 = int_from_bytes(os.urandom(32))
    s0 = ((sagg - z[1] * s1) * pow(z[0], -1, n)) % n
    pk0, msg0, sig0 = pms[0]
    pk1, msg1, sig1 = pms[1]
    sig0_invalid = sig0[:32] + bytes_from_int(s0) + sig0[32 + len(bytes_from_int(s0)):]
    sig1_invalid = sig1[:32] + bytes_from_int(s1) + sig1[32 + len(bytes_from_int(s1)):]
    assert not schnorr_verify(msg0, pk0, sig0_invalid)
    assert not schnorr_verify(msg1, pk1, sig1_invalid)

    pms_strange = [(pk0, msg0, sig0_invalid), (pk1, msg1, sig1_invalid)]
    aggsig_strange = Aggregate(pms_strange)
    pm_strange = [(x, y) for x, y, _ in pms_strange]
    assert VerifyAggregate(aggsig_strange, pm_strange)

    print("Test aggregate verify strange passed")


def test_edge_cases():
    empty_pm = []
    empty_pms = []
    aggsig = Aggregate(empty_pms)
    inc_aggsig = IncAggregate(aggsig, empty_pm, empty_pms)
    assert VerifyAggregate(aggsig, empty_pm)
    assert VerifyAggregate(inc_aggsig, empty_pm)

    aggsig = bytes([0] * 32)
    inc_aggsig = IncAggregate(aggsig, empty_pm, empty_pms)
    assert VerifyAggregate(aggsig, empty_pm)
    assert VerifyAggregate(inc_aggsig, empty_pm)

    try:
        aggsig = bytes([])
        IncAggregate(aggsig, empty_pm, empty_pms)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "Length of aggsig must be 32 * (v + 1)"

    try:
        VerifyAggregate(aggsig, empty_pm)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "Length of aggsig must be 32 * (u + 1)"

    big_pms = [(bytes([1] * 32), bytes([2] * 32), bytes([3] * 32)) for _ in range(0x10000)]
    try:
        Aggregate(big_pms)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "v + u must be less than 2^16"

    aggsig = bytes([0] * 32)
    big_pm = [(bytes([1] * 32), bytes([2] * 32)) for _ in range(0x10000)]
    try:
        IncAggregate(aggsig, big_pm, empty_pms)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "v + u must be less than 2^16"

    try:
        IncAggregate(aggsig, empty_pm, big_pms)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "v + u must be less than 2^16"

    try:
        VerifyAggregate(aggsig, big_pm)
        assert False  # This line should not be reached
    except ValueError as e:
        assert str(e) == "u must be less than 2^16"

    print("Test edge cases passed")


if __name__ == "__main__":
    test_verify_vectors()
    test_aggregate_verify()
    test_aggregate_verify_strange()
    test_edge_cases()
    print("All tests passed successfully!")
