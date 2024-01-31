import os

from halfagg import (
    Aggregate,
    IncAggregate,
    VerifyAggregate,
    hashHalfAgg_randomizer,
)
from bip340_reference import (
    bytes_from_int,
    int_from_bytes,
    n,
    pubkey_gen,
    schnorr_sign,
    schnorr_verify,
)


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
