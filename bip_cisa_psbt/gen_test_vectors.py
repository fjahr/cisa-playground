#!/usr/bin/env python3
"""
Test vector generator for the CISA PSBT fields BIP.

Writes test-vectors.json next to this file and prints the test vector
section of the BIP in MediaWiki markup.

The valid vectors walk through the PSBT workflow of a half-aggregation
group, a full-aggregation group, and a transaction with both groups,
from the aggregation modes to the finalized PSBT and the extracted
transaction. Every extracted transaction is checked against the witness
version 2 key path rules of BIP 460 before it is written. The invalid
vectors are PSBTs with malformed CISA fields.

The transaction, signature message, and signing helpers are adapted from
the BIP 460 test vector generator. halfagg.py and fullagg.py are the
reference implementations of BIP 458 and BIP 459 as vendored by BIP 460.

WARNING: All keys and nonces in this file are deterministic and publicly
known. They exist only to make the vectors reproducible. Nonces must be
fresh uniform randomness in any real signing session.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.bip340 import schnorr_sign, schnorr_verify
from secp256k1lab.util import tagged_hash

import halfagg
import fullagg

MARKER_HALFAGG = 0xBC
MARKER_FULLAGG = 0xBD
MODE_OPTOUT = 0x00
SIGHASH_EPOCH = 0x01

SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80

AUX_ZERO = bytes(32)

PSBT_MAGIC = b"psbt\xff"
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_CISA_MODE = 0x21
PSBT_IN_CISA_HALFAGG_SIG = 0x22
PSBT_IN_CISA_FULLAGG_PUB_NONCE = 0x23
PSBT_IN_CISA_FULLAGG_PARTIAL_SIG = 0x24

CISA_VALUE_LENGTHS = {
    PSBT_IN_CISA_MODE: (1,),
    PSBT_IN_CISA_HALFAGG_SIG: (64, 65),
    PSBT_IN_CISA_FULLAGG_PUB_NONCE: (66,),
    PSBT_IN_CISA_FULLAGG_PARTIAL_SIG: (32,),
}


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def sha256(b):
    return hashlib.sha256(b).digest()


def ser_compact_size(n):
    if n < 253:
        return bytes([n])
    if n < 0x10000:
        return b"\xfd" + n.to_bytes(2, "little")
    if n < 0x100000000:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def read_compact_size(b, pos):
    first = b[pos]
    if first < 253:
        return first, pos + 1
    if first == 0xFD:
        return int.from_bytes(b[pos + 1:pos + 3], "little"), pos + 3
    if first == 0xFE:
        return int.from_bytes(b[pos + 1:pos + 5], "little"), pos + 5
    return int.from_bytes(b[pos + 1:pos + 9], "little"), pos + 9


def ser_witness(stack):
    return ser_compact_size(len(stack)) + b"".join(
        ser_compact_size(len(element)) + element for element in stack
    )


class TxIn:
    def __init__(self, txid, vout, sequence=0xFFFFFFFF):
        self.txid = txid
        self.vout = vout
        self.sequence = sequence

    def outpoint(self):
        return self.txid + self.vout.to_bytes(4, "little")


class TxOut:
    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def serialize(self):
        return self.amount.to_bytes(8, "little") + ser_compact_size(
            len(self.script_pubkey)
        ) + self.script_pubkey


class Tx:
    def __init__(self, vin, vout, version=2, locktime=0):
        self.version = version
        self.locktime = locktime
        self.vin = vin
        self.vout = vout
        self.witnesses = [[] for _ in vin]

    def serialize_unsigned(self):
        out = self.version.to_bytes(4, "little")
        out += ser_compact_size(len(self.vin))
        for txin in self.vin:
            out += txin.outpoint() + b"\x00" + txin.sequence.to_bytes(4, "little")
        out += ser_compact_size(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        out += self.locktime.to_bytes(4, "little")
        return out

    def serialize_signed(self):
        out = self.version.to_bytes(4, "little")
        out += b"\x00\x01"
        out += ser_compact_size(len(self.vin))
        for txin in self.vin:
            out += txin.outpoint() + b"\x00" + txin.sequence.to_bytes(4, "little")
        out += ser_compact_size(len(self.vout))
        for txout in self.vout:
            out += txout.serialize()
        for witness in self.witnesses:
            out += ser_witness(witness)
        out += self.locktime.to_bytes(4, "little")
        return out


# ---------------------------------------------------------------------------
# PSBT serialization and parsing (BIP 174)
# ---------------------------------------------------------------------------

def ser_map(entries):
    out = b""
    for (keytype, keydata), value in sorted(entries.items()):
        key = ser_compact_size(keytype) + keydata
        out += ser_compact_size(len(key)) + key
        out += ser_compact_size(len(value)) + value
    return out + b"\x00"


def ser_psbt(tx, inputs, outputs):
    out = PSBT_MAGIC
    out += ser_map({(PSBT_GLOBAL_UNSIGNED_TX, b""): tx.serialize_unsigned()})
    for entries in inputs:
        out += ser_map(entries)
    for entries in outputs:
        out += ser_map(entries)
    return out


def parse_map(b, pos):
    entries = {}
    while True:
        keylen, pos = read_compact_size(b, pos)
        if keylen == 0:
            return entries, pos
        key = b[pos:pos + keylen]
        pos += keylen
        keytype, offset = read_compact_size(key, 0)
        vallen, pos = read_compact_size(b, pos)
        value = b[pos:pos + vallen]
        pos += vallen
        entry = (keytype, key[offset:])
        if entry in entries:
            raise ValueError("duplicate key")
        entries[entry] = value


def count_tx_io(txbytes):
    pos = 4
    nin, pos = read_compact_size(txbytes, pos)
    for _ in range(nin):
        pos += 36
        scriptlen, pos = read_compact_size(txbytes, pos)
        pos += scriptlen + 4
    nout, pos = read_compact_size(txbytes, pos)
    for _ in range(nout):
        pos += 8
        scriptlen, pos = read_compact_size(txbytes, pos)
        pos += scriptlen
    assert pos + 4 == len(txbytes)
    return nin, nout


def parse_psbt(b):
    if b[:5] != PSBT_MAGIC:
        raise ValueError("invalid magic")
    globals_, pos = parse_map(b, 5)
    nin, nout = count_tx_io(globals_[(PSBT_GLOBAL_UNSIGNED_TX, b"")])
    inputs, outputs = [], []
    for _ in range(nin):
        entries, pos = parse_map(b, pos)
        inputs.append(entries)
    for _ in range(nout):
        entries, pos = parse_map(b, pos)
        outputs.append(entries)
    if pos != len(b):
        raise ValueError("trailing data")
    return globals_, inputs, outputs


def validate_cisa_fields(inputs):
    for entries in inputs:
        for (keytype, keydata), value in entries.items():
            if keytype not in CISA_VALUE_LENGTHS:
                continue
            if keydata:
                raise ValueError("unexpected key data")
            if len(value) not in CISA_VALUE_LENGTHS[keytype]:
                raise ValueError("invalid value length")
            if keytype == PSBT_IN_CISA_MODE and value[0] not in (MODE_OPTOUT, MARKER_HALFAGG, MARKER_FULLAGG):
                raise ValueError("undefined aggregation mode")


# ---------------------------------------------------------------------------
# Taproot style key derivation and signature messages
# ---------------------------------------------------------------------------

def tweak_keypair(seckey32):
    d0 = Scalar.from_bytes_checked(seckey32)
    P = d0 * G
    d = d0 if P.has_even_y() else -d0
    internal_pubkey = P.to_bytes_xonly()
    t = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal_pubkey))
    Q = (d + t) * G
    tweaked_seckey = (d + t).to_bytes()
    return internal_pubkey, tweaked_seckey, Q.to_bytes_xonly()


def v2_script_pubkey(output_key32):
    return bytes([0x52, 0x20]) + output_key32


def sigmsg_common(tx, spent_utxos, input_index, hash_type, ext_flag):
    """Compute SigMsg(hash_type, ext_flag) as defined in BIP 341, without annex."""
    anyonecanpay = bool(hash_type & SIGHASH_ANYONECANPAY)
    base_type = hash_type & 3
    msg = bytes([hash_type])
    msg += tx.version.to_bytes(4, "little")
    msg += tx.locktime.to_bytes(4, "little")
    if not anyonecanpay:
        msg += sha256(b"".join(txin.outpoint() for txin in tx.vin))
        msg += sha256(b"".join(u.amount.to_bytes(8, "little") for u in spent_utxos))
        msg += sha256(b"".join(
            ser_compact_size(len(u.script_pubkey)) + u.script_pubkey for u in spent_utxos
        ))
        msg += sha256(b"".join(txin.sequence.to_bytes(4, "little") for txin in tx.vin))
    if base_type not in (SIGHASH_NONE, SIGHASH_SINGLE):
        msg += sha256(b"".join(txout.serialize() for txout in tx.vout))
    msg += bytes([2 * ext_flag])
    if anyonecanpay:
        txin = tx.vin[input_index]
        utxo = spent_utxos[input_index]
        msg += txin.outpoint()
        msg += utxo.amount.to_bytes(8, "little")
        msg += ser_compact_size(len(utxo.script_pubkey)) + utxo.script_pubkey
        msg += txin.sequence.to_bytes(4, "little")
    else:
        msg += input_index.to_bytes(4, "little")
    if base_type == SIGHASH_SINGLE:
        msg += sha256(tx.vout[input_index].serialize())
    return msg


def sigmsg_v1(tx, spent_utxos, input_index, hash_type):
    """The unchanged BIP 341 key path message, hash_TapSighash(0x00 || SigMsg(hash_type, 0))."""
    msg = sigmsg_common(tx, spent_utxos, input_index, hash_type, 0)
    return tagged_hash("TapSighash", bytes([0x00]) + msg)


def sigmsg_v2(tx, spent_utxos, input_index, hash_type, agg_mode):
    """The aggregated message of BIP 460, hash_TapSighash(0x01 || agg_mode || SigMsg(hash_type, 0))."""
    msg = sigmsg_common(tx, spent_utxos, input_index, hash_type, 0)
    return tagged_hash("TapSighash", bytes([SIGHASH_EPOCH, agg_mode]) + msg)


def with_sighash(data, hash_type):
    if hash_type == SIGHASH_DEFAULT:
        return data
    return data + bytes([hash_type])


# ---------------------------------------------------------------------------
# Deterministic test data
# ---------------------------------------------------------------------------

def test_seckey(i):
    return tagged_hash("CISA-PSBT/test/key", bytes([i]))


def test_prevout_txid(i):
    return sha256(b"CISA-PSBT vector prevout " + bytes([i]))


def test_fullagg_secnonce(i):
    r1 = Scalar.from_bytes_wrapping(tagged_hash("CISA-PSBT/test/nonce", bytes([i, 0])))
    r2 = Scalar.from_bytes_wrapping(tagged_hash("CISA-PSBT/test/nonce", bytes([i, 1])))
    return (r1, r2), (r1 * G, r2 * G)


def ser_pubnonce(pubnonce):
    return fullagg.cbytes(pubnonce[0]) + fullagg.cbytes(pubnonce[1])


# ---------------------------------------------------------------------------
# Verification of a signed transaction against the BIP 460 key path rules
# ---------------------------------------------------------------------------

def verify_v2_transaction(tx, utxos):
    halfagg_group = []
    fullagg_group = []
    for idx, (witness, utxo) in enumerate(zip(tx.witnesses, utxos)):
        assert utxo.script_pubkey[:2] == b"\x52\x20" and len(witness) == 1
        element = witness[0]
        length = len(element)
        pk = utxo.script_pubkey[2:]
        if length == 64 or (length == 65 and element[-1] not in (MARKER_HALFAGG, MARKER_FULLAGG)):
            hash_type = element[64] if length == 65 else SIGHASH_DEFAULT
            assert length == 64 or hash_type != SIGHASH_DEFAULT
            assert schnorr_verify(sigmsg_v1(tx, utxos, idx, hash_type), pk, element[:64])
        elif length in (0, 1):
            hash_type = element[0] if length == 1 else SIGHASH_DEFAULT
            fullagg_group.append((idx, hash_type, None))
        elif length in (32, 33):
            hash_type = element[32] if length == 33 else SIGHASH_DEFAULT
            halfagg_group.append((idx, hash_type, element[:32], None))
        elif length in (65, 66) and element[-1] == MARKER_HALFAGG:
            hash_type = element[64] if length == 66 else SIGHASH_DEFAULT
            halfagg_group.append((idx, hash_type, element[:32], element[32:64]))
        elif length in (65, 66) and element[-1] == MARKER_FULLAGG:
            hash_type = element[64] if length == 66 else SIGHASH_DEFAULT
            fullagg_group.append((idx, hash_type, element[:64]))
        else:
            raise AssertionError("invalid witness element")
        if length in (1, 33, 66):
            assert hash_type != SIGHASH_DEFAULT
    if halfagg_group:
        assert halfagg_group[-1][3] is not None and all(s is None for _, _, _, s in halfagg_group[:-1])
        pm = [(utxos[idx].script_pubkey[2:], sigmsg_v2(tx, utxos, idx, ht, MARKER_HALFAGG))
              for idx, ht, _, _ in halfagg_group]
        aggsig = b"".join(share for _, _, share, _ in halfagg_group) + halfagg_group[-1][3]
        assert halfagg.VerifyAggregate(aggsig, pm)
    if fullagg_group:
        assert fullagg_group[-1][2] is not None and all(s is None for _, _, s in fullagg_group[:-1])
        pks = [GE.from_bytes_xonly(utxos[idx].script_pubkey[2:]) for idx, _, _ in fullagg_group]
        msgs = [sigmsg_v2(tx, utxos, idx, ht, MARKER_FULLAGG) for idx, ht, _ in fullagg_group]
        sig = fullagg_group[-1][2]
        R = GE.from_bytes_xonly(sig[:32])
        assert fullagg.Verify(pks, msgs, (R, Scalar.from_bytes_checked(sig[32:])))


# ---------------------------------------------------------------------------
# Workflow construction
# ---------------------------------------------------------------------------

class TestInput:
    def __init__(self, index, key_index, mode, hash_type):
        self.index = index
        self.internal_key, self.seckey, self.output_key = tweak_keypair(test_seckey(key_index))
        self.mode = mode
        self.hash_type = hash_type
        self.utxo = TxOut(1_000_000 * (index + 1), v2_script_pubkey(self.output_key))
        self.message = None
        self.signature = None
        self.secnonce = None
        self.pubnonce = None
        self.psig = None
        self.witness = None

    def base_entries(self):
        entries = {
            (PSBT_IN_WITNESS_UTXO, b""): self.utxo.serialize(),
            (PSBT_IN_TAP_INTERNAL_KEY, b""): self.internal_key,
            (PSBT_IN_CISA_MODE, b""): bytes([self.mode]),
        }
        if self.hash_type != SIGHASH_DEFAULT:
            entries[(PSBT_IN_SIGHASH_TYPE, b"")] = self.hash_type.to_bytes(4, "little")
        return entries


def make_tx(inputs):
    vin = [TxIn(test_prevout_txid(i.index), 0) for i in inputs]
    _, _, destination = tweak_keypair(test_seckey(99))
    vout = [TxOut(sum(i.utxo.amount for i in inputs) - 1000, v2_script_pubkey(destination))]
    return Tx(vin, vout)


def stage(tx, inputs, extra):
    """Serialize a PSBT stage, extra maps input index to added entries."""
    maps = []
    for i in inputs:
        entries = dict(i.base_entries())
        entries.update(extra.get(i.index, {}))
        maps.append(entries)
    return ser_psbt(tx, maps, [{} for _ in tx.vout])


def finalized_stage(tx, inputs):
    maps = [{
        (PSBT_IN_WITNESS_UTXO, b""): i.utxo.serialize(),
        (PSBT_IN_FINAL_SCRIPTWITNESS, b""): ser_witness(i.witness),
    } for i in inputs]
    return ser_psbt(tx, maps, [{} for _ in tx.vout])


def sign_optout(tx, utxos, i):
    i.message = sigmsg_v1(tx, utxos, i.index, i.hash_type)
    i.signature = schnorr_sign(i.message, i.seckey, AUX_ZERO)
    i.witness = [with_sighash(i.signature, i.hash_type)]
    return {(PSBT_IN_TAP_KEY_SIG, b""): with_sighash(i.signature, i.hash_type)}


def sign_halfagg(tx, utxos, i):
    i.message = sigmsg_v2(tx, utxos, i.index, i.hash_type, MARKER_HALFAGG)
    i.signature = schnorr_sign(i.message, i.seckey, AUX_ZERO)
    return {(PSBT_IN_CISA_HALFAGG_SIG, b""): with_sighash(i.signature, i.hash_type)}


def finalize_halfagg(group):
    triples = [(i.output_key, i.message, i.signature) for i in group]
    aggsig = halfagg.Aggregate(triples)
    assert halfagg.VerifyAggregate(aggsig, [(pk, m) for pk, m, _ in triples])
    for i in group[:-1]:
        i.witness = [with_sighash(i.signature[:32], i.hash_type)]
    final = group[-1]
    final.witness = [with_sighash(final.signature[:32] + aggsig[-32:], final.hash_type) + bytes([MARKER_HALFAGG])]
    return aggsig


def nonce_fullagg(tx, utxos, i):
    i.message = sigmsg_v2(tx, utxos, i.index, i.hash_type, MARKER_FULLAGG)
    i.secnonce, i.pubnonce = test_fullagg_secnonce(i.index)
    return {(PSBT_IN_CISA_FULLAGG_PUB_NONCE, b""): ser_pubnonce(i.pubnonce)}


def sign_fullagg(group, i):
    pks = [GE.from_bytes_xonly(g.output_key) for g in group]
    msgs = [g.message for g in group]
    pubnonces = [g.pubnonce for g in group]
    aggnonce = fullagg.NonceAgg(pubnonces)
    i.psig = fullagg.Sign(i.secnonce, Scalar.from_bytes_checked(i.seckey), i.message, aggnonce, pks, msgs, pubnonces)
    return {(PSBT_IN_CISA_FULLAGG_PARTIAL_SIG, b""): i.psig.to_bytes()}


def finalize_fullagg(group):
    pks = [GE.from_bytes_xonly(g.output_key) for g in group]
    msgs = [g.message for g in group]
    pubnonces = [g.pubnonce for g in group]
    aggnonce = fullagg.NonceAgg(pubnonces)
    for pos, g in enumerate(group):
        assert fullagg.PartialSigVerify(g.psig, pks, msgs, pubnonces, pos)
    R, s = fullagg.SigAgg(aggnonce, pks, msgs, pubnonces, [g.psig for g in group])
    assert fullagg.Verify(pks, msgs, (R, s))
    sig64 = R.to_bytes_xonly() + s.to_bytes()
    for g in group[:-1]:
        g.witness = [with_sighash(b"", g.hash_type)]
    final = group[-1]
    final.witness = [with_sighash(sig64, final.hash_type) + bytes([MARKER_FULLAGG])]
    return sig64


def psbt_entry(description, psbt_bytes):
    return {
        "description": description,
        "base64": base64.b64encode(psbt_bytes).decode(),
        "hex": psbt_bytes.hex(),
    }


def build_case(description, specs, script):
    """specs: list of (key_index, mode, hash_type). script: list of steps.
    A step is (description, action) with action one of
    ('optout', index), ('halfagg', index), ('nonce', index), ('psig', index)."""
    inputs = [TestInput(idx, key_index, mode, hash_type)
              for idx, (key_index, mode, hash_type) in enumerate(specs)]
    tx = make_tx(inputs)
    utxos = [i.utxo for i in inputs]
    halfagg_group = [i for i in inputs if i.mode == MARKER_HALFAGG]
    fullagg_group = [i for i in inputs if i.mode == MARKER_FULLAGG]
    extra = {}
    stages = [psbt_entry("With aggregation modes only", stage(tx, inputs, extra))]
    for step_description, actions in script:
        for action, index in actions:
            i = inputs[index]
            if action == "optout":
                added = sign_optout(tx, utxos, i)
            elif action == "halfagg":
                added = sign_halfagg(tx, utxos, i)
            elif action == "nonce":
                added = nonce_fullagg(tx, utxos, i)
            elif action == "psig":
                added = sign_fullagg(fullagg_group, i)
            extra.setdefault(index, {}).update(added)
        stages.append(psbt_entry(step_description, stage(tx, inputs, extra)))
    intermediary = {"messages": [i.message.hex() for i in inputs]}
    signatures = [i.signature.hex() if i.signature else None for i in inputs]
    if any(signatures):
        intermediary["signatures"] = signatures
    if halfagg_group:
        intermediary["halfaggAggregateSignature"] = finalize_halfagg(halfagg_group).hex()
    if fullagg_group:
        intermediary["secretNonces"] = [
            (i.secnonce[0].to_bytes() + i.secnonce[1].to_bytes()).hex() if i.secnonce else None for i in inputs]
        intermediary["publicNonces"] = [ser_pubnonce(i.pubnonce).hex() if i.pubnonce else None for i in inputs]
        intermediary["partialSignatures"] = [i.psig.to_bytes().hex() if i.psig else None for i in inputs]
        intermediary["fullaggAggregateSignature"] = finalize_fullagg(fullagg_group).hex()
    stages.append(psbt_entry("Finalized", finalized_stage(tx, inputs)))
    tx.witnesses = [i.witness for i in inputs]
    verify_v2_transaction(tx, utxos)
    for entry in stages:
        _, parsed_inputs, _ = parse_psbt(bytes.fromhex(entry["hex"]))
        validate_cisa_fields(parsed_inputs)
    return {
        "description": description,
        "given": {
            "inputs": [{
                "index": i.index,
                "tweakedSecretKey": i.seckey.hex(),
                "internalKey": i.internal_key.hex(),
                "outputKey": i.output_key.hex(),
                "amount": i.utxo.amount,
                "aggregationMode": f"{i.mode:02x}",
                "sighashType": f"{i.hash_type:02x}",
            } for i in inputs],
            "unsignedTx": tx.serialize_unsigned().hex(),
        },
        "intermediary": intermediary,
        "stages": stages,
        "expected": {"transaction": tx.serialize_signed().hex()},
    }


def build_valid():
    return [
        build_case(
            "Half-aggregation group with an opted-out input",
            [(1, MODE_OPTOUT, SIGHASH_DEFAULT), (2, MARKER_HALFAGG, SIGHASH_DEFAULT), (3, MARKER_HALFAGG, SIGHASH_ALL)],
            [
                ("With the signature of input 1", [("halfagg", 1)]),
                ("With all signatures", [("optout", 0), ("halfagg", 2)]),
            ],
        ),
        build_case(
            "Full-aggregation group with an opted-out input",
            [(4, MODE_OPTOUT, SIGHASH_DEFAULT), (5, MARKER_FULLAGG, SIGHASH_DEFAULT), (6, MARKER_FULLAGG, SIGHASH_ALL)],
            [
                ("With the public nonce of input 1", [("nonce", 1)]),
                ("With all public nonces", [("nonce", 2)]),
                ("With all partial signatures", [("optout", 0), ("psig", 1), ("psig", 2)]),
            ],
        ),
        build_case(
            "Half-aggregation and full-aggregation groups in one transaction",
            [(7, MARKER_HALFAGG, SIGHASH_DEFAULT), (8, MARKER_FULLAGG, SIGHASH_DEFAULT),
             (9, MARKER_HALFAGG, SIGHASH_DEFAULT), (10, MARKER_FULLAGG, SIGHASH_DEFAULT)],
            [
                ("With all public nonces", [("nonce", 1), ("nonce", 3)]),
                ("With all signatures", [("halfagg", 0), ("halfagg", 2), ("psig", 1), ("psig", 3)]),
            ],
        ),
    ]


def build_invalid(valid):
    """Malform the CISA fields of the first stage of the half-aggregation case."""
    globals_, inputs, outputs = parse_psbt(bytes.fromhex(valid[0]["stages"][0]["hex"]))
    tx_bytes = globals_[(PSBT_GLOBAL_UNSIGNED_TX, b"")]

    class RawTx:
        def serialize_unsigned(self):
            return tx_bytes

    def variant(description, index, entry, value, remove=None):
        maps = [dict(m) for m in inputs]
        if remove is not None:
            del maps[index][remove]
        maps[index][entry] = value
        psbt_bytes = ser_psbt(RawTx(), maps, outputs)
        try:
            validate_cisa_fields(parse_psbt(psbt_bytes)[1])
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected failure: {description}")
        return psbt_entry(description, psbt_bytes)

    sig = bytes.fromhex(valid[0]["intermediary"]["signatures"][1])
    nonce = bytes.fromhex(valid[1]["intermediary"]["publicNonces"][1])
    psig = bytes.fromhex(valid[1]["intermediary"]["partialSignatures"][1])
    mode = (PSBT_IN_CISA_MODE, b"")
    return [
        variant("PSBT_IN_CISA_MODE with key data", 1, (PSBT_IN_CISA_MODE, b"\x00"), bytes([MARKER_HALFAGG]), remove=mode),
        variant("PSBT_IN_CISA_MODE with invalid value length", 1, mode, bytes([MARKER_HALFAGG, 0x00])),
        variant("PSBT_IN_CISA_MODE with an undefined aggregation mode", 1, mode, b"\x01"),
        variant("PSBT_IN_CISA_HALFAGG_SIG with key data", 1, (PSBT_IN_CISA_HALFAGG_SIG, b"\x00"), sig),
        variant("PSBT_IN_CISA_HALFAGG_SIG with invalid value length", 1, (PSBT_IN_CISA_HALFAGG_SIG, b""), sig[:63]),
        variant("PSBT_IN_CISA_FULLAGG_PUB_NONCE with invalid value length", 1, (PSBT_IN_CISA_FULLAGG_PUB_NONCE, b""), nonce[:65]),
        variant("PSBT_IN_CISA_FULLAGG_PARTIAL_SIG with invalid value length", 1, (PSBT_IN_CISA_FULLAGG_PARTIAL_SIG, b""), psig[:31]),
    ]


def mediawiki(vectors):
    lines = ["The following are valid PSBTs.", "Each case lists the PSBT at every stage of the workflow, followed by the extracted transaction.", ""]
    for case in vectors["valid"]:
        lines.append(f"* Case: {case['description']}")
        for entry in case["stages"]:
            lines.append(f"** {entry['description']}")
            lines.append(f"*** Base64 String: <pre>{entry['base64']}</pre>")
        lines.append(f"** Extracted transaction: <pre>{case['expected']['transaction']}</pre>")
    lines += ["", "The following are invalid PSBTs.", ""]
    for entry in vectors["invalid"]:
        lines.append(f"* Case: <tt>{entry['description'].split(' ', 1)[0]}</tt> {entry['description'].split(' ', 1)[1]}")
        lines.append(f"** Base64 String: <pre>{entry['base64']}</pre>")
    return "\n".join(lines)


def main():
    valid = build_valid()
    vectors = {"valid": valid, "invalid": build_invalid(valid)}
    out_path = Path(__file__).resolve().parent / "test-vectors.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    print(mediawiki(vectors))


if __name__ == "__main__":
    main()
