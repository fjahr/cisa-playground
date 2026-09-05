#!/usr/bin/env python3
"""
Test vector generator for the cisa() output script descriptor BIP.

Writes test-vectors.json next to this file and prints the test vector
section of the BIP in MediaWiki markup.

The parser covers the subset of descriptor syntax used by the vectors:
cisa(KEY) and cisa(KEY,TREE) with pk(), pkh(), multi_a(), and
sortedmulti_a() leaves, and key expressions consisting of hex keys, WIF
keys, BIP 32 extended keys with derivation paths, and musig() aggregate
keys with BIP 328 derivation. It also parses tr() so the published
BIP 386, BIP 387, and BIP 390 vectors and one Bitcoin Core descriptor
test can check the shared derivation code before the cisa() vectors are
produced.

WARNING: All keys in this file are deterministic and publicly known.
They exist only to make the vectors reproducible.
"""

import hashlib
import hmac
import json
from pathlib import Path

from secp256k1lab.secp256k1 import G, GE, Scalar
from secp256k1lab.util import tagged_hash

n = GE.ORDER

WITNESS_VERSION = {"tr": 1, "cisa": 2}


# ---------------------------------------------------------------------------
# Base58 and BIP 32
# ---------------------------------------------------------------------------

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XPRV_VERSION = bytes.fromhex("0488ade4")
XPUB_VERSION = bytes.fromhex("0488b21e")
# BIP 328 chaincode for synthetic xpubs of MuSig2 aggregate keys
MUSIG_CHAINCODE = bytes.fromhex("868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965")


def hash160(b):
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()


def b58check_decode(s):
    num = 0
    for c in s:
        if c not in B58:
            raise ValueError("invalid base58 character")
        num = num * 58 + B58.index(c)
    data = num.to_bytes((num.bit_length() + 7) // 8, "big")
    data = b"\x00" * (len(s) - len(s.lstrip("1"))) + data
    payload, checksum = data[:-4], data[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError("invalid base58 checksum")
    return payload


class ExtKey:
    def __init__(self, seckey, pubkey, chaincode):
        self.seckey = seckey
        self.pubkey = pubkey
        self.chaincode = chaincode

    @classmethod
    def parse(cls, s):
        raw = b58check_decode(s)
        if len(raw) != 78:
            raise ValueError("invalid extended key length")
        version, chaincode, key = raw[:4], raw[13:45], raw[45:78]
        if version == XPRV_VERSION:
            if key[0] != 0:
                raise ValueError("invalid extended private key")
            k = int.from_bytes(key[1:], "big")
            if not 0 < k < n:
                raise ValueError("invalid extended private key")
            return cls(k, Scalar.from_int_checked(k) * G, chaincode)
        if version == XPUB_VERSION:
            return cls(None, GE.from_bytes_compressed(key), chaincode)
        raise ValueError("unknown extended key version")

    def child(self, index, hardened):
        i = index + (1 << 31 if hardened else 0)
        if hardened:
            if self.seckey is None:
                raise ValueError("hardened derivation from an extended public key")
            data = b"\x00" + self.seckey.to_bytes(32, "big")
        else:
            data = self.pubkey.to_bytes_compressed()
        digest = hmac.new(self.chaincode, data + i.to_bytes(4, "big"), hashlib.sha512).digest()
        il = int.from_bytes(digest[:32], "big")
        if il >= n:
            raise ValueError("invalid child key")
        if self.seckey is not None:
            k = (il + self.seckey) % n
            if k == 0:
                raise ValueError("invalid child key")
            return ExtKey(k, Scalar.from_int_checked(k) * G, digest[32:])
        P = Scalar.from_int_checked(il) * G + self.pubkey
        if P.infinity:
            raise ValueError("invalid child key")
        return ExtKey(None, P, digest[32:])

    def derive(self, steps, ranged, child_index):
        key = self
        for index, hardened in steps:
            key = key.child(index, hardened)
        if ranged is not None:
            key = key.child(child_index, ranged)
        return key.pubkey


# ---------------------------------------------------------------------------
# MuSig2 key aggregation (BIP 327 KeyAgg with the KeySort of BIP 390)
# ---------------------------------------------------------------------------

def key_agg(points):
    pubkeys = sorted(P.to_bytes_compressed() for P in points)
    L = tagged_hash("KeyAgg list", b"".join(pubkeys))
    pk2 = next((pk for pk in pubkeys if pk != pubkeys[0]), None)
    Q = GE()
    for pk in pubkeys:
        if pk == pk2:
            coeff = 1
        else:
            coeff = int.from_bytes(tagged_hash("KeyAgg coefficient", L + pk), "big") % n
        Q = Q + Scalar.from_int_checked(coeff) * GE.from_bytes_compressed(pk)
    if Q.infinity:
        raise ValueError("invalid aggregate key")
    return Q


# ---------------------------------------------------------------------------
# Key expressions
# ---------------------------------------------------------------------------

def is_hex(s):
    return len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)


def parse_step(step):
    hardened = step[-1:] in ("h", "H", "'")
    core = step[:-1] if hardened else step
    if core == "*":
        return None, hardened
    if not core.isdigit() or int(core) >= (1 << 31):
        raise ValueError("invalid derivation step")
    return int(core), hardened


def parse_path(parts):
    """Parse derivation steps after a key into (steps, ranged)."""
    steps, ranged = [], None
    for pos, step in enumerate(parts):
        index, hardened = parse_step(step)
        if index is None:
            if pos != len(parts) - 1:
                raise ValueError("ranged step must be the last step")
            ranged = hardened
        else:
            steps.append((index, hardened))
    return steps, ranged


class FixedKey:
    """A single public key. The point is None for x-only hex keys."""

    def __init__(self, xonly, point):
        self.xonly = xonly
        self.point = point

    is_ranged = False

    def derive_point(self, child_index):
        return self.point

    def derive(self, child_index):
        return self.xonly


class ExtendedKey:
    """An extended key with derivation steps and an optional ranged step."""

    def __init__(self, ext, steps, ranged):
        self.ext = ext
        self.steps = steps
        self.ranged = ranged

    @property
    def is_ranged(self):
        return self.ranged is not None

    def derive_point(self, child_index):
        return self.ext.derive(self.steps, self.ranged, child_index)

    def derive(self, child_index):
        return self.derive_point(child_index).to_bytes_xonly()


class MusigKey:
    """A musig() aggregate key with optional BIP 328 derivation."""

    def __init__(self, participants, steps, ranged):
        self.participants = participants
        self.steps = steps
        self.ranged = ranged

    @property
    def is_ranged(self):
        return self.ranged is not None or any(p.is_ranged for p in self.participants)

    def aggregate(self, child_index):
        points = [p.derive_point(child_index) for p in self.participants]
        if any(P is None for P in points):
            raise ValueError("musig() participants must be full public keys")
        return key_agg(points)

    def derive_point(self, child_index):
        if not self.steps and self.ranged is None:
            return self.aggregate(child_index)
        synthetic = ExtKey(None, self.aggregate(0), MUSIG_CHAINCODE)
        return synthetic.derive(self.steps, self.ranged, child_index)

    def derive(self, child_index):
        return self.derive_point(child_index).to_bytes_xonly()


def parse_key(s):
    if s.startswith("musig("):
        depth, end = 0, None
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end is None:
            raise ValueError("unterminated musig()")
        participants = [parse_key(a) for a in split_args(s[6:end])]
        if any(isinstance(p, MusigKey) for p in participants):
            raise ValueError("musig() cannot be nested")
        steps, ranged = parse_path(s[end + 1:].split("/")[1:])
        if ranged or any(h for _, h in steps):
            raise ValueError("musig() cannot have hardened derivation")
        if (steps or ranged is not None) and any(p.is_ranged for p in participants):
            raise ValueError("musig() with derivation cannot have ranged participants")
        return MusigKey(participants, steps, ranged)
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise ValueError("unterminated key origin")
        origin = s[1:end].split("/")
        if len(origin[0]) != 8 or not is_hex(origin[0]):
            raise ValueError("invalid key origin fingerprint")
        for step in origin[1:]:
            if parse_step(step)[0] is None:
                raise ValueError("invalid key origin path")
        s = s[end + 1:]
    if s.startswith(("xpub", "xprv")):
        parts = s.split("/")
        ext = ExtKey.parse(parts[0])
        steps, ranged = parse_path(parts[1:])
        if ext.seckey is None and (ranged or any(h for _, h in steps)):
            raise ValueError("hardened derivation from an extended public key")
        return ExtendedKey(ext, steps, ranged)
    if is_hex(s):
        raw = bytes.fromhex(s)
        if len(raw) == 32:
            GE.from_bytes_xonly(raw)
            return FixedKey(raw, None)
        if len(raw) == 33 and raw[0] in (2, 3):
            return FixedKey(raw[1:], GE.from_bytes_compressed(raw))
        if len(raw) == 65 and raw[0] == 4:
            raise ValueError("uncompressed public key")
        raise ValueError("invalid hex key")
    raw = b58check_decode(s)
    if raw[:1] != b"\x80":
        raise ValueError("invalid WIF key")
    if len(raw) == 34 and raw[-1] == 1:
        P = Scalar.from_bytes_checked(raw[1:33]) * G
        return FixedKey(P.to_bytes_xonly(), P)
    if len(raw) == 33:
        raise ValueError("uncompressed private key")
    raise ValueError("invalid WIF key")


# ---------------------------------------------------------------------------
# Script and tree expressions
# ---------------------------------------------------------------------------

OP_DUP = b"\x76"
OP_EQUALVERIFY = b"\x88"
OP_HASH160 = b"\xa9"
OP_CHECKSIG = b"\xac"
OP_CHECKSIGADD = b"\xba"
OP_NUMEQUAL = b"\x9c"
LEAF_VERSION = b"\xc0"


def split_args(s):
    args, depth, start = [], 0, 0
    for i, c in enumerate(s):
        if c in "({[<":
            depth += 1
        elif c in ")}]>":
            depth -= 1
        elif c == "," and depth == 0:
            args.append(s[start:i])
            start = i + 1
    args.append(s[start:])
    return args


def parse_call(s):
    open_ = s.find("(")
    if open_ < 0 or not s.endswith(")"):
        raise ValueError("expected a script expression")
    name = s[:open_]
    if not name.replace("_", "").isalnum():
        raise ValueError("invalid expression name")
    return name, split_args(s[open_ + 1:-1])


def compact_size(v):
    if v < 0xFD:
        return bytes([v])
    if v <= 0xFFFF:
        return b"\xfd" + v.to_bytes(2, "little")
    raise ValueError("script too long")


def script_number(k):
    if 1 <= k <= 16:
        return bytes([0x50 + k])
    le = k.to_bytes(1 if k <= 0x7F else 2, "little")
    return bytes([len(le)]) + le


def pk_script(xonly):
    return b"\x20" + xonly + OP_CHECKSIG


def pkh_script(xonly):
    return OP_DUP + OP_HASH160 + b"\x14" + hash160(xonly) + OP_EQUALVERIFY + OP_CHECKSIG


def multi_a_script(k, keys, sort):
    if sort:
        keys = sorted(keys)
    script = b""
    for i, key in enumerate(keys):
        script += b"\x20" + key + (OP_CHECKSIG if i == 0 else OP_CHECKSIGADD)
    return script + script_number(k) + OP_NUMEQUAL


class Leaf:
    def __init__(self, keys, build):
        self.keys = keys
        self.build = build

    @property
    def is_ranged(self):
        return any(k.is_ranged for k in self.keys)

    def script(self, child_index):
        return self.build([k.derive(child_index) for k in self.keys])


class Branch:
    def __init__(self, left, right):
        self.left = left
        self.right = right

    @property
    def is_ranged(self):
        return self.left.is_ranged or self.right.is_ranged


def parse_tree(s):
    if s.startswith("{"):
        if not s.endswith("}"):
            raise ValueError("unterminated tree")
        parts = split_args(s[1:-1])
        if len(parts) != 2:
            raise ValueError("a tree branch has exactly two children")
        return Branch(parse_tree(parts[0]), parse_tree(parts[1]))
    name, args = parse_call(s)
    if name in ("pk", "pkh"):
        if len(args) != 1:
            raise ValueError(f"{name}() takes one key")
        build = pk_script if name == "pk" else pkh_script
        return Leaf([parse_key(args[0])], lambda keys: build(keys[0]))
    if name in ("multi_a", "sortedmulti_a"):
        if len(args) < 2 or not args[0].isdigit():
            raise ValueError("invalid threshold")
        k = int(args[0])
        keys = [parse_key(a) for a in args[1:]]
        if not 1 <= k <= len(keys) or len(keys) > 999:
            raise ValueError("invalid threshold")
        sort = name == "sortedmulti_a"
        return Leaf(keys, lambda derived: multi_a_script(k, derived, sort))
    raise ValueError(f"{name}() is not supported in a tree")


def tapleaf_hash(script):
    return tagged_hash("TapLeaf", LEAF_VERSION + compact_size(len(script)) + script)


def tree_hash(tree, child_index):
    if isinstance(tree, Leaf):
        return tapleaf_hash(tree.script(child_index))
    a = tree_hash(tree.left, child_index)
    b = tree_hash(tree.right, child_index)
    if b < a:
        a, b = b, a
    return tagged_hash("TapBranch", a + b)


# ---------------------------------------------------------------------------
# Bech32m (adapted from the BIP 350 reference implementation)
# ---------------------------------------------------------------------------

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32m_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def segwit_address(version, program, hrp="bc"):
    data = [version] + convertbits(program, 8, 5)
    combined = data + bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

class Descriptor:
    def __init__(self, s):
        name, args = parse_call(s.split("#")[0])
        if name not in WITNESS_VERSION:
            raise ValueError(f"{name}() is not a supported top level expression")
        if len(args) not in (1, 2):
            raise ValueError(f"{name}() takes one or two arguments")
        self.version = WITNESS_VERSION[name]
        self.internal = parse_key(args[0])
        self.tree = parse_tree(args[1]) if len(args) == 2 else None

    @property
    def is_ranged(self):
        return self.internal.is_ranged or (self.tree is not None and self.tree.is_ranged)

    def output(self, child_index=0):
        internal = self.internal.derive(child_index)
        merkle_root = tree_hash(self.tree, child_index) if self.tree is not None else b""
        P = GE.from_bytes_xonly(internal)
        t = Scalar.from_bytes_checked(tagged_hash("TapTweak", internal + merkle_root))
        Q = P + t * G
        output_key = Q.to_bytes_xonly()
        script = bytes([0x50 + self.version, 0x20]) + output_key
        return {
            "internalKey": internal.hex(),
            "merkleRoot": merkle_root.hex() if merkle_root else None,
            "outputKey": output_key.hex(),
            "scriptPubKey": script.hex(),
            "address": segwit_address(self.version, output_key),
        }

    def outputs(self):
        indices = range(3) if self.is_ranged else [None]
        return [(i, self.output(i or 0)) for i in indices]


# ---------------------------------------------------------------------------
# Self-test against published vectors
# ---------------------------------------------------------------------------

XPRV_A = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc"
XPRV_B = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334"
XPUB_C = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"
XPRV_D = "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L"
XPUB_E = "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"
XPRV_F = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
XPRV_G = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"
XPRV_H = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

KEY_A = "a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd"
KEY_B = "669b8afcec803a0d323e9a17f3ea8e68e8abe5a278020a929adbec52421adbd0"
KEY_H = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
KEY_C = "02df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076"
KEY_M = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
MUSIG_1 = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
MUSIG_2 = "03dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
MUSIG_3 = "023590a94e768f8e1815c2f24b4d80a8e3149316c3518ce7b7ad338368d038ca66"
WIF_A = "L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1"
WIF_B = "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy"
WIF_C = "L1NKM8dVA1h52mwDrmk1YreTWkAZZTu2vmKLpmLEbFRqGQYjHeEV"
WIF_UNCOMPRESSED = "5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss"
PUB_UNCOMPRESSED = "04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235"

PUBLISHED = [
    # BIP 386
    (f"tr({KEY_A})",
     ["512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11"]),
    (f"tr({WIF_A})",
     ["512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11"]),
    (f"tr({XPRV_A}/0/*,pk({XPRV_A}/1/*))",
     ["512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12",
      "512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11",
      "512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25"]),
    (f"tr({KEY_A},pk({KEY_B}))",
     ["512017cf18db381d836d8923b1bdb246cfcd818da1a9f0e6e7907f187f0b2f937754"]),
    (f"tr({KEY_A},{{pk({XPRV_B}/0),{{{{pk({XPUB_C}),pk({KEY_C})}},pk({WIF_A})}}}})",
     ["512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574"]),
    # BIP 387
    (f"tr({WIF_A},multi_a(1,{WIF_B}))",
     ["5120eb5bd3894327d75093891cc3a62506df7d58ec137fcd104cdd285d67816074f3"]),
    (f"tr({KEY_H},multi_a(2,[00000000/111'/222]{XPRV_A},{XPRV_D}/0))",
     ["51202eea93581594a43c0c8423b70dc112e5651df63984d108d4fc8ccd3b63b4eafa"]),
    (f"tr({KEY_H},sortedmulti_a(2,[00000000/111'/222]{XPRV_A},{XPRV_D}/0))",
     ["512016fa6a6ba7e98c54b5bf43b3144912b78a61b60b02f6a74172b8dcb35b12bc30"]),
    (f"tr({KEY_H},sortedmulti_a(2,{XPUB_C}/*,{XPUB_E}/0/0/*))",
     ["5120abd47468515223f58a1a18edfde709a7a2aab2b696d59ecf8c34f0ba274ef772",
      "5120fe62e7ed20705bd1d3678e072bc999acb014f07795fa02cb8f25a7aa787e8cbd",
      "51201311093750f459039adaa2a5ed23b0f7a8ae2c2ffb07c5390ea37e2fb1050b41"]),
    (f"tr({KEY_H},multi_a(2,{XPRV_F}/2147483647'/0,{XPRV_G}/1/2/*,{XPRV_H}/10/20/30/40/*'))",
     ["5120e4c8f2b0a7d3a688ac131cb03248c0d4b0a59bbd4f37211c848cfbd22a981192",
      "5120827faedaa21e52fca2ac83b53afd1ab7d4d1e6ce67ff42b19f2723d48b5a19ab",
      "5120647495ed09de61a3a324704f9203c130d655bf3141f9b748df8f7be7e9af55a4"]),
    # BIP 379 pkh() leaf, from the Bitcoin Core descriptor tests
    (f"tr({KEY_A},pkh({WIF_C}))",
     ["51201e9875f690f5847404e4c5951e2f029887df0525691ee11a682afd37b608aad4"]),
    # BIP 390
    (f"tr(musig({MUSIG_1},{MUSIG_2},{MUSIG_3}))",
     ["512079e6c3e628c9bfbce91de6b7fb28e2aec7713d377cf260ab599dcbc40e542312"]),
    (f"tr(musig({XPUB_C},{XPUB_E})/0/*,pk({KEY_M}))",
     ["51201d377b637b5c73f670f5c8a96a2c0bb0d1a682a1fca6aba91fe673501a189782",
      "51208950c83b117a6c208d5205ffefcf75b187b32512eb7f0d8577db8d9102833036",
      "5120a49a477c61df73691b77fcd563a80a15ea67bb9c75470310ce5c0f25918db60d"]),
    (f"tr({KEY_M},pk(musig({XPUB_C},{XPUB_E})/0/*))",
     ["512068983d461174afc90c26f3b2821d8a9ced9534586a756763b68371a404635cc8",
      "5120368e2d864115181bdc8bb5dc8684be8d0760d5c33315570d71a21afce4afd43e",
      "512097a1e6270b33ad85744677418bae5f59ea9136027223bc6e282c47c167b471d5"]),
    (f"tr(musig({XPUB_C}/1,{XPUB_C}/1)/2)",
     ["5120a17ceacd6422bd5ffd9f165807b254b7d68ad39f179cc4f11545a6835227e97c"]),
]

# BIP 460 wallet vector for the witness version 2 address encoding
BIP460_INTERNAL_KEY = "34b703e82bfdedfbab012da7a34767456c3f85524171663df7c0aaf227276901"
BIP460_SCRIPT = "52204049ce224d4b6407e9c7864e88d8020996beb04663cd1596bf4ff8ab335bc57b"
BIP460_ADDRESS = "bc1zgpyuugjdfdjq06w8se8g3kqzpxttavzxv0x3t94lflu2kv6mc4as88u8yc"


def selftest():
    for descriptor, expected in PUBLISHED:
        got = [out["scriptPubKey"] for _, out in Descriptor(descriptor).outputs()]
        assert got == expected, descriptor
    out = Descriptor(f"cisa({BIP460_INTERNAL_KEY})").output()
    assert out["scriptPubKey"] == BIP460_SCRIPT
    assert out["address"] == BIP460_ADDRESS


# ---------------------------------------------------------------------------
# Vectors of this BIP
# ---------------------------------------------------------------------------

VALID = [
    (f"cisa({KEY_A})",
     "x-only public key"),
    (f"cisa(03{KEY_A})",
     "compressed public key, converted to x-only"),
    (f"cisa(02{KEY_A})",
     "compressed public key with the other parity byte, same x-only key"),
    (f"cisa({WIF_A})",
     "WIF private key"),
    (f"cisa([deadbeef/1/2h/3/4h]{XPUB_C}/0/*)",
     "key origin information and ranged extended public key"),
    (f"cisa({XPRV_A}/0/*,pk({XPRV_A}/1/*))",
     "ranged internal key and ranged leaf key derived in lockstep"),
    (f"cisa({KEY_A},pk({KEY_B}))",
     "single leaf script tree"),
    (f"cisa({KEY_A},{{pk({XPRV_B}/0),{{{{pk({XPUB_C}),pk({KEY_C})}},pk({WIF_A})}}}})",
     "nested script tree"),
    (f"cisa({KEY_H},multi_a(2,[00000000/111'/222]{XPRV_A},{XPRV_D}/0))",
     "BIP 387 multi_a() leaf"),
    (f"cisa({KEY_H},sortedmulti_a(2,[00000000/111'/222]{XPRV_A},{XPRV_D}/0))",
     "BIP 387 sortedmulti_a() leaf"),
    (f"cisa({KEY_A},pkh({WIF_C}))",
     "BIP 379 Miniscript pkh() leaf"),
    (f"cisa(musig({MUSIG_1},{MUSIG_2},{MUSIG_3}))",
     "BIP 390 musig() internal key, participants are aggregated as compressed keys"),
    (f"cisa(musig({XPUB_C},{XPUB_E})/0/*,pk({KEY_M}))",
     "BIP 390 musig() internal key with BIP 328 derivation of the aggregate key"),
    (f"cisa({KEY_M},pk(musig({XPUB_C},{XPUB_E})/0/*))",
     "BIP 390 musig() leaf key with BIP 328 derivation of the aggregate key"),
]

INVALID = [
    (f"cisa({WIF_UNCOMPRESSED})", "Uncompressed private key"),
    (f"cisa({PUB_UNCOMPRESSED})", "Uncompressed public key"),
    (f"wsh(cisa({KEY_A}))", "<tt>cisa()</tt> nested in <tt>wsh</tt>"),
    (f"sh(cisa({KEY_A}))", "<tt>cisa()</tt> nested in <tt>sh</tt>"),
    (f"cisa({XPUB_C}/1h/*)", "Hardened derivation from an extended public key"),
]


def generate():
    valid = []
    for descriptor, description in VALID:
        children = []
        for index, out in Descriptor(descriptor).outputs():
            entry = {"childIndex": index} if index is not None else {}
            entry.update({
                "intermediary": {
                    "internalKey": out["internalKey"],
                    "merkleRoot": out["merkleRoot"],
                    "outputKey": out["outputKey"],
                },
                "expected": {
                    "scriptPubKey": out["scriptPubKey"],
                    "address": out["address"],
                },
            })
            children.append(entry)
        valid.append({"description": description, "given": {"descriptor": descriptor}, "results": children})
    invalid = []
    for descriptor, reason in INVALID:
        try:
            Descriptor(descriptor)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected failure: {descriptor}")
        invalid.append({"description": reason, "given": {"descriptor": descriptor}})
    return {"valid": valid, "invalid": invalid}


def mediawiki(vectors):
    lines = []
    for vector in vectors["valid"]:
        lines.append(f"* <tt>{vector['given']['descriptor']}</tt>")
        for result in vector["results"]:
            if "childIndex" in result:
                lines.append(f"** Child {result['childIndex']}")
                prefix = "***"
            else:
                prefix = "**"
            lines.append(f"{prefix} Script: <tt>{result['expected']['scriptPubKey']}</tt>")
            lines.append(f"{prefix} Address: <tt>{result['expected']['address']}</tt>")
    lines.append("")
    lines.append("Invalid descriptors")
    lines.append("")
    for vector in vectors["invalid"]:
        lines.append(f"* {vector['description']}: <tt>{vector['given']['descriptor']}</tt>")
    return "\n".join(lines)


def main():
    selftest()
    vectors = generate()
    out_path = Path(__file__).resolve().parent / "test-vectors.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(vectors, f, indent=2)
        f.write("\n")
    print(mediawiki(vectors))


if __name__ == "__main__":
    main()
