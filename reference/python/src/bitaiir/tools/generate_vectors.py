"""Generate cross-language test vectors for the bitaiir-crypto Rust crate.

Run with::

    cd reference/python
    uv run python -m bitaiir.tools.generate_vectors

This produces a JSON file at ``<repo_root>/tests/vectors/crypto.json`` that the
Rust test suite loads to verify byte-for-byte parity with the Python reference
implementation.

The vectors are deliberately deterministic: every private key is fixed, every
message is fixed, and every signature uses RFC 6979 (no random nonces). This
keeps the file stable across runs so any diff in the JSON is a real change in
the protocol or the implementation, never noise from randomness.

Sections produced:

* ``hash`` - known input -> known output for SHA-256, double SHA-256,
  RIPEMD-160, and HASH160 (RIPEMD-160 of SHA-256).
* ``hmac_sha256`` - HMAC-SHA-256 with selected (key, message) pairs, including
  RFC 4231 test vectors.
* ``base58`` - Base58 encoding round-trip cases, including leading-zero
  handling.
* ``keys`` - for each fixed private key, the derived compressed/uncompressed
  public key, BitAiir address, and WIF.
* ``msg_magic`` - the BitAiir signed-message magic prefix and the
  double-SHA-256 of the prefixed payload, used as input to ECDSA signing.
* ``signatures`` - deterministic (RFC 6979) signatures for selected
  (private_key, message) pairs, in compressed and uncompressed form.
* ``verify_known`` - hand-picked (address, message, signature) triples with
  the expected verification outcome, used to validate the Rust verifier
  against pre-existing signatures the Python reference accepts or rejects.
"""

import json
from pathlib import Path

from bitaiir.core.address.address import Address
from bitaiir.core.base.base58 import Base58
from bitaiir.core.crypto.hmac256 import HMACSHA256
from bitaiir.core.crypto.ripemd160 import Ripemd160
from bitaiir.core.crypto.sha256 import SHA256
from bitaiir.core.signature.signature import SignatureAlgorithm, SignatureError

# Resolve the output path relative to this file so the script works no matter
# what the current working directory is. The layout is:
#   reference/python/src/bitaiir/tools/generate_vectors.py
#   ^ parents[5]                                       parents[0]
HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[5]
OUTPUT = REPO_ROOT / "tests" / "vectors" / "crypto.json"


# --- Fixed inputs --------------------------------------------------------- #

# Private keys cover edge cases (smallest valid scalar, n-1, all-bits-set
# patterns) plus a few "ordinary" looking values. All are 32 bytes / 64 hex
# chars. The curve order n is:
#   0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PRIVATE_KEYS_HEX = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "00000000000000000000000000000000000000000000000000000000000000ff",
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    "1111111111111111111111111111111111111111111111111111111111111111",
    "798e2a22999e8b1ab02c2940eb72fdd048fabacfe78081caf902fca84d82e24c",
    "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a",
]

# Messages used as ECDSA inputs. The empty string is intentional - it exercises
# the varint(0) path of the message-magic prefix.
MESSAGES = [
    "ECDSA is the most fun I have ever experienced",
    "BitAiir genesis",
    "",
    "a",
]

# Raw byte inputs for hash function vectors.
HASH_INPUTS_HEX = [
    "",
    "61",                                # "a"
    "616263",                            # "abc"
    "00",
    "ffffffff",
    "00112233445566778899aabbccddeeff",
]

# HMAC-SHA-256 inputs. The first two entries are RFC 4231 test cases 1 and 2,
# which gives us a sanity check against the published HMAC standard.
HMAC_INPUTS_HEX = [
    ("", ""),
    ("0b" * 20, "4869205468657265"),
    ("4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
]

# Base58 round-trip inputs. Several entries have leading zero bytes to verify
# the encoder preserves them as leading '1' characters.
BASE58_INPUTS_HEX = [
    "",
    "00",
    "0000",
    "000000",
    "61",
    "626262",
    "636363",
    "73696d706c792061206c6f6e6720737472696e67",
    "00eb15231dfceb60925886b67d065299925915aeb172c06647",
]

# Pre-existing (address, message, signature) triples copied from the Python
# reference's __main__ test cases. The Rust verifier must agree on the
# expected verification result for each.
KNOWN_VERIFY_CASES = [
    {
        "address": "aiir1JzjaNRfrBVh6abfGzM8H7WSJmxvhoNhGR",
        "message": "ECDSA is the most fun I have ever experienced",
        "signature": "HxS3ZviRS/zIa26ohjnHnQ8MnUTBZ3PAQcQj0j5zFflzDpJ4/4tR21sX+sMFLB23qlU6NwOrD04NQqDvdvG35G0=",
        "note": "Compressed P2PKH, expected to verify",
    },
    {
        "address": "aiir1KBoKn8xzGgFnirpmqtfPRbeoE7WmGW1Wf",
        "message": "ECDSA is the most fun I have ever experienced",
        "signature": "GxS3ZviRS/zIa26ohjnHnQ8MnUTBZ3PAQcQj0j5zFflzDpJ4/4tR21sX+sMFLB23qlU6NwOrD04NQqDvdvG35G0=",
        "note": "Uncompressed P2PKH, expected to verify",
    },
    {
        "address": "aiir175A5YsPUdM71mnNCC3i8faxxYJgBonjWL",
        "message": "ECDSA is the most fun I have ever experienced",
        "signature": "IBuc5GXSJCr6m7KevsBAoCiX8ToOjW2CDZMr6PCEbiHwQJ237LZTj/REbDHI1/yelY6uBWEWXiOWoGnajlgvO/A=",
        "note": "Valid signature shape but recovers a different address",
    },
    {
        "address": "aiir175A5YsPUdM71mnNCC3i8faxxYJgBonjWL",
        "message": "ECDSA is the most fun I have ever experienced",
        "signature": "HyiLDcQQ1p2bKmyqM0e5oIBQtKSZds4kJQ+VbZWpr0kYA6Qkam2MlUeTr+lm1teUGHuLapfa43Jj=",
        "note": "Malformed signature, decode is shorter than 65 bytes",
    },
]


# --- Vector builders ------------------------------------------------------ #


def hash_vectors() -> list[dict]:
    sha = SHA256()
    rip = Ripemd160()
    out: list[dict] = []
    for hex_in in HASH_INPUTS_HEX:
        data = bytes.fromhex(hex_in)
        sha256_digest = sha.sha256(data)
        out.append(
            {
                "input_hex": hex_in,
                "sha256_hex": sha256_digest.hex(),
                "double_sha256_hex": sha.double_sha256(data).hex(),
                "ripemd160_hex": rip.digest(data).hex(),
                "hash160_hex": rip.digest(sha256_digest).hex(),
            }
        )
    return out


def hmac_vectors() -> list[dict]:
    out: list[dict] = []
    for key_hex, msg_hex in HMAC_INPUTS_HEX:
        key = bytes.fromhex(key_hex)
        msg = bytes.fromhex(msg_hex)
        out.append(
            {
                "key_hex": key_hex,
                "message_hex": msg_hex,
                "hmac_sha256_hex": HMACSHA256(key).compute(msg).hex(),
            }
        )
    return out


def base58_vectors() -> list[dict]:
    b58 = Base58()
    out: list[dict] = []
    for hex_in in BASE58_INPUTS_HEX:
        data = bytes.fromhex(hex_in)
        out.append({"input_hex": hex_in, "base58": b58.encode(data)})
    return out


def key_vectors() -> list[dict]:
    address = Address()
    out: list[dict] = []
    for priv_hex in PRIVATE_KEYS_HEX:
        pub_compressed = address.private_to_public(priv_hex, compressed=True)
        pub_uncompressed = address.private_to_public(priv_hex, compressed=False)
        out.append(
            {
                "private_key_hex": priv_hex,
                "public_key_compressed_hex": pub_compressed,
                "public_key_uncompressed_hex": pub_uncompressed,
                "address_compressed": address.public_to_address(pub_compressed),
                "address_uncompressed": address.public_to_address(pub_uncompressed),
                "wif_compressed": address.private_key_to_WIF(priv_hex, compressed=True),
                "wif_uncompressed": address.private_key_to_WIF(priv_hex, compressed=False),
            }
        )
    return out


def msg_magic_vectors() -> list[dict]:
    sig = SignatureAlgorithm()
    sha = SHA256()
    out: list[dict] = []
    for message in MESSAGES:
        magic = sig.msg_magic(message)
        out.append(
            {
                "message": message,
                "msg_magic_hex": magic.hex(),
                "double_sha256_of_magic_hex": sha.double_sha256(magic).hex(),
            }
        )
    return out


def signature_vectors() -> list[dict]:
    sig = SignatureAlgorithm()
    addr = Address()
    out: list[dict] = []
    # Limit to the first three private keys to keep the vector file small.
    # Each key generates one entry per message, in both compressed and
    # uncompressed form, all using deterministic RFC 6979 nonces.
    for priv_hex in PRIVATE_KEYS_HEX[:3]:
        wif_c = addr.private_key_to_WIF(priv_hex, compressed=True)
        wif_u = addr.private_key_to_WIF(priv_hex, compressed=False)
        for message in MESSAGES:
            entry: dict = {
                "private_key_hex": priv_hex,
                "message": message,
                "wif_compressed": wif_c,
                "wif_uncompressed": wif_u,
            }
            try:
                addr_c, _, signature_c = sig.sign_message(wif_c, message, deterministic=True)
                addr_u, _, signature_u = sig.sign_message(wif_u, message, deterministic=True)
                entry["address_compressed"] = addr_c
                entry["address_uncompressed"] = addr_u
                entry["signature_compressed_b64"] = signature_c
                entry["signature_uncompressed_b64"] = signature_u
            except SignatureError as exc:
                entry["error"] = str(exc)
            out.append(entry)
    return out


def verify_known_vectors() -> list[dict]:
    sig = SignatureAlgorithm()
    out: list[dict] = []
    for case in KNOWN_VERIFY_CASES:
        entry = dict(case)
        try:
            verified, public_key_hex, _status = sig.verify_message(
                case["address"], case["message"], case["signature"]
            )
            entry["expected_verified"] = verified
            entry["recovered_public_key_hex"] = public_key_hex
        except SignatureError as exc:
            entry["expected_verified"] = False
            entry["expected_error"] = str(exc)
        out.append(entry)
    return out


# --- Entry point ---------------------------------------------------------- #


def main() -> None:
    vectors = {
        "version": 1,
        "description": (
            "BitAiir crypto test vectors generated from the Python reference "
            "implementation. Used by the bitaiir-crypto Rust crate to verify "
            "byte-for-byte parity. Regenerate with "
            "`uv run python -m bitaiir.tools.generate_vectors`."
        ),
        "hash": hash_vectors(),
        "hmac_sha256": hmac_vectors(),
        "base58": base58_vectors(),
        "keys": key_vectors(),
        "msg_magic": msg_magic_vectors(),
        "signatures": signature_vectors(),
        "verify_known": verify_known_vectors(),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    section_counts = {k: len(v) for k, v in vectors.items() if isinstance(v, list)}
    total = sum(section_counts.values())
    print(f"Wrote {OUTPUT.relative_to(REPO_ROOT)}")
    print(f"  Sections: {section_counts}")
    print(f"  Total vectors: {total}")


if __name__ == "__main__":
    main()
