#!/usr/bin/env python3
"""Generate a signet WIF for experiments. No node required."""
import hashlib
import os
import sys

sys.path.insert(0, ".")
from btcaaron import TapTree, Key, RawScript
from experiments.opcodes import build_script, OP_1


def to_wif(secret_bytes: bytes, compressed: bool = True) -> str:
    version = 0xEF  # testnet/signet
    payload = bytes([version]) + secret_bytes
    if compressed:
        payload += b"\x01"
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(payload + chk, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = b58[r] + out
    return out


def main():
    secret = os.urandom(32)
    wif = to_wif(secret)
    key = Key.from_wif(wif)
    # Build a minimal tree to get Taproot address
    script = build_script(OP_1)
    program = TapTree(internal_key=key, network="signet").custom(script=RawScript(script), label="x").build()
    print("WIF:", wif)
    print("Address:", program.address)
    print()
    print("export CAT_DEMO_WIF=\"" + wif + "\"")


if __name__ == "__main__":
    main()
