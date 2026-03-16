"""
CSFS negative tests (intentional failures).

Run:
  PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_msg
  PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_sig
  PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_pubkey

Default behavior uses testmempoolaccept (no broadcast).
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, ".")

from btcaaron import Key, RawScript, TapTree
from experiments.opcodes import OP_CHECKSIGFROMSTACK, build_script

MESSAGE = hashlib.sha256(b"hello world").digest()
BAD_MESSAGE = hashlib.sha256(b"hello world?").digest()

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for internal key), or edit csfs_negative.py")

key = Key.from_wif(DEMO_KEY_WIF)
script_hex = build_script(OP_CHECKSIGFROMSTACK)
leaf_script = RawScript(script_hex)
program = TapTree(internal_key=key, network="signet").custom(script=leaf_script, label="csfs").build()
addr = program.address
FUND_TXID_FILE = __file__.replace("csfs_negative.py", ".csfs_fund_txid")


def _wif_to_secret(wif: str) -> bytes:
    b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for ch in wif:
        n = n * 58 + b58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big").lstrip(b"\x00")
    pad = 37 if len(raw) <= 37 else 38
    raw = (b"\x00" * (pad - len(raw))) + raw
    payload_len = 34 if len(raw) == 38 else 33
    chk = hashlib.sha256(hashlib.sha256(raw[:payload_len]).digest()).digest()[:4]
    assert raw[payload_len:] == chk
    return raw[1:33]


def _make_witness(case_name: str) -> list[str]:
    from secp256k1 import PrivateKey

    secret = _wif_to_secret(DEMO_KEY_WIF)
    pk = PrivateKey(secret, raw=True)
    sig = bytearray(pk.schnorr_sign(MESSAGE, "", raw=True))
    msg = MESSAGE
    pub_x = bytearray(pk.pubkey.serialize()[1:33])

    if case_name == "bad_msg":
        msg = BAD_MESSAGE
    elif case_name == "bad_sig":
        sig[0] ^= 0x01
    elif case_name == "bad_pubkey":
        pub_x[-1] ^= 0x01
    else:
        raise ValueError(f"Unknown case: {case_name}")

    return [bytes(sig).hex(), msg.hex(), bytes(pub_x).hex()]


def _find_utxo_via_txid(txid: str):
    from config import rpc

    raw = rpc("getrawtransaction", txid, 1)
    if not raw:
        return None
    for out in raw.get("vout", []):
        if out.get("scriptPubKey", {}).get("address") == addr:
            return txid, out["n"], int(out["value"] * 1e8)
    return None


def _resolve_utxo(txid_arg: str | None):
    from config import rpc

    utxo = _find_utxo_via_txid(txid_arg) if txid_arg else None
    if not utxo and os.path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE, "r", encoding="utf-8") as f:
            utxo = _find_utxo_via_txid(f.read().strip())
    if utxo:
        return utxo

    try:
        rpc("scantxoutset", "abort")
    except Exception:
        pass
    scan = rpc("scantxoutset", "start", json.dumps([f"addr({addr})"]))
    unspents = scan.get("unspents", [])
    if not unspents:
        raise RuntimeError("No UTXO for CSFS address. Run csfs.py --fund first.")
    u = unspents[0]
    return u["txid"], u["vout"], int(u["value"] * 1e8)


def run_negative(case_name: str, txid_arg: str | None):
    from config import rpc, rpc_wallet

    txid, vout, sats = _resolve_utxo(txid_arg)
    change_addr = rpc_wallet("getrawchangeaddress", "bech32m") or rpc_wallet("getnewaddress", "change", "bech32m")

    tx = (
        program.spend("csfs")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - 500)
        .unlock_with(_make_witness(case_name))
        .build()
    )

    result = rpc("testmempoolaccept", [tx.hex])[0]
    print(f"Case: {case_name}")
    print(json.dumps(result, indent=2))
    if result.get("allowed", False):
        print("WARNING: tx unexpectedly accepted (negative case should fail).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSFS negative tests")
    parser.add_argument("--case", choices=["bad_msg", "bad_sig", "bad_pubkey"], required=True)
    parser.add_argument("--txid", default=None, help="Optional explicit commit txid")
    args = parser.parse_args()
    run_negative(args.case, args.txid)

