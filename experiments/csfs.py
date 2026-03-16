"""
OP_CHECKSIGFROMSTACK (BIP348) — sign arbitrary message, verify in script.
Witness: [sig, message, pubkey].

Run:
  PYTHONPATH=. python3 experiments/csfs.py --fund
  PYTHONPATH=. python3 experiments/csfs.py --spend [txid] [--fee-sats 500]
"""
import argparse
import sys
import hashlib

sys.path.insert(0, ".")

from experiments.opcodes import build_script, OP_CHECKSIGFROMSTACK
from btcaaron import TapTree, Key, RawScript

MESSAGE = hashlib.sha256(b"hello world").digest()

script_hex = build_script(OP_CHECKSIGFROMSTACK)
leaf_script = RawScript(script_hex)

# Your signet WIF — set CAT_DEMO_WIF env var, or edit here. Generate with: bitcoin-cli -signet dumpwallet /dev/stdout | grep -m1 "c"
DEMO_KEY_WIF = __import__("os").environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for internal key), or edit csfs.py")
key = Key.from_wif(DEMO_KEY_WIF)

tap_tree = (
    TapTree(internal_key=key, network="signet")
    .custom(script=leaf_script, label="csfs")
).build()

program = tap_tree
addr = program.address

FUND_TXID_FILE = __file__.replace("csfs.py", ".csfs_fund_txid")


def _wif_to_secret(wif: str) -> bytes:
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b = 0
    for c in wif:
        b = b * 58 + B58.index(c)
    raw = b.to_bytes((b.bit_length() + 7) // 8 or 1, "big").lstrip(b"\x00")
    pad = 37 if len(raw) <= 37 else 38
    raw = (b"\x00" * (pad - len(raw))) + raw
    payload_len = 34 if len(raw) == 38 else 33
    chk = hashlib.sha256(hashlib.sha256(raw[:payload_len]).digest()).digest()[:4]
    assert raw[payload_len:] == chk
    return raw[1:33]


def _make_witness():
    from secp256k1 import PrivateKey
    secret = _wif_to_secret(DEMO_KEY_WIF)
    pk = PrivateKey(secret, raw=True)
    sig = pk.schnorr_sign(MESSAGE, "", raw=True)
    pub_x = pk.pubkey.serialize()[1:33]
    return [sig.hex(), MESSAGE.hex(), pub_x.hex()]


def print_setup():
    print("OP_CHECKSIGFROMSTACK — sign arbitrary message")
    print(f"Address: {addr}")
    print("Run: --fund, --spend (witness: sig, message, pubkey)")


def do_fund():
    from config import rpc_wallet
    txid = rpc_wallet("sendtoaddress", addr, 0.0005, "", "", False, False, None, "unset", False, 1)
    with open(FUND_TXID_FILE, "w") as f:
        f.write(txid)
    print(f"Commit TxID: {txid}")


def _find_utxo_via_txid(txid):
    from config import rpc
    try:
        raw = rpc("getrawtransaction", txid, 1)
    except Exception:
        # Common on nodes without txindex for already-confirmed tx.
        # Caller will fallback to scantxoutset.
        return None
    if not raw:
        return None
    for out in raw.get("vout", []):
        if out.get("scriptPubKey", {}).get("address") == addr:
            return txid, out["n"], int(out["value"] * 1e8)
    return None


def do_spend(txid_arg=None, fee_sats=500):
    import json
    from config import rpc, rpc_wallet

    change_addr = rpc_wallet("getrawchangeaddress", "bech32m") or rpc_wallet("getnewaddress", "change", "bech32m")
    utxo = None
    if txid_arg:
        utxo = _find_utxo_via_txid(txid_arg)
    elif __import__("os").path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE) as f:
            utxo = _find_utxo_via_txid(f.read().strip())

    if not utxo:
        try:
            rpc("scantxoutset", "abort")
        except Exception:
            pass
        scan_result = rpc("scantxoutset", "start", json.dumps([f"addr({addr})"]))
        unspents = scan_result.get("unspents", [])
        if not unspents:
            print("No UTXO. Run --fund first.")
            sys.exit(1)
        u = unspents[0]
        amt_btc = u.get("value", u.get("amount"))
        if amt_btc is None:
            raise KeyError(f"Unexpected scantxoutset entry without value/amount: {u}")
        utxo = u["txid"], u["vout"], int(float(amt_btc) * 1e8)

    txid, vout, sats = utxo
    if fee_sats <= 0 or fee_sats >= sats:
        raise ValueError(f"Invalid fee_sats={fee_sats}. Must be >0 and < input sats({sats}).")
    tx = (
        program.spend("csfs")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - fee_sats)
        .unlock_with(_make_witness())
        .build()
    )
    reveal_txid = rpc("sendrawtransaction", tx.hex)
    print(f"Reveal TxID: {reveal_txid} (fee_sats={fee_sats})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSFS experiment runner")
    parser.add_argument("--fund", action="store_true", help="Send commit tx to CSFS address")
    parser.add_argument("--spend", nargs="?", const="", default=None, metavar="TXID", help="Build and broadcast reveal tx")
    parser.add_argument("--fee-sats", type=int, default=500, help="Reveal fee in satoshis (default: 500)")
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.spend is not None:
        txid_arg = args.spend if args.spend else None
        do_spend(txid_arg, fee_sats=args.fee_sats)
    else:
        print_setup()
