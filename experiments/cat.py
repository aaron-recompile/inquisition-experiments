"""
OP_CAT — witness lock. Data in witness; only holder of part_a/part_b can spend.
Run: PYTHONPATH=. python3 experiments/cat.py [--fund|--spend]
"""
import sys
import hashlib

sys.path.insert(0, ".")

from experiments.opcodes import build_script, push_bytes, OP_CAT, OP_SHA256, OP_EQUAL
from btcaaron import TapTree, Key, RawScript

PART_A = b"hello"
PART_B = b"world"
EXPECTED_HASH = hashlib.sha256(PART_A + PART_B).digest()

script_hex = build_script(OP_CAT, OP_SHA256, push_bytes(EXPECTED_HASH), OP_EQUAL)
leaf_script = RawScript(script_hex)

# Your signet WIF — set CAT_DEMO_WIF env var, or edit here. Generate with: bitcoin-cli -signet dumpwallet /dev/stdout | grep -m1 "c"
DEMO_KEY_WIF = __import__("os").environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for internal key), or edit cat.py")
key = Key.from_wif(DEMO_KEY_WIF)

tap_tree = (
    TapTree(internal_key=key, network="signet")
    .custom(script=leaf_script, label="cat")
).build()

program = tap_tree
addr = program.address

FUND_TXID_FILE = __file__.replace("cat.py", ".cat_fund_txid")


def print_setup():
    print("OP_CAT — witness lock")
    print(f"Address: {addr}")
    print("Run: --fund, --spend (witness provides part_a, part_b)")


def do_fund():
    from config import rpc_wallet
    txid = rpc_wallet("sendtoaddress", addr, 0.0005, "", "", False, False, None, "unset", False, 1)
    with open(FUND_TXID_FILE, "w") as f:
        f.write(txid)
    print(f"Commit TxID: {txid}")


def _find_utxo_via_txid(txid):
    from config import rpc
    raw = rpc("getrawtransaction", txid, 1)
    if not raw:
        return None
    for out in raw.get("vout", []):
        if out.get("scriptPubKey", {}).get("address") == addr:
            return txid, out["n"], int(out["value"] * 1e8)
    return None


def do_spend(txid_arg=None):
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
        utxo = u["txid"], u["vout"], int(u["value"] * 1e8)

    txid, vout, sats = utxo
    tx = (
        program.spend("cat")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - 500)
        .unlock_with([PART_A.hex(), PART_B.hex()])
        .build()
    )
    reveal_txid = rpc("sendrawtransaction", tx.hex)
    print(f"Reveal TxID: {reveal_txid}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--fund":
        do_fund()
    elif len(sys.argv) > 1 and sys.argv[1] == "--spend":
        do_spend(sys.argv[2] if len(sys.argv) > 2 else None)
    else:
        print_setup()
