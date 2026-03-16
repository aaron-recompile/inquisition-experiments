"""
CTV negative tests (intentional template mismatch).

Run:
  PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_amount
  PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_sequence

Default behavior uses testmempoolaccept (no broadcast).
"""

import argparse
import json
import os
import sys

sys.path.insert(0, ".")

from btcaaron import Key
from experiments.ctv import (
    CHANGE_ADDR_FILE,
    FUND_SATS,
    FUND_TXID_FILE,
    OUTPUT_SATS,
    _build_ctv_address,
    _find_utxo_via_txid,
)

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for internal key), or edit ctv_negative.py")
Key.from_wif(DEMO_KEY_WIF)


def _resolve_utxo(addr: str, txid_arg: str | None):
    from config import rpc

    utxo = _find_utxo_via_txid(txid_arg, addr) if txid_arg else None
    if not utxo and os.path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE, "r", encoding="utf-8") as f:
            utxo = _find_utxo_via_txid(f.read().strip(), addr)
    if utxo:
        return utxo

    try:
        rpc("scantxoutset", "abort")
    except Exception:
        pass
    scan = rpc("scantxoutset", "start", json.dumps([f"addr({addr})"]))
    unspents = scan.get("unspents", [])
    if not unspents:
        raise RuntimeError("No UTXO for CTV address. Run ctv.py --fund first.")
    u = unspents[0]
    return u["txid"], u["vout"], int(u["value"] * 1e8)


def run_negative(case_name: str, txid_arg: str | None):
    from config import rpc

    if not os.path.exists(CHANGE_ADDR_FILE):
        raise RuntimeError("No change address found. Run ctv.py --fund first.")

    with open(CHANGE_ADDR_FILE, "r", encoding="utf-8") as f:
        change_addr = f.read().strip()

    _, program, _ = _build_ctv_address(change_addr)
    addr = program.address
    txid, vout, sats = _resolve_utxo(addr, txid_arg)
    if sats != FUND_SATS:
        print(f"Warning: UTXO has {sats} sats, expected {FUND_SATS}.")

    builder = program.spend("ctv").from_utxo(txid, vout, sats=sats)
    if case_name == "wrong_amount":
        builder = builder.to(change_addr, OUTPUT_SATS - 1).sequence(0xFFFFFFFF)
    elif case_name == "wrong_sequence":
        builder = builder.to(change_addr, OUTPUT_SATS).sequence(0xFFFFFFFE)
    else:
        raise ValueError(f"Unknown case: {case_name}")

    tx = builder.unlock_with([]).build()
    result = rpc("testmempoolaccept", [tx.hex])[0]
    print(f"Case: {case_name}")
    print(json.dumps(result, indent=2))
    if result.get("allowed", False):
        print("WARNING: tx unexpectedly accepted (negative case should fail).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CTV negative tests")
    parser.add_argument("--case", choices=["wrong_amount", "wrong_sequence"], required=True)
    parser.add_argument("--txid", default=None, help="Optional explicit commit txid")
    args = parser.parse_args()
    run_negative(args.case, args.txid)

