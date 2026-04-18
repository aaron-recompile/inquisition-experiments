"""
OP_INTERNALKEY negative test (intentional failure).

Case:
  wrong_expected_key: script compares internal key against a wrong x-only key.

Run:
  PYTHONPATH=. python3 experiments/internalkey_negative.py --fund
  PYTHONPATH=. python3 experiments/internalkey_negative.py --case wrong_expected_key
"""

import argparse
import json
import os
import sys

sys.path.insert(0, ".")
import experiments.load_local_env  # noqa: F401

from btcaaron import Key, RawScript, TapTree
from experiments.opcodes import OP_EQUAL, OP_INTERNALKEY, build_script, push_bytes
from experiments.template_common import (
    default_change_address,
    find_template_utxo_or_exit,
    fund_address,
    read_txid_hint,
)

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError(
        "Set CAT_DEMO_WIF (shell or `.env` — see env.example), or edit internalkey_negative.py"
    )

key = Key.from_wif(DEMO_KEY_WIF)
correct = bytes.fromhex(key.xonly)
wrong = bytearray(correct)
wrong[-1] ^= 0x01

# Intentional mismatch: OP_INTERNALKEY <wrong_key> OP_EQUAL
leaf_script = RawScript(build_script(OP_INTERNALKEY, push_bytes(bytes(wrong)), OP_EQUAL))
program = TapTree(internal_key=key, network="signet").custom(script=leaf_script, label="internalkey").build()
addr = program.address

FUND_TXID_FILE = __file__.replace("internalkey_negative.py", ".internalkey_negative_fund_txid")


def do_fund():
    txid = fund_address(addr, FUND_TXID_FILE, fund_sats=50_000)
    print(f"Commit TxID: {txid}")


def run_negative(txid_arg=None, fee_sats=500):
    from config import rpc

    change_addr = default_change_address()
    txid_hint = read_txid_hint(txid_arg, FUND_TXID_FILE)
    txid, vout, sats = find_template_utxo_or_exit(addr, txid_hint)
    if fee_sats <= 0 or fee_sats >= sats:
        raise ValueError(f"Invalid fee_sats={fee_sats}. Must be >0 and < input sats({sats}).")

    tx = (
        program.spend("internalkey")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - fee_sats)
        .unlock_with([])
        .build()
    )

    result = rpc("testmempoolaccept", [tx.hex])[0]
    print("Case: wrong_expected_key")
    print(json.dumps(result, indent=2))
    if result.get("allowed", False):
        print("WARNING: tx unexpectedly accepted (negative case should fail).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OP_INTERNALKEY negative test")
    parser.add_argument("--fund", action="store_true", help="Fund negative-test commit address")
    parser.add_argument("--case", choices=["wrong_expected_key"], default=None)
    parser.add_argument("--txid", default=None, help="Optional explicit commit txid")
    parser.add_argument("--fee-sats", type=int, default=500, help="Spend fee in satoshis (default: 500)")
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.case == "wrong_expected_key":
        run_negative(args.txid, fee_sats=args.fee_sats)
    else:
        print("Use --fund first, then --case wrong_expected_key")

