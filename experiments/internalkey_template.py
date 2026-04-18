"""
OP_INTERNALKEY (template-style experiment).

Run:
  PYTHONPATH=. python3 experiments/internalkey_template.py --fund
  PYTHONPATH=. python3 experiments/internalkey_template.py --spend [txid] [--fee-sats 500]
"""

import argparse
import os
import sys

sys.path.insert(0, ".")
import experiments.load_local_env  # noqa: F401

from btcaaron import Key, RawScript, TapTree
from experiments.opcodes import OP_EQUAL, OP_INTERNALKEY, build_script, push_bytes
from experiments.template_common import (
    broadcast_or_raise,
    default_change_address,
    find_template_utxo_or_exit,
    fund_address,
    print_setup,
    read_txid_hint,
)

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError(
        "Set CAT_DEMO_WIF (shell or `.env` — see env.example), or edit internalkey_template.py"
    )

key = Key.from_wif(DEMO_KEY_WIF)
expected_internal_key = bytes.fromhex(key.xonly)

# Script: OP_INTERNALKEY <expected_internal_key> OP_EQUAL
leaf_script = RawScript(build_script(OP_INTERNALKEY, push_bytes(expected_internal_key), OP_EQUAL))
program = TapTree(internal_key=key, network="signet").custom(script=leaf_script, label="internalkey").build()
addr = program.address

FUND_TXID_FILE = __file__.replace("internalkey_template.py", ".internalkey_template_fund_txid")


def do_fund():
    txid = fund_address(addr, FUND_TXID_FILE, fund_sats=50_000)
    print(f"Commit TxID: {txid}")


def do_spend(txid_arg=None, fee_sats=500):
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
    reveal_txid = broadcast_or_raise(tx.hex)
    print(f"Reveal TxID: {reveal_txid} (fee_sats={fee_sats})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OP_INTERNALKEY template experiment runner")
    parser.add_argument("--fund", action="store_true", help="Send commit tx to OP_INTERNALKEY address")
    parser.add_argument("--spend", nargs="?", const="", default=None, metavar="TXID", help="Build and broadcast reveal tx")
    parser.add_argument("--fee-sats", type=int, default=500, help="Reveal fee in satoshis (default: 500)")
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.spend is not None:
        txid_arg = args.spend if args.spend else None
        do_spend(txid_arg, fee_sats=args.fee_sats)
    else:
        print_setup(
            "OP_INTERNALKEY (template) — script checks internal key equality",
            addr,
            "Run: --fund, --spend (no extra witness args)",
        )

