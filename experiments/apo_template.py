"""
BIP118 (SIGHASH_ANYPREVOUT) — tapscript ``<0x01||xonly> OP_CHECKSIG`` + BIP340 signature with explicit sighash byte (e.g. ``0x41``).

Requires a **BIP118-capable** consensus (e.g. Bitcoin Inquisition signet). Standard Bitcoin nodes will not accept these spends.

Run:
  PYTHONPATH=. python3 experiments/apo_template.py --fund
  PYTHONPATH=. python3 experiments/apo_template.py --spend [txid] [--fee-sats 3000]
"""
import argparse
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import experiments.load_local_env  # noqa: F401

from btcaaron import Key, inq_apo_program
from experiments.template_common import (
    broadcast_or_raise,
    default_change_address,
    find_template_utxo_or_exit,
    fund_address,
    print_setup,
    read_txid_hint,
)

FUND_SATS = 50_000

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError(
        "Set CAT_DEMO_WIF (shell or `.env` — see env.example), or edit apo_template.py"
    )
key = Key.from_wif(DEMO_KEY_WIF)

program = inq_apo_program(key, network="signet", label="apo")
addr = program.address

FUND_TXID_FILE = __file__.replace("apo_template.py", ".apo_template_fund_txid")


def do_fund():
    txid = fund_address(addr, FUND_TXID_FILE, fund_sats=FUND_SATS)
    print(f"Fund TxID: {txid}")
    print(f"P2TR (BIP118 leaf): {addr}")


def do_spend(txid_arg=None, fee_sats=3000):
    change_addr = default_change_address()
    txid_hint = read_txid_hint(txid_arg, FUND_TXID_FILE)
    utxo = find_template_utxo_or_exit(addr, txid_hint)

    txid, vout, sats = utxo
    if fee_sats <= 0 or fee_sats >= sats:
        raise ValueError(f"Invalid fee_sats={fee_sats}. Must be >0 and < input sats({sats}).")

    tx = (
        program.spend("apo")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - fee_sats)
        .sign(key)
        .build()
    )
    reveal_txid = broadcast_or_raise(tx.hex)
    print(f"Reveal TxID: {reveal_txid} (fee_sats={fee_sats})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BIP118 APO template — fund & spend on Inquisition")
    parser.add_argument("--fund", action="store_true", help="Send coins to the APO tapscript address")
    parser.add_argument(
        "--spend",
        nargs="?",
        const="",
        default=None,
        metavar="TXID",
        help="Build script-path spend and broadcast",
    )
    parser.add_argument(
        "--fee-sats",
        type=int,
        default=3000,
        help="Reveal fee in satoshis (default: 3000; higher = faster confirm on signet)",
    )
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.spend is not None:
        txid_arg = args.spend if args.spend else None
        do_spend(txid_arg, fee_sats=args.fee_sats)
    else:
        print_setup(
            "BIP118 ANYPREVOUT — tapscript BIP118 pubkey + OP_CHECKSIG",
            addr,
            "Run: --fund, --spend (witness: sig, script, control block; sig ends with 0x41)",
        )
