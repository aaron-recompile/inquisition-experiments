"""
CTV CPFP accelerator: create a high-fee child tx that spends the unconfirmed CTV reveal output.

Why CPFP (not RBF)?
- Current CTV reveal commits to a fixed 1-output template.
- Direct fee bump via changing outputs is not possible without violating CTV template.
- CPFP can still incentivize package inclusion (parent + child).

Usage:
  PYTHONPATH=. python3 experiments/ctv_cpfp.py --parent-txid <ctv_reveal_txid> --fee-sats 10000
"""

import argparse
import json
import sys

sys.path.insert(0, ".")


def main():
    from config import rpc, rpc_wallet

    parser = argparse.ArgumentParser(description="Create/broadcast CPFP child for CTV reveal")
    parser.add_argument("--parent-txid", required=True, help="Unconfirmed CTV reveal txid")
    parser.add_argument("--vout", type=int, default=0, help="Parent output index to spend (default: 0)")
    parser.add_argument("--fee-sats", type=int, default=10000, help="Child tx fee in sats (default: 10000)")
    parser.add_argument("--dry-run", action="store_true", help="Build + testmempoolaccept only, do not broadcast")
    args = parser.parse_args()

    parent = rpc("getrawtransaction", args.parent_txid, 1)
    if not parent:
        raise RuntimeError("Parent tx not found via getrawtransaction")

    if args.vout >= len(parent.get("vout", [])):
        raise ValueError(f"vout {args.vout} out of range")

    out = parent["vout"][args.vout]
    value_btc = float(out["value"])
    input_sats = int(value_btc * 1e8)
    if args.fee_sats <= 0 or args.fee_sats >= input_sats:
        raise ValueError(f"Invalid fee-sats={args.fee_sats}; input={input_sats} sats")

    dest_addr = rpc_wallet("getrawchangeaddress", "bech32m") or rpc_wallet("getnewaddress", "change", "bech32m")
    output_sats = input_sats - args.fee_sats
    output_btc = output_sats / 1e8

    inputs = [{"txid": args.parent_txid, "vout": args.vout}]
    outputs = {dest_addr: output_btc}
    raw = rpc("createrawtransaction", json.dumps(inputs), json.dumps(outputs), 0, True)
    signed = rpc_wallet("signrawtransactionwithwallet", raw)
    if not signed.get("complete", False):
        raise RuntimeError(f"signrawtransactionwithwallet incomplete: {signed}")

    txhex = signed["hex"]
    check = rpc("testmempoolaccept", json.dumps([txhex]))[0]

    print(json.dumps({
        "parent_txid": args.parent_txid,
        "parent_vout": args.vout,
        "input_sats": input_sats,
        "fee_sats": args.fee_sats,
        "output_sats": output_sats,
        "destination": dest_addr,
        "testmempoolaccept": check,
    }, indent=2))

    if not check.get("allowed", False):
        print("CPFP child rejected by mempool; not broadcasting.")
        return

    if args.dry_run:
        print("Dry run only; child not broadcast.")
        return

    child_txid = rpc("sendrawtransaction", txhex)
    print(f"CPFP child broadcast txid: {child_txid}")


if __name__ == "__main__":
    main()

