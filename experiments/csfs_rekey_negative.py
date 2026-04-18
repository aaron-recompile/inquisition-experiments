"""
CSFS Re-Keying negative tests (intentional failures).

Validates that the re-key script rejects:
  - bad_delegation: tampered delegation signature
  - wrong_guardian: spending with an unauthorized key (C instead of B)
  - no_delegation:  skipping delegation entirely (random sig)

All cases use testmempoolaccept (no broadcast).

Run:
  PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case bad_delegation
  PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case wrong_guardian
  PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case no_delegation
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, ".")

from experiments.csfs_rekey import (
    DELEGATION_FILE,
    FUND_TXID_FILE,
    SECRET_A,
    SECRET_B,
    addr,
    program,
)


# Guardian C: an unauthorized third party.
SECRET_C = hashlib.sha256(SECRET_A + b"guardian_c_intruder").digest()


def _get_all_keys():
    from secp256k1 import PrivateKey

    pk_a = PrivateKey(SECRET_A, raw=True)
    pub_a_x = pk_a.pubkey.serialize()[1:33]
    pk_b = PrivateKey(SECRET_B, raw=True)
    pub_b_x = pk_b.pubkey.serialize()[1:33]
    pk_c = PrivateKey(SECRET_C, raw=True)
    pub_c_x = pk_c.pubkey.serialize()[1:33]
    return pk_a, pub_a_x, pk_b, pub_b_x, pk_c, pub_c_x


def _resolve_utxo(txid_arg: str | None):
    from config import rpc

    if txid_arg:
        try:
            raw = rpc("getrawtransaction", txid_arg, 1)
            if raw:
                for out in raw.get("vout", []):
                    if out.get("scriptPubKey", {}).get("address") == addr:
                        return txid_arg, out["n"], int(out["value"] * 1e8)
        except Exception:
            pass

    if os.path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE) as f:
            stored_txid = f.read().strip()
        try:
            raw = rpc("getrawtransaction", stored_txid, 1)
            if raw:
                for out in raw.get("vout", []):
                    if out.get("scriptPubKey", {}).get("address") == addr:
                        return stored_txid, out["n"], int(out["value"] * 1e8)
        except Exception:
            pass

    try:
        rpc("scantxoutset", "abort")
    except Exception:
        pass
    scan = rpc("scantxoutset", "start", json.dumps([f"addr({addr})"]))
    unspents = scan.get("unspents", [])
    if not unspents:
        raise RuntimeError("No UTXO for re-key address. Run csfs_rekey.py --fund first.")
    u = unspents[0]
    return u["txid"], u["vout"], int(u["value"] * 1e8)


def _build_bad_witness(case_name: str) -> list[str]:
    """Build an intentionally invalid witness for the given negative case."""
    pk_a, pub_a_x, pk_b, pub_b_x, pk_c, pub_c_x = _get_all_keys()

    # Valid delegation: A signs B's pubkey
    valid_delegation_sig = pk_a.schnorr_sign(pub_b_x, "", raw=True)

    # Spend commitment (arbitrary for testing)
    spend_commitment = hashlib.sha256(b"negative_test_destination").digest()

    if case_name == "bad_delegation":
        # Tamper with A's delegation signature (flip a byte)
        bad_sig = bytearray(valid_delegation_sig)
        bad_sig[0] ^= 0x01
        spend_sig = pk_b.schnorr_sign(spend_commitment, "", raw=True)
        return [
            spend_sig.hex(),
            spend_commitment.hex(),
            pub_b_x.hex(),
            bytes(bad_sig).hex(),
            pub_b_x.hex(),
        ]

    elif case_name == "wrong_guardian":
        # C tries to spend, but delegation is to B (not C).
        # A actually signed B's pubkey, but C presents C's pubkey + C's spend sig.
        delegation_sig_a_over_b = valid_delegation_sig
        spend_sig_c = pk_c.schnorr_sign(spend_commitment, "", raw=True)
        # Witness claims key_C, but delegation was for key_B → CSFS #1 fails
        # because msg (key_C) != what A signed (key_B)
        return [
            spend_sig_c.hex(),
            spend_commitment.hex(),
            pub_c_x.hex(),
            delegation_sig_a_over_b.hex(),
            pub_c_x.hex(),  # wrong key — not the delegatee
        ]

    elif case_name == "no_delegation":
        # B tries to spend without valid delegation.
        # Use a random/self-signed "delegation" (B signs B, not A signs B).
        fake_delegation = pk_b.schnorr_sign(pub_b_x, "", raw=True)
        spend_sig = pk_b.schnorr_sign(spend_commitment, "", raw=True)
        return [
            spend_sig.hex(),
            spend_commitment.hex(),
            pub_b_x.hex(),
            fake_delegation.hex(),  # B signed this, not A
            pub_b_x.hex(),
        ]

    else:
        raise ValueError(f"Unknown case: {case_name}")


def run_negative(case_name: str, txid_arg: str | None):
    from config import rpc, rpc_wallet

    txid, vout, sats = _resolve_utxo(txid_arg)
    change_addr = (
        rpc_wallet("getrawchangeaddress", "bech32m")
        or rpc_wallet("getnewaddress", "change", "bech32m")
    )

    witness = _build_bad_witness(case_name)

    tx = (
        program.spend("rekey")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - 500)
        .unlock_with(witness)
        .build()
    )

    result = rpc("testmempoolaccept", [tx.hex])[0]
    print(f"Case: {case_name}")
    print(json.dumps(result, indent=2))
    if result.get("allowed", False):
        print("WARNING: tx unexpectedly accepted (negative case should fail).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSFS Re-Keying negative tests")
    parser.add_argument(
        "--case",
        choices=["bad_delegation", "wrong_guardian", "no_delegation"],
        required=True,
    )
    parser.add_argument("--txid", default=None, help="Optional explicit fund txid")
    args = parser.parse_args()
    run_negative(args.case, args.txid)
