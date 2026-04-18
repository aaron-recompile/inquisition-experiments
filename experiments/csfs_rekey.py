"""
CSFS Re-Keying — Key Guardian Rotation (Rubin-style delegation).

Scenario: Guardian A manages a vault. A retires and delegates authority
to Guardian B via an off-chain CSFS signature. B spends the UTXO by
proving A's delegation + B's own spend authorization — all verified
on-chain via double OP_CHECKSIGFROMSTACK.

Taproot structure:
  Key path  → Guardian A direct spend (normal case, no rotation)
  Script leaf "rekey" → CSFS delegation verification (rotation path)

Script:
  <key_A_32> OP_CHECKSIGFROMSTACK OP_VERIFY OP_CHECKSIGFROMSTACK

Witness (stack bottom → top):
  [0] spend_sig_B        — B signs the spend commitment (64B)
  [1] spend_commitment   — SHA256(destination_address) (32B)
  [2] key_B_pubkey       — B's pubkey for CSFS #2 (32B)
  [3] delegation_sig_A   — A signs B's pubkey (64B)
  [4] key_B_pubkey       — B's pubkey as CSFS #1 message (32B)

Stack trace:
  initial:  spend_sig_B | commit | key_B | del_sig_A | key_B
  PUSH A:   spend_sig_B | commit | key_B | del_sig_A | key_B | key_A
  CSFS #1:  pops (key_A, key_B, del_sig_A) → "A delegated to B"
            spend_sig_B | commit | key_B | ✓
  VERIFY:   spend_sig_B | commit | key_B
  CSFS #2:  pops (key_B, commit, spend_sig_B) → "B authorizes spend"
            ✓

Run:
  PYTHONPATH=. python3 experiments/csfs_rekey.py --fund
  PYTHONPATH=. python3 experiments/csfs_rekey.py --delegate
  PYTHONPATH=. python3 experiments/csfs_rekey.py --spend [TXID] [--fee-sats 500]

Note: In production, CSFS #2 would be replaced by OP_CHECKSIG to bind
the spend authorization to the actual transaction sighash. This experiment
uses double CSFS to focus purely on the delegation mechanism.
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, ".")

from experiments.opcodes import (
    OP_CHECKSIGFROMSTACK,
    OP_VERIFY,
    build_script,
    push_bytes,
)
from btcaaron import Key, RawScript, TapTree

# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for Guardian A)")


def _wif_to_secret(wif: str) -> bytes:
    """Decode WIF to 32-byte raw secret."""
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


SECRET_A = _wif_to_secret(DEMO_KEY_WIF)

# Guardian B: deterministic derivation from A (reproducible, no extra config).
# In production, B would generate their own key independently.
SECRET_B = hashlib.sha256(SECRET_A + b"guardian_b").digest()


def _get_keys():
    """Return (pk_A, pub_A_x, pk_B, pub_B_x) using secp256k1."""
    from secp256k1 import PrivateKey

    pk_a = PrivateKey(SECRET_A, raw=True)
    pub_a_x = pk_a.pubkey.serialize()[1:33]

    pk_b = PrivateKey(SECRET_B, raw=True)
    pub_b_x = pk_b.pubkey.serialize()[1:33]

    return pk_a, pub_a_x, pk_b, pub_b_x


# ---------------------------------------------------------------------------
# Script & address construction
# ---------------------------------------------------------------------------

def _build_rekey_program():
    """Build Taproot program with re-key script leaf."""
    _, pub_a_x, _, pub_b_x = _get_keys()

    # Script: <key_A_32> OP_CHECKSIGFROMSTACK OP_VERIFY OP_CHECKSIGFROMSTACK
    script_hex = build_script(
        push_bytes(pub_a_x),
        OP_CHECKSIGFROMSTACK,
        OP_VERIFY,
        OP_CHECKSIGFROMSTACK,
    )
    leaf_script = RawScript(script_hex)

    key_a = Key.from_wif(DEMO_KEY_WIF)
    program = (
        TapTree(internal_key=key_a, network="signet")
        .custom(script=leaf_script, label="rekey")
    ).build()

    return program


program = _build_rekey_program()
addr = program.address

# Persistent file paths
FUND_TXID_FILE = os.path.join(os.path.dirname(__file__), ".csfs_rekey_fund_txid")
DELEGATION_FILE = os.path.join(os.path.dirname(__file__), ".csfs_rekey_delegation.json")

# ---------------------------------------------------------------------------
# Phase 1: Fund — lock coins to the re-keyable address
# ---------------------------------------------------------------------------

def do_fund():
    from config import rpc_wallet

    _, pub_a_x, _, pub_b_x = _get_keys()

    print("=== CSFS Re-Keying: Fund (Phase 1) ===")
    print(f"Guardian A pubkey: {pub_a_x.hex()}")
    print(f"Guardian B pubkey: {pub_b_x.hex()}")
    print(f"Re-key address:   {addr}")
    print()
    print("Taproot structure:")
    print("  Key path  → Guardian A (direct spend, no rotation)")
    print("  Script    → CSFS re-key (delegation path)")
    print()

    txid = rpc_wallet(
        "sendtoaddress", addr, 0.0005,
        "", "", False, False, None, "unset", False, 1,
    )
    with open(FUND_TXID_FILE, "w") as f:
        f.write(txid)
    print(f"Fund TxID: {txid}")
    print("Next: --delegate (off-chain, no tx), then --spend")


# ---------------------------------------------------------------------------
# Phase 2: Delegate — A signs B's pubkey off-chain
# ---------------------------------------------------------------------------

def do_delegate():
    pk_a, pub_a_x, _, pub_b_x = _get_keys()

    # The delegation: A signs B's x-only pubkey (32 bytes).
    # This is the "letter of authority" — the message has cryptographic meaning.
    delegation_sig = pk_a.schnorr_sign(pub_b_x, "", raw=True)

    delegation = {
        "guardian_a_pubkey": pub_a_x.hex(),
        "guardian_b_pubkey": pub_b_x.hex(),
        "message": pub_b_x.hex(),
        "delegation_sig": delegation_sig.hex(),
        "note": "Guardian A authorizes Guardian B. Message = B's x-only pubkey.",
    }
    with open(DELEGATION_FILE, "w") as f:
        json.dump(delegation, f, indent=2)

    print("=== CSFS Re-Keying: Delegate (Phase 2) ===")
    print(f"Guardian A ({pub_a_x.hex()[:16]}...) signs delegation to")
    print(f"Guardian B ({pub_b_x.hex()[:16]}...)")
    print(f"Delegation sig: {delegation_sig.hex()[:32]}...")
    print(f"Saved to: {DELEGATION_FILE}")
    print()
    print("This is OFF-CHAIN. No transaction, no fee, no on-chain footprint.")
    print("Next: --spend to use the delegation on-chain.")


# ---------------------------------------------------------------------------
# Phase 3: Spend — B uses delegation proof to spend the UTXO
# ---------------------------------------------------------------------------

def _find_utxo_via_txid(txid):
    from config import rpc

    try:
        raw = rpc("getrawtransaction", txid, 1)
    except Exception:
        return None
    if not raw:
        return None
    for out in raw.get("vout", []):
        if out.get("scriptPubKey", {}).get("address") == addr:
            return txid, out["n"], int(out["value"] * 1e8)
    return None


def do_spend(txid_arg=None, fee_sats=500):
    from config import rpc, rpc_wallet

    # Load delegation
    if not os.path.exists(DELEGATION_FILE):
        print("No delegation found. Run --delegate first.")
        sys.exit(1)
    with open(DELEGATION_FILE) as f:
        delegation = json.load(f)

    delegation_sig_hex = delegation["delegation_sig"]
    pub_b_hex = delegation["guardian_b_pubkey"]

    # Resolve UTXO
    utxo = None
    if txid_arg:
        utxo = _find_utxo_via_txid(txid_arg)
    elif os.path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE) as f:
            utxo = _find_utxo_via_txid(f.read().strip())

    if not utxo:
        try:
            rpc("scantxoutset", "abort")
        except Exception:
            pass
        scan = rpc("scantxoutset", "start", json.dumps([f"addr({addr})"]))
        unspents = scan.get("unspents", [])
        if not unspents:
            print("No UTXO. Run --fund first.")
            sys.exit(1)
        u = unspents[0]
        amt = u.get("value", u.get("amount"))
        if amt is None:
            raise KeyError(f"Unexpected scantxoutset entry: {u}")
        utxo = u["txid"], u["vout"], int(float(amt) * 1e8)

    txid, vout, sats = utxo
    if fee_sats <= 0 or fee_sats >= sats:
        raise ValueError(f"fee_sats={fee_sats} invalid (input={sats} sats)")

    # Get change address (destination for B's spend)
    change_addr = (
        rpc_wallet("getrawchangeaddress", "bech32m")
        or rpc_wallet("getnewaddress", "change", "bech32m")
    )

    # Spend commitment: SHA256 of the destination address.
    # Symbolic binding — in production, use CHECKSIG sighash instead.
    spend_commitment = hashlib.sha256(change_addr.encode()).digest()

    # B signs the spend commitment
    from secp256k1 import PrivateKey

    pk_b = PrivateKey(SECRET_B, raw=True)
    spend_sig = pk_b.schnorr_sign(spend_commitment, "", raw=True)

    # Build witness: [spend_sig_B, commit, key_B, delegation_sig_A, key_B]
    # key_B appears twice: as CSFS #1 message (top) and CSFS #2 pubkey (deeper)
    witness = [
        spend_sig.hex(),
        spend_commitment.hex(),
        pub_b_hex,
        delegation_sig_hex,
        pub_b_hex,
    ]

    tx = (
        program.spend("rekey")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, sats - fee_sats)
        .unlock_with(witness)
        .build()
    )

    print("=== CSFS Re-Keying: Spend (Phase 3) ===")
    print(f"Input:  {txid}:{vout} ({sats} sats)")
    print(f"Output: {change_addr} ({sats - fee_sats} sats)")
    print(f"Fee:    {fee_sats} sats")
    print()
    print("Witness stack:")
    print(f"  [0] spend_sig_B:      {spend_sig.hex()[:32]}...")
    print(f"  [1] spend_commitment: {spend_commitment.hex()[:32]}...")
    print(f"  [2] key_B (CSFS#2):   {pub_b_hex[:32]}...")
    print(f"  [3] delegation_sig_A: {delegation_sig_hex[:32]}...")
    print(f"  [4] key_B (CSFS#1):   {pub_b_hex[:32]}...")
    print()

    reveal_txid = rpc("sendrawtransaction", tx.hex)
    print(f"Spend TxID: {reveal_txid}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_setup():
    _, pub_a_x, _, pub_b_x = _get_keys()
    print("CSFS Re-Keying — Key Guardian Rotation")
    print(f"  Guardian A: {pub_a_x.hex()}")
    print(f"  Guardian B: {pub_b_x.hex()}")
    print(f"  Address:    {addr}")
    print()
    print("Usage:")
    print("  --fund                 Lock coins to re-keyable address")
    print("  --delegate             A signs off-chain delegation to B")
    print("  --spend [TXID]         B spends with delegation proof")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CSFS Re-Keying experiment")
    parser.add_argument("--fund", action="store_true", help="Phase 1: fund the re-key address")
    parser.add_argument("--delegate", action="store_true", help="Phase 2: A delegates to B (off-chain)")
    parser.add_argument("--spend", nargs="?", const="", default=None, metavar="TXID", help="Phase 3: B spends with delegation proof")
    parser.add_argument("--fee-sats", type=int, default=500, help="Fee in satoshis (default: 500)")
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.delegate:
        do_delegate()
    elif args.spend is not None:
        txid_arg = args.spend if args.spend else None
        do_spend(txid_arg, fee_sats=args.fee_sats)
    else:
        print_setup()
