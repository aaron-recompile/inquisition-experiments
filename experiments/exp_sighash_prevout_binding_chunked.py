"""Sighash prevout binding (chunked witness for Inquisition signet)."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
import experiments.load_local_env  # noqa: F401

from secp256k1 import PrivateKey as Secp256k1PrivateKey
from bitcoinutils.constants import TAPROOT_SIGHASH_ALL
from bitcoinutils.script import Script as BUScript
from bitcoinutils.setup import setup as bu_setup
bu_setup("signet")

from experiments.opcodes import (
    OP_CAT, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_VERIFY,
    OP_DUP, OP_EQUALVERIFY, OP_OVER, OP_ROT, OP_SIZE,
    OP_SWAP, OP_SHA256, build_script, push_bytes,
)
from btcaaron import Key, RawScript, TapTree
from btcaaron.sigmsg import compute_sigmsg_preimage
from experiments.template_common import (
    broadcast_or_raise, default_change_address, find_template_utxo_or_exit,
)

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "").strip()
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF")

demo_key = Key.from_wif(DEMO_KEY_WIF)


def _wif_to_secret(wif):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b = 0
    for c in wif:
        b = b * 58 + B58.index(c)
    raw = b.to_bytes((b.bit_length() + 7) // 8 or 1, "big").lstrip(b"\x00")
    pad = 37 if len(raw) <= 37 else 38
    raw = (b"\x00" * (pad - len(raw))) + raw
    return raw[1:33]


SECRET = _wif_to_secret(DEMO_KEY_WIF)
SECP_KEY = Secp256k1PrivateKey(SECRET, raw=True)
PUBKEY_X = SECP_KEY.pubkey.serialize()[1:33]

_TAG_HASH = hashlib.sha256(b"TapSighash").digest()
TAG_PREFIX = _TAG_HASH + _TAG_HASH
TAG_HALF1 = TAG_PREFIX[:32]
TAG_HALF2 = TAG_PREFIX[32:]

DEFAULT_FEE = 1500
FUND_SATS_A = 50_000
FUND_SATS_B = 10_000

_DIR = os.path.dirname(__file__)
STATE_FILE = os.path.join(_DIR, ".prevout_binding_chunked_state.json")


def _rpc():
    from config import rpc
    return rpc


def _rpc_wallet():
    from config import rpc_wallet
    return rpc_wallet


def _correct_preimage(inner_tx, txin_index, all_spks, all_amounts, raw_script_hex):
    from bitcoinutils.utils import tagged_hash, prepend_compact_size

    wrong_preimage = compute_sigmsg_preimage(
        inner_tx, txin_index, all_spks, all_amounts,
        ext_flag=1,
        script=BUScript.from_raw(raw_script_hex),
        sighash=TAPROOT_SIGHASH_ALL,
    )

    script_raw = bytes.fromhex(raw_script_hex)
    correct_tapleaf = tagged_hash(
        bytes([0xC0]) + prepend_compact_size(script_raw),
        "TapLeaf",
    )

    base = wrong_preimage[:-37]
    correct_ext = correct_tapleaf + bytes([0]) + b"\xff\xff\xff\xff"
    return base + correct_ext


def _b_program():
    return (TapTree(internal_key=demo_key, network="signet")
            .checksig(demo_key, label="b_keypath").build())


def _a_script_and_program(b_prevout: bytes):
    script_hex = build_script(
        push_bytes(b_prevout),
        OP_CAT,
        OP_SHA256,
        OP_SWAP,
        OP_DUP,
        OP_ROT,
        OP_EQUALVERIFY,

        OP_SWAP,
        OP_SIZE,
        0x5a,
        OP_EQUALVERIFY,

        OP_SWAP,
        OP_CAT,
        OP_SWAP,
        OP_CAT,
        OP_SWAP,
        OP_CAT,
        OP_SWAP,
        OP_CAT,

        push_bytes(TAG_HALF1),
        push_bytes(TAG_HALF2),
        OP_CAT,
        OP_SWAP,
        OP_CAT,
        OP_SHA256,

        OP_OVER,
        OP_SWAP,
        push_bytes(PUBKEY_X),
        OP_CHECKSIGFROMSTACK,
        OP_VERIFY,

        push_bytes(PUBKEY_X),
        OP_CHECKSIG,
    )

    leaf_script = RawScript(script_hex)
    program = (TapTree(internal_key=demo_key, network="signet")
               .custom(script=leaf_script, label="prevout_binding",
                       unlock_hint="chunked prevout binding")
               .build())
    return leaf_script, program


def do_fund():
    rpc = _rpc_wallet()
    print("=== Fund Phase (Chunked) ===")

    b_prog = _b_program()
    print(f"  UTXO B address: {b_prog.address}")

    from btcaaron import wallet_send_sats
    txid_b = wallet_send_sats(rpc, b_prog.address, FUND_SATS_B)
    print(f"  UTXO B funded:  {txid_b}")

    b_utxo = find_template_utxo_or_exit(b_prog.address, txid_b)
    _, vout_b, sats_b = b_utxo
    b_prevout = bytes.fromhex(txid_b)[::-1] + struct.pack("<I", vout_b)

    leaf_script, a_prog = _a_script_and_program(b_prevout)
    print(f"\n  UTXO A address: {a_prog.address}")
    print(f"  UTXO A script:  {leaf_script.to_hex()[:48]}... ({len(leaf_script.to_hex())//2}B)")

    txid_a = wallet_send_sats(rpc, a_prog.address, FUND_SATS_A)
    print(f"  UTXO A funded:  {txid_a}")

    a_utxo = find_template_utxo_or_exit(a_prog.address, txid_a)
    _, vout_a, sats_a = a_utxo

    state = {
        "txid_a": txid_a, "vout_a": vout_a, "sats_a": sats_a,
        "txid_b": txid_b, "vout_b": vout_b, "sats_b": sats_b,
        "b_prevout_hex": b_prevout.hex(),
        "a_address": a_prog.address, "b_address": b_prog.address,
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)
    print(f"\n  State saved: {STATE_FILE}")
    print("  Next: --spend")


def do_spend():
    rpc = _rpc()
    if not os.path.exists(STATE_FILE):
        print("ERROR: run --fund first")
        sys.exit(1)
    with open(STATE_FILE) as f:
        state = json.load(f)

    txid_a, vout_a, sats_a = state["txid_a"], state["vout_a"], state["sats_a"]
    txid_b, vout_b, sats_b = state["txid_b"], state["vout_b"], state["sats_b"]
    b_prevout = bytes.fromhex(state["b_prevout_hex"])

    leaf_script, a_prog = _a_script_and_program(b_prevout)
    b_prog = _b_program()

    total_in = sats_a + sats_b
    out_sats = total_in - DEFAULT_FEE
    change_addr = default_change_address()

    print("=== Spend Phase (Chunked, A + B) ===")
    print(f"  Input A: {txid_a}:{vout_a} ({sats_a} sats)")
    print(f"  Input B: {txid_b}:{vout_b} ({sats_b} sats)")
    print(f"  Output:  {change_addr} ({out_sats} sats)")

    b_spk_hex = _rpc_wallet()("getaddressinfo", b_prog.address)["scriptPubKey"]
    a_prevout = bytes.fromhex(txid_a)[::-1] + struct.pack("<I", vout_a)

    ph = ["00"*64, "00"*36, "00"*32, "00"*10, "00"*57, "00"*57, "00"*56]
    tx_built = (a_prog.spend("prevout_binding")
                .from_utxo(txid_a, vout_a, sats=sats_a)
                .add_external_input(txid_b, vout_b, sats_b,
                                    script_pubkey_hex=b_spk_hex,
                                    sign_keypath=demo_key,
                                    keypath_tweak=b_prog._tree)
                .to(change_addr, out_sats)
                .unlock_with(ph).build())
    inner_tx = tx_built._tx

    a_spk_hex = _rpc_wallet()("getaddressinfo", a_prog.address)["scriptPubKey"]
    all_spks = [BUScript.from_raw(a_spk_hex), BUScript.from_raw(b_spk_hex)]
    all_amounts = [sats_a, sats_b]

    preimage = _correct_preimage(inner_tx, 0, all_spks, all_amounts, leaf_script.to_hex())
    assert len(preimage) == 212, f"Expected 212, got {len(preimage)}"

    sha_prevouts = preimage[10:42]
    expected_sha = hashlib.sha256(a_prevout + b_prevout).digest()
    print(f"\n  sha_prevouts match: {sha_prevouts == expected_sha}")
    assert sha_prevouts == expected_sha

    tagged = hashlib.sha256(TAG_PREFIX + preimage).digest()
    sig = SECP_KEY.schnorr_sign(tagged, "", raw=True)
    print(f"  Signature: {sig.hex()[:24]}... ({len(sig)}B)")

    pre = preimage[0:10]
    sha = preimage[10:42]
    post = preimage[42:212]
    post_a = post[0:57]
    post_b = post[57:114]
    post_c = post[114:170]
    assert (len(pre), len(sha), len(post_a), len(post_b), len(post_c)) == (10, 32, 57, 57, 56)

    witness = [
        sig.hex(),
        post_c.hex(),
        post_b.hex(),
        post_a.hex(),
        pre.hex(),
        sha.hex(),
        a_prevout.hex(),
    ]

    print(f"\n  Witness ({len(witness)} items, all <80B):")
    for i, w in enumerate(witness):
        print(f"    [{i}] {len(w)//2}B: {w[:24]}{'...' if len(w)>24 else ''}")

    tx_final = (a_prog.spend("prevout_binding")
                .from_utxo(txid_a, vout_a, sats=sats_a)
                .add_external_input(txid_b, vout_b, sats_b,
                                    script_pubkey_hex=b_spk_hex,
                                    sign_keypath=demo_key,
                                    keypath_tweak=b_prog._tree)
                .to(change_addr, out_sats)
                .unlock_with(witness).build())

    print(f"\n  Testing...")
    try:
        result = rpc("testmempoolaccept", [tx_final.hex])
        print(f"  testmempoolaccept: {json.dumps(result, indent=2)}")
        if result and result[0].get("allowed"):
            print("\n  RESULT: ACCEPTED")
            spend_txid = broadcast_or_raise(tx_final.hex)
            print(f"  Spend TxID: {spend_txid}")
            state["spend_txid"] = spend_txid
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        else:
            reason = result[0].get("reject-reason", "?") if result else "?"
            print(f"\n  REJECTED: {reason}")
    except Exception as e:
        print(f"  Error: {e}")


def do_attack():
    rpc = _rpc()
    if not os.path.exists(STATE_FILE):
        print("ERROR: run --fund first")
        sys.exit(1)
    with open(STATE_FILE) as f:
        state = json.load(f)

    if "spend_txid" in state:
        print("ERROR: A already spent. Re-run --fund.")
        sys.exit(1)

    txid_a, vout_a, sats_a = state["txid_a"], state["vout_a"], state["sats_a"]
    b_prevout = bytes.fromhex(state["b_prevout_hex"])
    leaf_script, a_prog = _a_script_and_program(b_prevout)

    rpc_w = _rpc_wallet()
    c_prog = (TapTree(internal_key=demo_key, network="signet")
              .checksig(demo_key, label="c_keypath").build())
    from btcaaron import wallet_send_sats
    txid_c = wallet_send_sats(rpc_w, c_prog.address, 10_000)
    c_utxo = find_template_utxo_or_exit(c_prog.address, txid_c)
    _, vout_c, sats_c = c_utxo
    c_spk_hex = rpc_w("getaddressinfo", c_prog.address)["scriptPubKey"]

    print("=== Attack Phase (Chunked, Replace B with C) ===")
    print(f"  Input A: {txid_a}:{vout_a}")
    print(f"  Input C: {txid_c}:{vout_c} (replacing B)")

    a_prevout = bytes.fromhex(txid_a)[::-1] + struct.pack("<I", vout_a)
    total_in = sats_a + sats_c
    out_sats = total_in - DEFAULT_FEE
    change_addr = default_change_address()

    ph = ["00"*64, "00"*36, "00"*32, "00"*10, "00"*57, "00"*57, "00"*56]
    tx_built = (a_prog.spend("prevout_binding")
                .from_utxo(txid_a, vout_a, sats=sats_a)
                .add_external_input(txid_c, vout_c, sats_c,
                                    script_pubkey_hex=c_spk_hex,
                                    sign_keypath=demo_key,
                                    keypath_tweak=c_prog._tree)
                .to(change_addr, out_sats)
                .unlock_with(ph).build())
    inner_tx = tx_built._tx

    a_spk_hex = rpc_w("getaddressinfo", a_prog.address)["scriptPubKey"]
    all_spks = [BUScript.from_raw(a_spk_hex), BUScript.from_raw(c_spk_hex)]
    all_amounts = [sats_a, sats_c]

    preimage = _correct_preimage(inner_tx, 0, all_spks, all_amounts, leaf_script.to_hex())

    sha_actual = preimage[10:42]
    c_prevout = bytes.fromhex(txid_c)[::-1] + struct.pack("<I", vout_c)
    exp_b = hashlib.sha256(a_prevout + b_prevout).digest()
    print(f"\n  sha_prevouts (with C): {sha_actual.hex()[:24]}...")
    print(f"  Expected (with B):     {exp_b.hex()[:24]}...")
    print(f"  Match: {sha_actual == exp_b}")

    tagged = hashlib.sha256(TAG_PREFIX + preimage).digest()
    sig = SECP_KEY.schnorr_sign(tagged, "", raw=True)

    pre = preimage[0:10]
    sha = preimage[10:42]
    post = preimage[42:212]
    post_a, post_b, post_c = post[0:57], post[57:114], post[114:170]

    witness = [sig.hex(), post_c.hex(), post_b.hex(), post_a.hex(),
               pre.hex(), sha.hex(), a_prevout.hex()]

    tx_final = (a_prog.spend("prevout_binding")
                .from_utxo(txid_a, vout_a, sats=sats_a)
                .add_external_input(txid_c, vout_c, sats_c,
                                    script_pubkey_hex=c_spk_hex,
                                    sign_keypath=demo_key,
                                    keypath_tweak=c_prog._tree)
                .to(change_addr, out_sats)
                .unlock_with(witness).build())

    print(f"\n  Testing (expected to fail)...")
    try:
        result = rpc("testmempoolaccept", [tx_final.hex])
        print(f"  testmempoolaccept: {json.dumps(result, indent=2)}")
        if result and not result[0].get("allowed", False):
            reason = result[0].get("reject-reason", "?")
            print(f"\n  Rejected as expected: {reason}")
        else:
            print("\n  UNEXPECTED: attack was not blocked")
    except Exception as e:
        print(f"  REJECTED: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sighash Prevout Binding (Chunked)")
    parser.add_argument("--fund", action="store_true")
    parser.add_argument("--spend", action="store_true")
    parser.add_argument("--attack", action="store_true")
    args = parser.parse_args()

    if args.fund:
        do_fund()
    elif args.spend:
        do_spend()
    elif args.attack:
        do_attack()
    else:
        parser.print_help()
        print("\n  --fund     Fund UTXOs A and B")
        print("  --spend    Spend A+B (positive test)")
        print("  --attack   Replace B with C (negative test)")
