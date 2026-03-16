"""
OP_CHECKTEMPLATEVERIFY (BIP119) — commit to output template.
Script: push <hash> OP_CTV. Spend tx must match template exactly.
Run: PYTHONPATH=. python3 experiments/ctv.py [--fund|--spend]
"""
import sys
import struct
import hashlib

sys.path.insert(0, ".")

from experiments.opcodes import build_script, push_bytes, OP_CHECKTEMPLATEVERIFY
from btcaaron import TapTree, Key, RawScript

# Fixed amounts for demo: fund 50000 sats, fee 500, output 49500
FUND_SATS = 50_000
FEE_SATS = 500
OUTPUT_SATS = FUND_SATS - FEE_SATS

DEMO_KEY_WIF = __import__("os").environ.get("CAT_DEMO_WIF", "")
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF (signet WIF for internal key), or edit ctv.py")
key = Key.from_wif(DEMO_KEY_WIF)

FUND_TXID_FILE = __file__.replace("ctv.py", ".ctv_fund_txid")
CHANGE_ADDR_FILE = __file__.replace("ctv.py", ".ctv_change_addr")


def _ser_compact_size(n: int) -> bytes:
    if n < 253:
        return struct.pack("B", n)
    if n < 0x10000:
        return struct.pack("<BH", 253, n)
    if n < 0x100000000:
        return struct.pack("<BI", 254, n)
    return struct.pack("<BQ", 255, n)


def _ser_string(s: bytes) -> bytes:
    return _ser_compact_size(len(s)) + s


def _ser_txout(n_value: int, script_pubkey: bytes) -> bytes:
    return struct.pack("<q", n_value) + _ser_string(script_pubkey)


def compute_ctv_hash(
    n_version: int,
    n_locktime: int,
    n_vin: int,
    sequences: bytes,
    n_vout: int,
    outputs_serialized: bytes,
    n_in: int,
) -> bytes:
    """Compute DefaultCheckTemplateVerifyHash per BIP119."""
    precomputed = {
        "sequences": hashlib.sha256(sequences).digest(),
        "outputs": hashlib.sha256(outputs_serialized).digest(),
    }
    r = b""
    r += struct.pack("<i", n_version)
    r += struct.pack("<I", n_locktime)
    r += struct.pack("<I", n_vin)
    r += precomputed["sequences"]
    r += struct.pack("<I", n_vout)
    r += precomputed["outputs"]
    r += struct.pack("<I", n_in)
    return hashlib.sha256(r).digest()


def _get_script_pubkey_hex(addr: str) -> str:
    """Get scriptPubKey hex for address via RPC getaddressinfo."""
    from config import rpc_wallet
    info = rpc_wallet("getaddressinfo", addr)
    return info["scriptPubKey"]


def _build_ctv_address(change_addr: str) -> tuple:
    """Build CTV address and program from change_addr. Returns (addr, program, template_hash)."""
    script_pubkey = bytes.fromhex(_get_script_pubkey_hex(change_addr))
    out_ser = _ser_txout(OUTPUT_SATS, script_pubkey)
    seq = struct.pack("<I", 0xFFFFFFFF)
    template_hash = compute_ctv_hash(
        n_version=2,
        n_locktime=0,
        n_vin=1,
        sequences=seq,
        n_vout=1,
        outputs_serialized=out_ser,
        n_in=0,
    )
    script_hex = build_script(push_bytes(template_hash), OP_CHECKTEMPLATEVERIFY)
    leaf_script = RawScript(script_hex)
    tap_tree = (
        TapTree(internal_key=key, network="signet")
        .custom(script=leaf_script, label="ctv")
    ).build()
    return tap_tree.address, tap_tree, template_hash


def print_setup():
    print("OP_CHECKTEMPLATEVERIFY — commit to output template")
    print("Run: --fund, --spend (spend tx must match template exactly)")
    print("Requires node for --fund (to get change address)")


def do_fund():
    from config import rpc_wallet

    change_addr = rpc_wallet("getrawchangeaddress", "bech32m") or rpc_wallet(
        "getnewaddress", "change", "bech32m"
    )
    with open(CHANGE_ADDR_FILE, "w") as f:
        f.write(change_addr)

    addr, program, _ = _build_ctv_address(change_addr)
    txid = rpc_wallet(
        "sendtoaddress", addr, FUND_SATS / 1e8, "", "", False, False, None, "unset", False, 1
    )
    with open(FUND_TXID_FILE, "w") as f:
        f.write(txid)
    print(f"Commit TxID: {txid}")
    print(f"Change addr (saved): {change_addr}")


def _find_utxo_via_txid(txid, addr):
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

    if not __import__("os").path.exists(CHANGE_ADDR_FILE):
        print("No change addr. Run --fund first.")
        sys.exit(1)
    with open(CHANGE_ADDR_FILE) as f:
        change_addr = f.read().strip()

    _, program, _ = _build_ctv_address(change_addr)
    addr = program.address

    utxo = None
    if txid_arg:
        utxo = _find_utxo_via_txid(txid_arg, addr)
    elif __import__("os").path.exists(FUND_TXID_FILE):
        with open(FUND_TXID_FILE) as f:
            utxo = _find_utxo_via_txid(f.read().strip(), addr)

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
    if sats != FUND_SATS:
        print(f"Warning: UTXO has {sats} sats, expected {FUND_SATS}. Fee may differ.")

    tx = (
        program.spend("ctv")
        .from_utxo(txid, vout, sats=sats)
        .to(change_addr, OUTPUT_SATS)
        .sequence(0xFFFFFFFF)
        .unlock_with([])
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
