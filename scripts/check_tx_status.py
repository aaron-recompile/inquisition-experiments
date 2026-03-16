"""
One-command tracker for commit/reveal confirmation status.

Usage:
  PYTHONPATH=. python3 scripts/check_tx_status.py
  PYTHONPATH=. python3 scripts/check_tx_status.py --watchlist results/TX_WATCHLIST.json

Outputs:
  - results/confirmation_snapshots.jsonl (append-only)
  - results/confirmation_status.md (latest human-readable snapshot)
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import os
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WATCHLIST = ROOT / "results" / "TX_WATCHLIST.json"
SNAPSHOT_JSONL = ROOT / "results" / "confirmation_snapshots.jsonl"
STATUS_MD = ROOT / "results" / "confirmation_status.md"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(ts: int | float) -> str:
    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fmt_seconds(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    return str(dt.timedelta(seconds=seconds))


def parse_rpc_error(exc: Exception) -> str:
    msg = str(exc).strip()
    if "RPC error:" in msg:
        return msg.split("RPC error:", 1)[1].strip()
    return msg


def bootstrap_env_from_btcrun_config() -> None:
    """
    If INQUISITION_DATADIR is missing, try to infer from ~/.btcrun/config.toml.
    """
    if os.environ.get("INQUISITION_DATADIR"):
        return
    cfg_path = Path.home() / ".btcrun" / "config.toml"
    if not cfg_path.exists():
        return
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore
        data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return

    instances = data.get("instances", {})
    if not isinstance(instances, dict):
        return

    inq = instances.get("inquisition") or instances.get("signet_inquisition")
    if not isinstance(inq, dict):
        # best effort: first instance containing "inquisition"
        for name, item in instances.items():
            if "inquisition" in str(name).lower() and isinstance(item, dict):
                inq = item
                break
    if not isinstance(inq, dict):
        return

    datadir = inq.get("datadir")
    port = inq.get("rpcport")
    if datadir and not os.environ.get("INQUISITION_DATADIR"):
        os.environ["INQUISITION_DATADIR"] = str(datadir)
    if port and not os.environ.get("INQUISITION_RPC_PORT"):
        os.environ["INQUISITION_RPC_PORT"] = str(port)


_RPC_FUNCS: tuple[Any, Any] | None = None


def _config_funcs():
    global _RPC_FUNCS
    if _RPC_FUNCS is not None:
        return _RPC_FUNCS
    bootstrap_env_from_btcrun_config()
    cfg = importlib.import_module("config")
    # reload to re-read env if set by bootstrap
    cfg = importlib.reload(cfg)
    _RPC_FUNCS = (cfg.rpc, cfg.rpc_wallet)
    return _RPC_FUNCS


def safe_rpc(method: str, *params: Any) -> tuple[Any | None, str | None]:
    rpc, _ = _config_funcs()
    try:
        return rpc(method, *params), None
    except Exception as exc:
        return None, parse_rpc_error(exc)


def safe_rpc_wallet(method: str, *params: Any, wallet: str = "lab") -> tuple[Any | None, str | None]:
    _, rpc_wallet = _config_funcs()
    try:
        return rpc_wallet(method, *params, wallet=wallet), None
    except Exception as exc:
        return None, parse_rpc_error(exc)


def resolve_reveal(
    txid: str, wallet: str, now_epoch: int
) -> dict[str, Any]:
    """
    Prefer getrawtransaction (node scope), fallback to gettransaction (wallet scope).
    """
    raw, raw_err = safe_rpc("getrawtransaction", txid, 1)
    reveal = {
        "txid": txid,
        "source": None,
        "in_mempool": False,
        "confirmed": False,
        "confirmations": 0,
        "blockhash": None,
        "first_seen_epoch": None,
        "first_seen_utc": None,
        "confirm_epoch": None,
        "confirm_utc": None,
        "error": None,
    }

    mempool, mempool_err = safe_rpc("getmempoolentry", txid)
    if mempool is not None:
        reveal["in_mempool"] = True
        first_seen = int(mempool.get("time", 0) or 0)
        if first_seen > 0:
            reveal["first_seen_epoch"] = first_seen
            reveal["first_seen_utc"] = iso(first_seen)
    elif mempool_err and "not in mempool" not in mempool_err.lower():
        reveal["error"] = f"getmempoolentry: {mempool_err}"

    if isinstance(raw, dict):
        reveal["source"] = "getrawtransaction"
        conf = int(raw.get("confirmations", 0) or 0)
        reveal["confirmations"] = conf
        reveal["confirmed"] = conf > 0
        reveal["blockhash"] = raw.get("blockhash")
        if reveal["confirmed"]:
            bt = int(raw.get("blocktime", 0) or 0)
            if bt > 0:
                reveal["confirm_epoch"] = bt
                reveal["confirm_utc"] = iso(bt)
        if not reveal["first_seen_epoch"]:
            t = int(raw.get("time", 0) or 0)
            if t > 0:
                reveal["first_seen_epoch"] = t
                reveal["first_seen_utc"] = iso(t)
        return reveal

    wallet_tx, wallet_err = safe_rpc_wallet("gettransaction", txid, wallet=wallet)
    if isinstance(wallet_tx, dict):
        reveal["source"] = "gettransaction"
        conf = int(wallet_tx.get("confirmations", 0) or 0)
        reveal["confirmations"] = conf
        reveal["confirmed"] = conf > 0
        reveal["blockhash"] = wallet_tx.get("blockhash")
        t = int(wallet_tx.get("time", 0) or 0)
        if t > 0 and not reveal["first_seen_epoch"]:
            reveal["first_seen_epoch"] = t
            reveal["first_seen_utc"] = iso(t)
        if reveal["confirmed"]:
            bt = int(wallet_tx.get("blocktime", 0) or 0)
            if bt > 0:
                reveal["confirm_epoch"] = bt
                reveal["confirm_utc"] = iso(bt)
        return reveal

    reveal["error"] = (
        f"getrawtransaction failed ({raw_err or 'unknown'}) ; "
        f"gettransaction failed ({wallet_err or 'unknown'})"
    )
    return reveal


def resolve_commit(txid: str, wallet: str) -> dict[str, Any]:
    tx, err = safe_rpc_wallet("gettransaction", txid, wallet=wallet)
    commit = {
        "txid": txid,
        "found": False,
        "broadcast_epoch": None,
        "broadcast_utc": None,
        "confirmations": 0,
        "blockhash": None,
        "error": None,
    }
    if isinstance(tx, dict):
        commit["found"] = True
        t = int(tx.get("time", 0) or 0)
        if t > 0:
            commit["broadcast_epoch"] = t
            commit["broadcast_utc"] = iso(t)
        conf = int(tx.get("confirmations", 0) or 0)
        commit["confirmations"] = conf
        commit["blockhash"] = tx.get("blockhash")
    else:
        commit["error"] = err or "commit tx not found in wallet scope"
    return commit


def compute_intervals(commit: dict[str, Any], reveal: dict[str, Any], now_epoch: int) -> dict[str, Any]:
    commit_to_reveal = None
    reveal_to_confirm = None
    reveal_to_now = None

    c = commit.get("broadcast_epoch")
    r = reveal.get("first_seen_epoch")
    k = reveal.get("confirm_epoch")

    if isinstance(c, int) and isinstance(r, int):
        commit_to_reveal = max(0, r - c)
    if isinstance(r, int) and isinstance(k, int):
        reveal_to_confirm = max(0, k - r)
    elif isinstance(r, int):
        reveal_to_now = max(0, now_epoch - r)

    return {
        "commit_to_reveal_seconds": commit_to_reveal,
        "reveal_to_confirm_seconds": reveal_to_confirm,
        "reveal_to_now_seconds": reveal_to_now,
    }


def load_watchlist(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_snapshot(snapshot: dict[str, Any]) -> None:
    SNAPSHOT_JSONL.parent.mkdir(parents=True, exist_ok=True)
    with SNAPSHOT_JSONL.open("a", encoding="utf-8") as f:
        f.write(json.dumps(snapshot, ensure_ascii=False) + "\n")


def write_status_md(snapshot: dict[str, Any]) -> None:
    now_iso = snapshot["snapshot_utc"]
    node = snapshot.get("node", {})
    lines: list[str] = []
    lines.append("# Confirmation Status Snapshot")
    lines.append("")
    lines.append(f"- Snapshot UTC: `{now_iso}`")
    if node:
        lines.append(f"- Node: chain=`{node.get('chain')}` blocks=`{node.get('blocks')}` bestblock=`{node.get('bestblockhash')}`")
    lines.append("")
    lines.append("| Experiment | Commit | Reveal | Reveal state | commit->reveal | reveal->confirm | reveal->now |")
    lines.append("|------------|--------|--------|--------------|----------------|-----------------|-------------|")

    for exp in snapshot.get("experiments", []):
        name = exp["name"]
        commit_txid = exp["commit"]["txid"]
        reveal_txid = exp["reveal"]["txid"]
        reveal_state = (
            "confirmed"
            if exp["reveal"]["confirmed"]
            else ("mempool" if exp["reveal"]["in_mempool"] else "unknown")
        )
        i = exp["intervals"]
        c2r = i["commit_to_reveal_seconds"]
        r2c = i["reveal_to_confirm_seconds"]
        r2n = i["reveal_to_now_seconds"]
        lines.append(
            f"| {name} | `{commit_txid}` | `{reveal_txid}` | `{reveal_state}` | "
            f"`{c2r if c2r is not None else '-'}` ({fmt_seconds(c2r)}) | "
            f"`{r2c if r2c is not None else '-'}` ({fmt_seconds(r2c)}) | "
            f"`{r2n if r2n is not None else '-'}` ({fmt_seconds(r2n)}) |"
        )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- `commit->reveal` uses commit wallet `time` and reveal mempool first-seen time.")
    lines.append("- `reveal->confirm` appears only after reveal has block confirmation.")
    lines.append("- While pending, `reveal->now` tracks real waiting time so it is not forgotten.")
    STATUS_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Track commit/reveal confirmation progress.")
    parser.add_argument("--watchlist", default=str(DEFAULT_WATCHLIST), help="Path to watchlist JSON.")
    parser.add_argument("--wallet", default="lab", help="Wallet name for gettransaction lookup.")
    args = parser.parse_args()

    watchlist_path = Path(args.watchlist).resolve()
    if not watchlist_path.exists():
        raise SystemExit(f"Watchlist not found: {watchlist_path}")

    watch = load_watchlist(watchlist_path)
    now = utc_now()
    now_epoch = int(now.timestamp())
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    info, info_err = safe_rpc("getblockchaininfo")
    node = {}
    if isinstance(info, dict):
        node = {
            "chain": info.get("chain"),
            "blocks": info.get("blocks"),
            "bestblockhash": info.get("bestblockhash"),
        }
    else:
        node = {"error": info_err or "cannot fetch getblockchaininfo"}

    experiments = []
    for item in watch.get("experiments", []):
        name = item["name"]
        commit_txid = item["commit_txid"]
        reveal_txid = item["reveal_txid"]
        commit = resolve_commit(commit_txid, wallet=args.wallet)
        reveal = resolve_reveal(reveal_txid, wallet=args.wallet, now_epoch=now_epoch)
        intervals = compute_intervals(commit, reveal, now_epoch)
        experiments.append(
            {
                "name": name,
                "commit": commit,
                "reveal": reveal,
                "intervals": intervals,
            }
        )

    snapshot = {
        "snapshot_utc": now_iso,
        "snapshot_epoch": now_epoch,
        "wallet": args.wallet,
        "watchlist": str(watchlist_path),
        "node": node,
        "experiments": experiments,
    }

    write_snapshot(snapshot)
    write_status_md(snapshot)
    print(f"Snapshot written: {SNAPSHOT_JSONL}")
    print(f"Status updated:   {STATUS_MD}")

    for exp in experiments:
        st = "confirmed" if exp["reveal"]["confirmed"] else ("mempool" if exp["reveal"]["in_mempool"] else "unknown")
        i = exp["intervals"]
        print(
            f"[{exp['name']}] state={st} "
            f"commit->reveal={i['commit_to_reveal_seconds']}s "
            f"reveal->confirm={i['reveal_to_confirm_seconds']}s "
            f"reveal->now={i['reveal_to_now_seconds']}s"
        )


if __name__ == "__main__":
    main()

