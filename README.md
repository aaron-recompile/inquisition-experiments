# Bitcoin Inquisition Experiments

Python experiments on [Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) signet. Each script produces **real on-chain transactions**; TxIDs prove they were run.

## Why this repo

- **Minimal Python scaffolding** — Swap in your WIF, point at your node, run. No ceremony.
- **On-chain proof** — Real signet TxIDs; anyone can verify the experiment structure.
- **btcaaron in action** — [btcaaron](https://github.com/aaron-recompile/btcaaron): pragmatic Taproot toolkit for reproducible experiments and script-path development.

## Experiment

| Experiment | Description | Commit TxID | Reveal TxID |
|------------|-------------|-------------|-------------|
| **cat** | OP_CAT witness lock: data in witness, only holder of part_a/part_b can spend. | `084d5a9c6a8c176c24edc0a8b7ce54ed65808a326367d8a9299b4460ecaada09` | `00072d4aa354b5987eb8f2ffec440db7467b0581c5e845a6a0ef6999b2d05656` |
| **csfs** | OP_CHECKSIGFROMSTACK: BIP340 sign arbitrary message, verify in script. | `96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3` | `a5260c3dee88b1c0949ea71a57f8f0481f399a84fc89d59c38ac877149908e95` |
| **ctv** | OP_CHECKTEMPLATEVERIFY: commit to output template, spend tx must match exactly. | `2378642548c7f86472d3998a0fcb2d364084783e487dd87c1e1020684aed51de` | `9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c` |

Full TxIDs and addresses: [results/transactions.md](results/transactions.md)

## Pipeline (planned)

- **INTERNALKEY** — OP_INTERNALKEY: reference internal key in script path

## Requirements

- [Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) node (signet)
- Python 3.10+
- [btcaaron](https://github.com/aaron-recompile/btcaaron) — Taproot toolkit
- secp256k1

```bash
pip install btcaaron secp256k1
```

## Run

```bash
# Set INQUISITION_DATADIR (path to your Inquisition node)
# If using btcrun: same as datadir in ~/.btcrun/config.toml [instances.inquisition]
export INQUISITION_DATADIR=/path/to/inquisition-data

# Set CAT_DEMO_WIF — your signet WIF (shared by cat, csfs, etc.)
# No wallet? Generate one: PYTHONPATH=. python3 scripts/gen_wif.py
export CAT_DEMO_WIF="your_signet_wif..."

# If using btcrun inquisition (port 38335):
export INQUISITION_RPC_PORT=38335

PYTHONPATH=. python3 experiments/cat.py          # OP_CAT
PYTHONPATH=. python3 experiments/csfs.py         # OP_CHECKSIGFROMSTACK
PYTHONPATH=. python3 experiments/ctv.py           # OP_CHECKTEMPLATEVERIFY

# CSFS high-fee re-broadcast (RBF style, same commit UTXO):
PYTHONPATH=. python3 experiments/csfs.py --spend 96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3 --fee-sats 5000
```

## Sensitivity / negative tests

Intentional failure tests to verify rule sensitivity:

```bash
# CSFS negatives
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_msg
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_sig
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_pubkey

# CTV negatives
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_amount
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_sequence

# CTV acceleration via CPFP (parent reveal + high-fee child package)
PYTHONPATH=. python3 experiments/ctv_cpfp.py --parent-txid 9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c --fee-sats 10000
```

Result notes: `results/negative_test_results.md`

Run full suite + append report:

```bash
PYTHONPATH=. python3 scripts/run_negative_suite.py
```

## Confirmation Tracking (one command)

When confirmations can take hours/days, run one command to snapshot status and waiting intervals:

```bash
PYTHONPATH=. python3 scripts/check_tx_status.py
```

Outputs:

- `results/confirmation_snapshots.jsonl` (append-only timeline)
- `results/confirmation_status.md` (latest human-readable status)
- watchlist source: `results/TX_WATCHLIST.json`

## Related

- [btcrun](https://github.com/aaron-recompile/btcrun) — sibling project: multi-chain manager. Manages multiple bitcoinds on one machine: mainnet, testnet, regtest (local mining), and signet variants (BOSS Challenge, **Inquisition**). Inquisition uses a source-compiled binary (`bitcoind_path`), not the system Bitcoin Core — btcrun unifies start/stop/status across all of them.

## Structure

```
inquisition-experiments/
├── README.md
├── config.py           # RPC settings (set INQUISITION_DATADIR env or edit)
├── requirements.txt
├── experiments/
│   ├── cat.py
│   ├── csfs.py
│   ├── ctv.py
│   └── opcodes.py
├── scripts/
│   └── gen_wif.py    # Generate WIF (no node needed)
└── results/
    ├── transactions.md
    ├── WORKLOG.md       # Wallet reuse, faucet notes
    ├── commit_084d5a9c.json
    └── spend_00072d4a.json
```
