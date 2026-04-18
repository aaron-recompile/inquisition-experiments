# Bitcoin Inquisition Experiments

Python experiments on [Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) signet. Each script produces **real on-chain transactions**; TxIDs prove they were run.

## Why this repo

- **Minimal Python scaffolding** — Swap in your WIF, point at your node, run. No ceremony.
- **On-chain proof** — Real signet TxIDs; anyone can verify the experiment structure.
- **btcaaron in action** — [btcaaron](https://github.com/aaron-recompile/btcaaron): pragmatic Taproot toolkit for reproducible experiments and script-path development.

## Experiments

| Experiment | Description | Fund TxID | Spend TxID |
|------------|-------------|-----------|------------|
| **cat** | OP_CAT witness lock: data in witness, only holder of part_a/part_b can spend. | `084d5a9c6a8c176c24edc0a8b7ce54ed65808a326367d8a9299b4460ecaada09` | `00072d4aa354b5987eb8f2ffec440db7467b0581c5e845a6a0ef6999b2d05656` |
| **csfs** | OP_CHECKSIGFROMSTACK: BIP340 sign arbitrary message, verify in script. | `96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3` | `a5260c3dee88b1c0949ea71a57f8f0481f399a84fc89d59c38ac877149908e95` |
| **ctv** | OP_CHECKTEMPLATEVERIFY: commit to output template, spend tx must match exactly. | `2378642548c7f86472d3998a0fcb2d364084783e487dd87c1e1020684aed51de` | `9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c` |
| **internalkey** | OP_INTERNALKEY: reference the Taproot internal key from script path. | `1428d3e2db6bcc6050053f5fee710ec4c254f375d825486a19da49a4763e7676` | — |
| **apo_template** | BIP-118 (SIGHASH_ANYPREVOUT) tapscript template. | `4b6451082fe4349fdb2acad6bf0964c6cfd8c9cbf5161806fc342b051dee344a` | — |
| **csfs_rekey** | CSFS off-chain key delegation: A signs B's pubkey, B later spends with the delegation + own signature. | `219655b5823f4b5a3319f16b107b8f7c7f0faa41b112d64b20d905528f5c8e97` | `0177142057e0e271e12c84be8ac0694e461cb32c40f0e7f09351aa64cb2f6b3f` |

Full TxIDs and addresses: [results/transactions.md](results/transactions.md)

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
# Optional: one-time `.env` at repo root (or under
# experiments/bitcoin-signature-binding-experiments/.env) — scripts load it
# automatically; you do not need to export CAT_DEMO_WIF / INQUISITION_* every shell.

# Set INQUISITION_DATADIR (path to your Inquisition node)
# If using btcrun: same as datadir in ~/.btcrun/config.toml [instances.inquisition]
export INQUISITION_DATADIR=/path/to/inquisition-data

# Set CAT_DEMO_WIF — your signet WIF (shared by all template experiments)
# No wallet? Generate one: PYTHONPATH=. python3 scripts/gen_wif.py
export CAT_DEMO_WIF="your_signet_wif..."

# If using btcrun inquisition (port 38335):
export INQUISITION_RPC_PORT=38335

# Core opcode demos
PYTHONPATH=. python3 experiments/cat.py          # OP_CAT
PYTHONPATH=. python3 experiments/csfs.py         # OP_CHECKSIGFROMSTACK
PYTHONPATH=. python3 experiments/ctv.py          # OP_CHECKTEMPLATEVERIFY

# Template-style experiments
PYTHONPATH=. python3 experiments/internalkey_template.py --fund
PYTHONPATH=. python3 experiments/internalkey_template.py --spend

PYTHONPATH=. python3 experiments/apo_template.py --fund
PYTHONPATH=. python3 experiments/apo_template.py --spend

# CSFS Re-Keying (3-phase: fund → delegate off-chain → spend with delegation)
PYTHONPATH=. python3 experiments/csfs_rekey.py --fund
PYTHONPATH=. python3 experiments/csfs_rekey.py --delegate
PYTHONPATH=. python3 experiments/csfs_rekey.py --spend

# CSFS high-fee re-broadcast (RBF style, same commit UTXO)
PYTHONPATH=. python3 experiments/csfs.py --spend 96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3 --fee-sats 5000
```

### Wallet: load `lab` after restart

Experiments call `rpc_wallet` with wallet name **`lab`**. If you see **RPC -18** (wallet not loaded), load it once per bitcoind restart:

```bash
btcrun core rpc inquisition loadwallet '"lab"'
# or: btcrun inq load-wallet lab
```

Raw `bitcoin-cli`:

```bash
bitcoin-cli -datadir="$INQUISITION_DATADIR" loadwallet lab
```

Don't pass `-signet` together with `-datadir=...` — the datadir's `bitcoin.conf` already selects signet.

## Sensitivity / negative tests

Intentional-failure tests verify rule sensitivity:

```bash
# CSFS negatives
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_msg
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_sig
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_pubkey

# CSFS Re-Keying negatives
PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case bad_delegation
PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case wrong_guardian
PYTHONPATH=. python3 experiments/csfs_rekey_negative.py --case no_delegation

# INTERNALKEY negatives
PYTHONPATH=. python3 experiments/internalkey_negative.py --case wrong_expected_key

# CTV negatives
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_amount
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_sequence

# CTV acceleration via CPFP (parent reveal + high-fee child package)
PYTHONPATH=. python3 experiments/ctv_cpfp.py --parent-txid 9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c --fee-sats 10000
```

Result notes: [results/negative_test_results.md](results/negative_test_results.md)

Run the full suite + append a report:

```bash
PYTHONPATH=. python3 scripts/run_negative_suite.py
```

## Confirmation tracking

When confirmations take hours/days, snapshot status with one command:

```bash
PYTHONPATH=. python3 scripts/check_tx_status.py
```

Outputs:
- `results/confirmation_snapshots.jsonl` (append-only timeline)
- `results/confirmation_status.md` (latest human-readable status)
- watchlist source: `results/TX_WATCHLIST.json`

## Related

- [btcaaron](https://github.com/aaron-recompile/btcaaron) — pragmatic Taproot toolkit (legacy / SegWit / Taproot, plus Inquisition opcode templates).
- [btcrun](https://github.com/aaron-recompile/btcrun) — multi-chain bitcoind manager: mainnet, testnet, regtest, and signet variants (BOSS Challenge, Inquisition).

## Structure

```
inquisition-experiments/
├── README.md
├── config.py               # RPC settings (set INQUISITION_DATADIR env or edit)
├── requirements.txt
├── experiments/
│   ├── cat.py              # OP_CAT
│   ├── csfs.py             # OP_CHECKSIGFROMSTACK
│   ├── ctv.py              # OP_CHECKTEMPLATEVERIFY
│   ├── internalkey_template.py
│   ├── apo_template.py     # BIP-118 SIGHASH_ANYPREVOUT
│   ├── csfs_rekey.py       # off-chain key delegation
│   ├── opcodes.py          # opcode constants
│   ├── template_common.py  # fund/spend helpers
│   └── load_local_env.py   # .env loader
├── scripts/
│   ├── gen_wif.py          # generate signet WIF (no node needed)
│   └── check_tx_status.py
└── results/
    ├── transactions.md
    └── …
```
