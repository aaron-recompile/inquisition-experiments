# Bitcoin Inquisition Experiments

Python experiments on [Bitcoin Inquisition](https://github.com/bitcoin-inquisition/bitcoin) signet. Each script produces **real on-chain transactions**; TxIDs prove they were run.

## Why this repo

- **Minimal Python scaffolding** — Swap in your WIF, point at your node, run. No ceremony.
- **On-chain proof** — Real signet TxIDs; anyone can verify the experiment structure.
- **btcaaron in action** — Built with [btcaaron](https://github.com/aaron-recompile/btcaaron); reproducible Taproot workflows.

## Experiment

| Experiment | Description | Commit TxID | Reveal TxID |
|------------|-------------|-------------|-------------|
| **cat** | OP_CAT witness lock: data in witness, only holder of part_a/part_b can spend. | `084d5a9c6a8c176c24edc0a8b7ce54ed65808a326367d8a9299b4460ecaada09` | `00072d4aa354b5987eb8f2ffec440db7467b0581c5e845a6a0ef6999b2d05656` |

Full TxIDs and addresses: [results/transactions.md](results/transactions.md)

## Pipeline (planned)

Future experiments to run on signet:

- **CSFS** — OP_CHECKSIGFROMSTACK: BIP340 sign arbitrary message, verify in script
- **CTV** — OP_CHECKTEMPLATEVERIFY: commit to output template
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
export INQUISITION_DATADIR=/path/to/inquisition-data

# Set CAT_DEMO_WIF — your signet WIF for the Taproot internal key (or edit experiments/cat.py)
export CAT_DEMO_WIF="your_signet_wif..."

PYTHONPATH=. python3 experiments/cat.py          # show address
PYTHONPATH=. python3 experiments/cat.py --fund   # commit 50k sats
PYTHONPATH=. python3 experiments/cat.py --spend   # reveal
```

## Structure

```
inquisition-experiments/
├── README.md
├── config.py           # RPC settings (set INQUISITION_DATADIR env or edit)
├── requirements.txt
├── experiments/
│   ├── cat.py
│   └── opcodes.py
└── results/
    ├── transactions.md
    ├── commit_084d5a9c.json
    └── spend_00072d4a.json
```
