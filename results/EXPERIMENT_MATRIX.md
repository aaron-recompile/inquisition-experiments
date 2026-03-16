# Experiment Matrix

Use this file as the human-review checklist.  
Machine snapshots are written by `scripts/check_tx_status.py`.

## Status Legend

- `broadcast` = sent to node
- `mempool` = accepted by local Inquisition mempool
- `confirmed` = has blockhash + confirmations
- `analyzed` = witness/stack breakdown completed

## Matrix

| Experiment | Commit TxID | Reveal TxID | Current status | commit->reveal | reveal->confirm | Stack analysis |
|------------|-------------|-------------|----------------|----------------|-----------------|----------------|
| CAT | `084d5a9c6a8c176c24edc0a8b7ce54ed65808a326367d8a9299b4460ecaada09` | `00072d4aa354b5987eb8f2ffec440db7467b0581c5e845a6a0ef6999b2d05656` | confirmed | done | done | done |
| CSFS | `96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3` | `32fa307f3a570cfe93ebf7c101dba9ee8f289a5ca926dfed8baca92bb196e36b` | confirmed (RBF replaced old reveal) | `338376s` | `113s` | done |
| CTV | `2378642548c7f86472d3998a0fcb2d364084783e487dd87c1e1020684aed51de` | `9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c` | confirmed | `68s` | `338814s` | done |

## One-command refresh

```bash
PYTHONPATH=. python3 scripts/check_tx_status.py
```

Generated artifacts:

- `results/confirmation_snapshots.jsonl` (append-only timeline)
- `results/confirmation_status.md` (latest status table)

