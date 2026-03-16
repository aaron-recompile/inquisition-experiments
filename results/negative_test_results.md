# Negative Test Results

Intentional-failure (sensitivity) tests for CSFS/CTV.

## Commands

```bash
# CSFS
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_msg
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_sig
PYTHONPATH=. python3 experiments/csfs_negative.py --case bad_pubkey

# CTV
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_amount
PYTHONPATH=. python3 experiments/ctv_negative.py --case wrong_sequence
```

Expected for each case:

- `testmempoolaccept.allowed = false`
- reject reason indicates script/template mismatch

## Suite runner

```bash
PYTHONPATH=. python3 scripts/run_negative_suite.py
```

## Public summary (publish-safe)

| Case | Intent |
|------|--------|
| CSFS bad_msg | mutate message digest, keep sig/pubkey path |
| CSFS bad_sig | mutate signature bytes |
| CSFS bad_pubkey | mutate x-only pubkey bytes |
| CTV wrong_amount | mismatch committed output amount |
| CTV wrong_sequence | mismatch committed sequence |

Result summary:

- All five cases are designed to fail mempool acceptance under correct opcode enforcement.
- If any case is accepted, treat it as an unexpected result and investigate node/rule setup.

Note:

- Local raw run logs (including host-specific interpreter paths and full tracebacks) are intentionally not included in this publish document.

