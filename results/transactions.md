# On-chain Transaction Records (Inquisition)

This file records the four transactions in the screenshot set:

- CSFS: commit + reveal (RBF replacement reveal)
- CTV: commit + reveal

Visibility note (soft-fork behavior):

- Pre-confirmation: new-opcode spends may be absent from standard signet mempools.
- Post-confirmation: once mined, transactions are visible via normal block explorers.

## Quick verify commands

```bash
btcrun inq rpc gettransaction <txid> true
btcrun inq rpc decoderawtransaction <hex>
```

---

## A) CSFS pair (first two screenshots)

### CSFS commit

| Field | Value |
|-------|-------|
| TxID | `96df453d9e9ce50fdfca063528b03e3310033c3a61818bbe30e7fab5c61133e3` |
| Confirmations (snapshot) | `564` |
| Blockheight | `295204` |
| Blocktime (UTC) | `2026-03-12T04:32:42Z` |
| Wallet time (UTC) | `2026-03-12T04:32:15Z` |
| Fee | `155 sats` |
| vsize | `154 vB` |
| Output carrying CSFS script path | `vout=1` to `tb1p822a0zqj4fyj6h62qjchxgucxuu498nlzf9eq7yn3kludkc0fcfqp6x5up` |

### CSFS reveal (RBF replacement, final)

| Field | Value |
|-------|-------|
| TxID | `32fa307f3a570cfe93ebf7c101dba9ee8f289a5ca926dfed8baca92bb196e36b` |
| Superseded tx | `a5260c3dee88b1c0949ea71a57f8f0481f399a84fc89d59c38ac877149908e95` |
| Confirmations (snapshot) | `12` |
| Blockheight | `295756` |
| Blocktime (UTC) | `2026-03-16T02:33:44Z` |
| Wallet time (UTC) | `2026-03-16T02:31:51Z` |
| Fee | `5000 sats` |
| vsize | `137 vB` |
| Approx feerate | `36.5 sat/vB` |
| Spend from | `96df...` `vout=1` |
| Output | `45000 sats` to `tb1pjhf6vrmzen7v7n6knjz0l4u9q5j3dtx9ug8m2txz3rfl7rdra46quvk3e9` |

### CSFS witness stack and opcode semantics

Decoded `txinwitness` (in execution order):

1. `ab69f3...76912` (64B Schnorr signature)
2. `b94d27...fcde9` (32B message digest; this equals `SHA256("hello world")`)
3. `ff1f9f...986b8` (32B x-only public key)
4. `cc` (tapscript body: `OP_CHECKSIGFROMSTACK`)
5. `c0ff1f...986b8` (control block proving this leaf belongs to Taproot output)

Execution intuition:

- Script is just `OP_CHECKSIGFROMSTACK`.
- The opcode consumes `(sig, msg32, pubkey32)` from stack.
- It verifies Schnorr(sig, msg32, pubkey32).
- If valid, stack gets true and spend succeeds; otherwise fail.

---

## B) CTV pair (last two screenshots)

### CTV commit

| Field | Value |
|-------|-------|
| TxID | `2378642548c7f86472d3998a0fcb2d364084783e487dd87c1e1020684aed51de` |
| Confirmations (snapshot) | `560` |
| Blockheight | `295208` |
| Blocktime (UTC) | `2026-03-12T05:01:18Z` |
| Wallet time (UTC) | `2026-03-12T04:54:54Z` |
| Fee | `155 sats` |
| vsize | `154 vB` |
| Output carrying CTV script path | `vout=1` to `tb1p6lyh7dmfc43x4vq2vdv8833rxjgq2eexkklewj4urw92huh38amq933ehv` |

### CTV reveal

| Field | Value |
|-------|-------|
| TxID | `9ccbce8ad87f0f94632119245a42537c9fbd2c8f706621f76f513339f220d55c` |
| Confirmations (snapshot) | `10` |
| Blockheight | `295758` |
| Blocktime (UTC) | `2026-03-16T03:02:56Z` |
| Wallet time (UTC) | `2026-03-12T04:56:02Z` |
| Fee | `500 sats` |
| vsize | `112 vB` |
| Approx feerate | `4.46 sat/vB` |
| Spend from | `2378...` `vout=1` |
| Output | `49500 sats` to `tb1ple77ewdzh54ft8czq5wyxnvm7m2u50ygajcka6jjvegrll37mmtqjjzfgj` |

### CTV stack/script explanation

Decoded `txinwitness` has only 2 items:

1. `2032eb42...f03b42b3` (script leaf bytes)
2. `c0ff1f...9986b8` (control block)

The script leaf decodes to:

- `OP_PUSHBYTES_32 <template_hash>`
- `OP_NOP4` (interpreted as CTV in this Inquisition context)

Execution intuition:

- There are no extra unlock arguments like signature/message.
- Script pushes the committed 32-byte template hash.
- CTV checks current transaction template against this hash.
- Match => valid spend; mismatch => fail.

---

## Timing metrics (for paper-ready citation)

| Experiment | commit->reveal | reveal->confirm |
|------------|----------------|-----------------|
| CSFS | `338376s` (`3d 21:59:36`) | `113s` (`0:01:53`) |
| CTV | `68s` (`0:01:08`) | `338814s` (`3d 22:06:54`) |

Cross-reference:

- Matrix overview: `results/EXPERIMENT_MATRIX.md`
- Re-run tracker locally if needed: `PYTHONPATH=. python3 scripts/check_tx_status.py`
