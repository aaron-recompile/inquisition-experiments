# On-chain transaction records

Bitcoin Inquisition signet. **Note**: Spend txs are only visible on Inquisition nodes; standard signet explorers reject blocks containing new-opcode spends.

## Verify

```bash
bitcoin-cli -signet -datadir=<your-inquisition-datadir> getrawtransaction <txid> 1
```

Raw JSON dumps (from Inquisition node): [commit_084d5a9c.json](commit_084d5a9c.json), [spend_00072d4a.json](spend_00072d4a.json)

Or with env: `INQUISITION_DATADIR` set, use `-datadir=$INQUISITION_DATADIR`.

## cat (OP_CAT witness lock)

| Field | Value |
|-------|-------|
| Commit TxID | `084d5a9c6a8c176c24edc0a8b7ce54ed65808a326367d8a9299b4460ecaada09` |
| Reveal TxID | `00072d4aa354b5987eb8f2ffec440db7467b0581c5e845a6a0ef6999b2d05656` |
| Address | `tb1p7lcpdk4d3huwajdlkk7fph5750pllf4sk06ezl3nsmfssv7x468snhqmnc` |
| Script hex | `7ea820936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af87` |
| Witness | `[68656c6c6f, 776f726c64, script, control_block]` (part_a, part_b, ...) |

### Spend witness breakdown

| Stack item | Hex | Meaning |
|------------|-----|---------|
| 1 | `68656c6c6f` | `"hello"` (part_a) |
| 2 | `776f726c64` | `"world"` (part_b) |
| 3 | `7ea820...87` | Script (OP_CAT, OP_SHA256, expected_hash, OP_EQUAL) |
| 4 | `c050be...` | Taproot control block |
