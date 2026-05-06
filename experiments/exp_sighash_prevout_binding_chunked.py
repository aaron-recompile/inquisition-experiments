"""
Sighash Prevout Binding (chunked version) — witness items < 80 bytes.

Same logic as exp_sighash_prevout_binding.py but splits all preimage
segments into <80B chunks for Inquisition signet standardness.

Preimage layout (212 bytes, SIGHASH_ALL, script-path, ext_flag=1):
  pre       = bytes[0:10]   = epoch(1) + hash_type(1) + nVersion(4) + nLockTime(4)
  sha_prevouts = bytes[10:42] = SHA256(all inputs' prevouts)
  mid       = bytes[42:112]  = sha_amounts(32) + sha_scriptpubkeys(first 6 of 32)
  mid2      = bytes[112:182] = sha_scriptpubkeys(last 26) + sha_sequences(32) + sha_outputs(first 12)
  tail      = bytes[182:212] = sha_outputs(last 20) + spend_type(1) + input_index(4) + tapleaf(5 of 32)
  ... wait, that doesn't add up. Let me just split post into equal-ish chunks.

  post = bytes[42:212] = 170 bytes → split into post1(57B) + post2(57B) + post3(56B)

Witness: [sig(64B), pre(10B), sha_prevouts(32B), post1(57B), post2(57B), post3(56B), a_prevout(36B)]
All items < 80B ✓

Stack (top→bot): a_prevout | post3 | post2 | post1 | sha_prevouts | pre | sig

Script:
  # Step 1: Compute expected sha_prevouts
  push B_PREVOUT(36B)       B | a | post3 | post2 | post1 | sha | pre | sig
  OP_CAT                    a||B(72) | post3 | post2 | post1 | sha | pre | sig
  OP_SHA256                 exp(32) | post3 | post2 | post1 | sha | pre | sig

  # Step 2: Bring sha up, DUP, verify
  # sha is 5th from top. We need multiple ROTs to bring it up.
  # Actually, let's rearrange witness order to make this easier.

REVISED witness order — put sha_prevouts on TOP (last in array):

Witness: [sig(64B), pre(10B), post1(57B), post2(57B), post3(56B), a_prevout(36B), sha_prevouts(32B)]
Stack: sha_prevouts | a_prevout | post3 | post2 | post1 | pre | sig

Script:
  # Step 1: Compute expected from a_prevout
  OP_SWAP                   a_prevout | sha | post3 | post2 | post1 | pre | sig
  push B_PREVOUT(36B)       B | a | sha | post3 | post2 | post1 | pre | sig
  OP_CAT                    a||B(72) | sha | post3 | post2 | post1 | pre | sig
  OP_SHA256                 exp(32) | sha | post3 | post2 | post1 | pre | sig

  # Step 2: Verify sha_prevouts
  OP_EQUALVERIFY            post3 | post2 | post1 | pre | sig
                            (exp == sha verified!)

  # Step 3: CAT post chunks
  OP_CAT                    post2||post3(113) | post1 | pre | sig
  OP_CAT                    post1||post2||post3(170) | pre | sig

  # Step 4: pre SIZE check
  OP_SWAP                   pre | post(170) | sig
  OP_SIZE <10> EQUALVERIFY  pre | post | sig

  # Step 5: CAT full preimage
  OP_SWAP                   post | pre | sig
  OP_CAT                    pre||post(180) | sig
  # WAIT: we lost sha_prevouts! It was consumed by EQUALVERIFY.
  # Need to DUP or keep it.

REVISED AGAIN — DUP sha before verify:

Witness: [sig(64B), pre(10B), post1(57B), post2(57B), post3(56B), a_prevout(36B), sha_prevouts(32B)]
Stack: sha(32) | a_prevout(36) | post3(56) | post2(57) | post1(57) | pre(10) | sig(64)

Script:
  # === Step 1: DUP sha, then compute expected and verify ===
  OP_DUP                    sha | sha | a | post3 | post2 | post1 | pre | sig
  OP_ROT                    a | sha | sha | post3 | post2 | post1 | pre | sig
  push B_PREVOUT(36B)       B | a | sha | sha | post3 | post2 | post1 | pre | sig
  OP_CAT                    a||B(72) | sha | sha | post3 | post2 | post1 | pre | sig
  OP_SHA256                 exp(32) | sha | sha | post3 | post2 | post1 | pre | sig
  OP_EQUALVERIFY            sha | post3 | post2 | post1 | pre | sig
                            ← verified! sha_prevouts is correct.
                            ← sha is still on stack for CAT.

  # === Step 2: CAT post chunks ===
  OP_SWAP                   post3 | sha | post2 | post1 | pre | sig
  OP_ROT                    post2 | post3 | sha | post1 | pre | sig
  OP_CAT                    post3||... NO.

  # Hmm, ROT/SWAP with 6+ items is tricky. Let me reconsider.
  # After step 1: sha(32) | post3(56) | post2(57) | post1(57) | pre(10) | sig(64)
  #
  # I want: pre || sha || post1 || post2 || post3 = full preimage
  # That's 5 CAT operations. Let me work bottom-up.
  #
  # Strategy: CAT post3+post2, then +post1, then sha, then pre.
  # But sha is on top and posts are below it.

  # Move sha below the posts:
  OP_SWAP                   post3 | sha | post2 | post1 | pre | sig
  OP_ROT                    post2 | post3 | sha | post1 | pre | sig
  # Now top 3: post2, post3, sha → ROT brought sha to... no.
  # ROT: x1 x2 x3 → x2 x3 x1. x3=post2(top), x2=post3, x1=sha
  # After: post3 post2 sha → sha on top. WRONG.

  # Let me just use a different approach: put sha into its right place via SWAPs.

  # After step 1: sha | post3 | post2 | post1 | pre | sig

  # Goal order for CAT: pre | sha | post1 | post2 | post3 | sig
  # (bottom to top: sig, pre, sha, post1, post2, post3)
  # Then: CAT post2||post3, CAT post1||post2||post3, CAT sha||post, CAT pre||sha||post

  # This requires way too many stack ops. Simpler: just CAT everything in witness order.

OK FINAL APPROACH: arrange witness so segments are in order for sequential CAT.

Witness: [sig(64B), pre(10B), sha_prevouts(32B), post1(57B), post2(57B), post3(56B), a_prevout(36B)]
Stack: a_prevout(36) | post3(56) | post2(57) | post1(57) | sha(32) | pre(10) | sig(64)

Script:
  # === Step 1: Compute expected sha_prevouts from a_prevout ===
  push B_PREVOUT(36)        B | a | post3 | post2 | post1 | sha | pre | sig
  OP_CAT                    a||B(72) | post3 | post2 | post1 | sha | pre | sig
  OP_SHA256                 exp(32) | post3 | post2 | post1 | sha | pre | sig

  # === Step 2: Bring sha up, DUP, verify, keep sha ===
  # sha is 4th from top. Need 3 SWAPs? No, use stack rotation.
  # Top 3: exp, post3, post2. ROT: post2, exp, post3... nope.
  # This deep access is impossible with just ROT/SWAP on top 3.

  # BETTER: put exp at bottom near sha. But we can only manipulate top 3.

  # SIMPLEST CORRECT APPROACH: put sha_prevouts verification at the END,
  # after CAT reconstructs the full preimage. Extract sha field from the
  # assembled preimage. But we can't extract from middle of a byte string.

  # TRULY SIMPLEST: Don't verify sha field separately. Instead:
  # 1. Witness provides all preimage chunks + a_prevout
  # 2. Script CATs chunks into full preimage
  # 3. Script computes SHA256(a_prevout || B_CONST) = expected_sha
  # 4. Script uses OP_SUBSTR... no, doesn't exist.

  # OK, THE ACTUAL SIMPLEST: keep the field-split approach but move
  # sha_prevouts verification to right after it's accessible.

Witness: [sig, a_prevout(36), sha_prevouts(32), pre(10), post1(57), post2(57), post3(56)]
Stack: post3 | post2 | post1 | pre | sha | a_prevout | sig

  # CAT post chunks first (they're on top):
  OP_CAT                    post2||post3(113) | post1 | pre | sha | a_prevout | sig
  OP_CAT                    post1||..||post3(170) | pre | sha | a_prevout | sig

  # Now: post(170) | pre(10) | sha(32) | a_prevout(36) | sig(64)

  # pre SIZE check:
  OP_SWAP                   pre | post | sha | a_prevout | sig
  OP_SIZE <10> EQUALVERIFY  pre | post | sha | a_prevout | sig

  # Now build preimage = pre || sha || post
  # SWAP to get sha on top:
  OP_ROT                    sha | pre | post | a_prevout | sig
                            (ROT: x1=sha, x2=post, x3=pre → post, pre, sha → sha on top)
                            WAIT: x1=sha(deepest of 3), x2=post, x3=pre(top)
                            After ROT: x2 x3 x1 = post pre sha → sha on top. YES!

  OP_SWAP                   pre | sha | post | a_prevout | sig
  OP_CAT                    sha||pre... NO, CAT pops top=pre, pops second=sha, pushes sha||pre(42).
                            WRONG ORDER. We need pre||sha.

  # Fix: don't SWAP before CAT. After ROT: sha on top, pre below.
  # We want pre || sha. So: push pre first, then sha, then CAT.
  # After ROT: sha | post | pre... WAIT let me re-trace.

  # Before ROT: pre(top) | post | sha | a_prevout | sig
  # ROT (top3: pre, post, sha): takes deepest(sha) to top
  #   x1=sha, x2=post, x3=pre → x2, x3, x1 = post, pre, sha
  # After: sha(top) | pre | post | a_prevout | sig

  OP_SWAP                   pre | sha | post | a_prevout | sig
  OP_CAT                    sha||pre... STILL WRONG.

  # CAT semantics: pops x(top), pops y(second), pushes y||x
  # So: top=pre, second=sha → pushes sha||pre. WRONG.
  # Want: pre||sha. So need sha on top, pre second:
  # Don't swap: sha(top) | pre | post | ...
  OP_CAT                    pre||sha(42) | post | a_prevout | sig  ← CORRECT!
                            (pops sha(top), pops pre(second), pushes pre||sha)

  OP_SWAP                   post | pre||sha | a_prevout | sig
  OP_CAT                    pre||sha||post(212) | a_prevout | sig
                            (pops post(top), pops pre||sha, pushes pre||sha||post) ← CORRECT!

  # Now verify sha_prevouts:
  # a_prevout is second from top. SWAP to get it.
  OP_SWAP                   a_prevout | preimage(212) | sig

  push B_PREVOUT(36)        B | a_prevout | preimage | sig
  OP_CAT                    a_prevout||B(72) | preimage | sig
  OP_SHA256                 expected_sha(32) | preimage | sig

  # Extract actual sha_prevouts from preimage for comparison?
  # We can't extract bytes from middle of preimage on stack.
  # BUT: we already assembled preimage from known segments.
  # The sha segment IS the correct one if the assembly is right.
  # And CHECKSIG binding ensures the assembled preimage = real SigMsg.
  # So we verify: is the sha segment in the preimage actually = expected?
  #
  # We don't need to extract it! We verified at assembly time:
  # preimage = pre || sha_from_witness || post
  # We need: sha_from_witness == SHA256(a_prevout || B)
  #
  # But sha_from_witness was just concatenated, not verified.
  # We need to verify it BEFORE assembly.
  #
  # Let me move verification before the final CAT.

OK let me restart with a clean design.
"""
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

bu_setup("signet")

DEMO_KEY_WIF = os.environ.get("CAT_DEMO_WIF", "").strip()
if not DEMO_KEY_WIF:
    raise ValueError("Set CAT_DEMO_WIF")

demo_key = Key.from_wif(DEMO_KEY_WIF)

def _wif_to_secret(wif):
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    b = 0
    for c in wif: b = b * 58 + B58.index(c)
    raw = b.to_bytes((b.bit_length() + 7) // 8 or 1, "big").lstrip(b"\x00")
    pad = 37 if len(raw) <= 37 else 38
    raw = (b"\x00" * (pad - len(raw))) + raw
    return raw[1:33]

SECRET = _wif_to_secret(DEMO_KEY_WIF)
SECP_KEY = Secp256k1PrivateKey(SECRET, raw=True)
PUBKEY_X = SECP_KEY.pubkey.serialize()[1:33]
_TAG_HASH = hashlib.sha256(b"TapSighash").digest()
TAG_PREFIX = _TAG_HASH + _TAG_HASH  # 64 bytes

# Split TAG_PREFIX into two 32B halves for witness standardness
TAG_HALF1 = TAG_PREFIX[:32]  # = SHA256("TapSighash")
TAG_HALF2 = TAG_PREFIX[32:]  # = SHA256("TapSighash") (same)

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
    """
    Compute SigMsg preimage with correct tapleaf_hash from raw script bytes.

    BUScript.from_raw() mangles OP_CAT (0x7e) into OP_PUSHDATA1 (0x4c),
    producing wrong tapleaf_hash. We compute preimage using BUScript for
    the non-script parts, then manually replace the tapleaf_hash.
    """
    from bitcoinutils.utils import tagged_hash, prepend_compact_size

    # Get wrong preimage (with mangled tapleaf_hash)
    wrong_preimage = compute_sigmsg_preimage(
        inner_tx, txin_index, all_spks, all_amounts,
        ext_flag=1,
        script=BUScript.from_raw(raw_script_hex),
        sighash=TAPROOT_SIGHASH_ALL,
    )

    # Compute correct tapleaf_hash from raw bytes
    script_raw = bytes.fromhex(raw_script_hex)
    correct_tapleaf = tagged_hash(
        bytes([0xC0]) + prepend_compact_size(script_raw),  # 0xC0 = LEAF_VERSION_TAPSCRIPT
        "TapLeaf",
    )

    # Replace last 37 bytes: tapleaf_hash(32) + key_version(1) + codesep_pos(4)
    base = wrong_preimage[:-37]
    correct_ext = correct_tapleaf + bytes([0]) + b"\xff\xff\xff\xff"
    return base + correct_ext


def _b_program():
    return (TapTree(internal_key=demo_key, network="signet")
            .checksig(demo_key, label="b_keypath").build())


def _a_script_and_program(b_prevout: bytes):
    """
    Chunked version of prevout binding script.

    Witness array: [sig(64), a_prevout(36), sha(32), pre(10), post1(57), post2(57), post3(56)]
    Stack (top→bot): post3(56) | post2(57) | post1(57) | pre(10) | sha(32) | a_prevout(36) | sig(64)

    All witness items < 80 bytes ✓

    Stack trace:

    INITIAL         post3 | post2 | post1 | pre | sha | a_prevout | sig

    # --- CAT post chunks ---
    OP_CAT          post2||post3(113) | post1 | pre | sha | a_prevout | sig
    OP_CAT          post(170) | pre | sha | a_prevout | sig

    # --- pre SIZE check ---
    OP_SWAP         pre | post | sha | a_prevout | sig
    OP_SIZE <10>
    OP_EQUALVERIFY  pre | post | sha | a_prevout | sig

    # --- Verify sha_prevouts ---
    OP_ROT          sha | pre | post | a_prevout | sig
                    (top3: pre,post,sha → ROT brings sha to top)
    OP_DUP          sha | sha | pre | post | a_prevout | sig

    # Bring a_prevout up: it's 4th from top. Use 3× ROT-like ops.
    # top 3 of remaining (under dup'd sha): sha, pre, post
    # a_prevout is 5th total... too deep.

    # ALTERNATIVE: compute expected before CAT, using witness items.
    # Rearrange so a_prevout and sha are adjacent at top.

    OK I'll use a different witness order that puts verification items on top:

    Witness: [sig(64), pre(10), post1(57), post2(57), post3(56), sha(32), a_prevout(36)]
    Stack:    a_prevout(36) | sha(32) | post3(56) | post2(57) | post1(57) | pre(10) | sig(64)

    # --- Step 1: Verify sha_prevouts ---
    <B_PREVOUT(36)>  B | a_prevout | sha | post3 | post2 | post1 | pre | sig
    OP_CAT           a||B(72) | sha | post3 | post2 | post1 | pre | sig
    OP_SHA256        exp(32) | sha | post3 | post2 | post1 | pre | sig
    OP_SWAP          sha | exp | post3 | post2 | post1 | pre | sig
    OP_DUP           sha | sha | exp | post3 | post2 | post1 | pre | sig
    OP_ROT           exp | sha | sha | post3 | post2 | post1 | pre | sig
    OP_EQUALVERIFY   sha | post3 | post2 | post1 | pre | sig
                     ← verified! sha is kept on stack.

    # --- Step 2: CAT post chunks ---
    OP_ROT           post2 | sha | post3 | post1 | pre | sig
    # WRONG. ROT on (sha, post3, post2): x1=sha, x2=post3, x3=post2(top)
    # Hmm top 3 are: sha(top after step1), post3, post2.
    # Wait, after step1: sha | post3 | post2 | post1 | pre | sig
    # top=sha, 2nd=post3, 3rd=post2
    # ROT: x1=post2(deepest of 3), x2=post3, x3=sha(top)
    # After: post3, sha, post2 → post2 on top.
    # Stack: post2 | sha | post3 | post1 | pre | sig
    # Not helpful.

    # Let me push sha down past the posts.
    # After step1: sha | post3 | post2 | post1 | pre | sig
    OP_SWAP          post3 | sha | post2 | post1 | pre | sig
    OP_ROT           sha | post3 | post2 | ... NO.
    # ROT on top 3: (post3, sha, post2) where... ugh.
    # top=post3, 2nd=sha, 3rd=post2. x1=post2, x2=sha, x3=post3
    # After ROT: sha, post3, post2 → post2 on top.
    # Stack: post2 | sha | post3 | post1 | pre | sig. Even worse.

    # DIFFERENT STRATEGY: CAT post chunks FIRST, then do sha verification.

    Witness: [sig(64), sha(32), a_prevout(36), pre(10), post1(57), post2(57), post3(56)]
    Stack:    post3(56) | post2(57) | post1(57) | pre(10) | a_prevout(36) | sha(32) | sig(64)

    # --- Step 1: CAT post chunks (top 3) ---
    OP_CAT           post2||post3(113) | post1 | pre | a_prevout | sha | sig
    OP_CAT           post(170) | pre | a_prevout | sha | sig

    # --- Step 2: pre SIZE check ---
    OP_SWAP          pre | post | a_prevout | sha | sig
    OP_SIZE <10>
    OP_EQUALVERIFY   pre | post | a_prevout | sha | sig

    # --- Step 3: Assemble pre || sha || post ---
    # Need sha between pre and post. sha is 3rd from top.
    # Stack: pre | post | a_prevout | sha | sig
    OP_ROT           a_prevout | pre | post | sha | sig
                     (top3: pre,post,a_prevout → a_prevout to top)
                     Wait: x1=a_prevout(deepest), x2=post, x3=pre(top)
                     After: post, pre, a_prevout → a_prevout on top.
                     Stack: a_prevout | post | pre | sha | sig. Hmm.

    # ROT again to get sha:
    # top3: a_prevout, post, pre. Deepest of 3 is pre.
    # After ROT: post, a_prevout, pre → pre on top.
    # Nope. Too many items between sha and the pre/post.

    # SIMPLEST POSSIBLE: don't separate sha from the preimage at all.
    # Instead, put the entire preimage as chunks and do sha verification
    # by having the witness provide sha_prevouts separately AND as part of preimage.
    # Redundant but simple.

    # CLEANEST APPROACH: pre-split preimage into 4 chunks where sha_prevouts
    # is its own chunk. Verify sha chunk, then CAT all 4 into full preimage.

    Witness: [sig(64), pre(10), sha(32), post_a(57), post_b(57), post_c(56), a_prevout(36)]
    Stack:   a_prevout | post_c | post_b | post_a | sha | pre | sig

    Script:
    # --- Verify sha_prevouts from a_prevout + B_PREVOUT ---
    <B_PREVOUT(36)>   B | a_prevout | postc | postb | posta | sha | pre | sig
    OP_CAT            a||B(72) | postc | postb | posta | sha | pre | sig
    OP_SHA256          exp(32) | postc | postb | posta | sha | pre | sig

    # Now exp is on top, sha is 4th. Need to compare.
    # Move exp down to sha: SWAP, ROT, SWAP...
    # Actually, can we bring sha up? It's 4th from top.
    # Top 3: exp, postc, postb. ROT brings postb to top... no.
    # Can't reach 4th item with only SWAP/ROT.

    # USE OP_2SWAP or OP_ROLL? No, Bitcoin Script only has SWAP, ROT for top 3.
    # OP_ROLL exists: OP_ROLL pops n, then rotates the n+1'th item to top.
    # But OP_ROLL is not in our opcodes.py...

    # FINAL FINAL approach: arrange so exp and sha are adjacent.
    # Put a_prevout FIRST in stack (deepest after sig), verify sha EARLY.

    # THE ACTUAL SIMPLEST DESIGN:
    # Step 1: verify sha using a_prevout (both at top of stack)
    # Step 2: CAT pre || sha (sha stays after verify via DUP)
    # Step 3: CAT with post chunks one by one
    # Step 4: tagged hash + CHECKSIG + CSFS

    Witness: [sig(64), post_c(56), post_b(57), post_a(57), pre(10), sha(32), a_prevout(36)]
    Stack:   a_prevout(36) | sha(32) | pre(10) | post_a(57) | post_b(57) | post_c(56) | sig(64)
    """

    script_hex = build_script(
        # Stack: a_prevout | sha | pre | posta | postb | postc | sig

        # === Step 1: Verify sha_prevouts ===
        push_bytes(b_prevout),  # B | a | sha | pre | posta | postb | postc | sig
        OP_CAT,                 # a||B(72) | sha | pre | posta | postb | postc | sig
        OP_SHA256,              # exp(32) | sha | pre | posta | postb | postc | sig
        OP_SWAP,                # sha | exp | pre | posta | postb | postc | sig
        OP_DUP,                 # sha | sha | exp | pre | posta | postb | postc | sig
        OP_ROT,                 # exp | sha | sha | pre | posta | postb | postc | sig
        OP_EQUALVERIFY,         # sha | pre | posta | postb | postc | sig
                                # ← sha_prevouts verified, sha kept for CAT

        # === Step 2: pre SIZE check + CAT pre||sha ===
        OP_SWAP,                # pre | sha | posta | postb | postc | sig
        OP_SIZE,                # 10 | pre | sha | ...
        0x5a,  # OP_10 (minimal encoding for number 10)    # <10>
        OP_EQUALVERIFY,         # pre | sha | posta | postb | postc | sig
        OP_CAT,                 # sha||pre... NO!
                                # CAT pops top=pre, pops 2nd=sha, pushes sha||pre
                                # WRONG! We want pre||sha.
                                # Solution: don't SWAP. Keep sha on top, pre below.
    )

    # Let me redo from step 2:
    # After step 1: sha(32) | pre(10) | posta(57) | postb(57) | postc(56) | sig(64)
    # We want pre||sha||posta||postb||postc
    # CAT semantics: pops top(x), pops second(y), pushes y||x
    # So to get pre||sha: need sha on top, pre on second → CAT → pre||sha ✓

    # After step 1, sha IS on top, pre IS second. Perfect, just CAT:
    # sha | pre → CAT → pre||sha(42). CORRECT!

    # Then: pre||sha(42) | posta(57) | postb(57) | postc(56) | sig(64)
    # CAT: pops pre||sha, pops posta → posta||pre||sha. WRONG ORDER!
    # Want: pre||sha||posta. Need pre||sha on second, posta on top.
    # SWAP first:
    # SWAP: posta | pre||sha | postb | postc | sig
    # CAT: pops posta, pops pre||sha → pre||sha||posta(99). CORRECT!

    # Then: pre||sha||posta(99) | postb(57) | postc(56) | sig
    # SWAP: postb | pre||sha||posta | postc | sig
    # CAT: pops postb, pops prefix → prefix||postb(156). CORRECT!

    # Then: prefix||postb(156) | postc(56) | sig
    # SWAP: postc | prefix | sig
    # CAT: pops postc, pops prefix → prefix||postc(212). CORRECT!

    # Full preimage(212) | sig

    script_hex = build_script(
        # Stack: a_prevout | sha | pre | posta | postb | postc | sig

        # === Step 1: Verify sha_prevouts ===
        push_bytes(b_prevout),  # B | a | sha | pre | posta | postb | postc | sig
        OP_CAT,                 # a||B(72) | sha | pre | posta | postb | postc | sig
        OP_SHA256,              # exp(32) | sha | pre | posta | postb | postc | sig
        OP_SWAP,                # sha | exp | pre | posta | postb | postc | sig
        OP_DUP,                 # sha | sha | exp | pre | posta | postb | postc | sig
        OP_ROT,                 # exp | sha | sha | pre | posta | postb | postc | sig
        OP_EQUALVERIFY,         # sha | pre | posta | postb | postc | sig

        # === Step 2: pre SIZE check ===
        OP_SWAP,                # pre | sha | posta | postb | postc | sig
        OP_SIZE,
        0x5a,  # OP_10 (minimal encoding for number 10)
        OP_EQUALVERIFY,         # pre | sha | posta | postb | postc | sig

        # === Step 3: CAT full preimage ===
        OP_SWAP,                # sha | pre | posta | postb | postc | sig
        OP_CAT,                 # pre||sha(42) | posta | postb | postc | sig
        OP_SWAP,                # posta | pre||sha | postb | postc | sig
        OP_CAT,                 # pre||sha||posta(99) | postb | postc | sig
        OP_SWAP,                # postb | pre||sha||posta | postc | sig
        OP_CAT,                 # pre||sha||posta||postb(156) | postc | sig
        OP_SWAP,                # postc | prefix | sig
        OP_CAT,                 # full_preimage(212) | sig

        # === Step 4: Tagged hash ===
        push_bytes(TAG_HALF1),  # T1(32) | full | sig
        push_bytes(TAG_HALF2),  # T2(32) | T1 | full | sig
        OP_CAT,                 # T1||T2(64) | full | sig  (= TAG_PREFIX)
        OP_SWAP,                # full | TAG | sig
        OP_CAT,                 # TAG||full(276) | sig
        OP_SHA256,              # tagged_hash(32) | sig

        # === Step 5: CSFS (same sig) ===
        OP_OVER,                # sig | hash | sig
        OP_SWAP,                # hash | sig | sig
        push_bytes(PUBKEY_X),
        OP_CHECKSIGFROMSTACK,        # result | sig
        OP_VERIFY,                   # sig  (CSFS verified)

        # === Step 6: CHECKSIG (same sig, actual tx) ===
        push_bytes(PUBKEY_X),
        OP_CHECKSIG,            # 1
    )

    leaf_script = RawScript(script_hex)
    program = (TapTree(internal_key=demo_key, network="signet")
               .custom(script=leaf_script, label="prevout_binding",
                       unlock_hint="chunked prevout binding")
               .build())
    return leaf_script, program


# ---------------------------------------------------------------------------
# --fund
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# --spend
# ---------------------------------------------------------------------------
def do_spend():
    rpc = _rpc()
    if not os.path.exists(STATE_FILE):
        print("ERROR: run --fund first"); sys.exit(1)
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

    # Placeholder witness (all items < 80B)
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

    # Use corrected preimage (fixes BUScript mangling OP_CAT → wrong tapleaf_hash)
    preimage = _correct_preimage(inner_tx, 0, all_spks, all_amounts, leaf_script.to_hex())
    assert len(preimage) == 212, f"Expected 212, got {len(preimage)}"

    # Verify sha_prevouts
    sha_prevouts = preimage[10:42]
    expected_sha = hashlib.sha256(a_prevout + b_prevout).digest()
    print(f"\n  sha_prevouts match: {sha_prevouts == expected_sha}")
    assert sha_prevouts == expected_sha

    # Sign: tagged_hash for same-sig CHECKSIG+CSFS binding
    tagged = hashlib.sha256(TAG_PREFIX + preimage).digest()
    sig = SECP_KEY.schnorr_sign(tagged, "", raw=True)
    print(f"  Signature: {sig.hex()[:24]}... ({len(sig)}B)")

    # Split preimage
    pre = preimage[0:10]     # 10B
    sha = preimage[10:42]    # 32B
    post = preimage[42:212]  # 170B
    post_a = post[0:57]      # 57B
    post_b = post[57:114]    # 57B
    post_c = post[114:170]   # 56B
    assert len(pre)==10 and len(sha)==32 and len(post_a)==57 and len(post_b)==57 and len(post_c)==56

    # Witness: [sig, post_c, post_b, post_a, pre, sha, a_prevout]
    # Wait, looking at the script, the stack order expected is:
    # Stack: a_prevout | sha | pre | posta | postb | postc | sig
    # Witness pushes bottom-first: sig is first (bottom), then postc, postb, posta, pre, sha, a_prevout (top)
    # NO! Witness array is pushed in order: item[0] first (bottom), item[-1] last (top).
    # So: witness = [sig, postc, postb, posta, pre, sha, a_prevout]
    # Stack (top→bot): a_prevout, sha, pre, posta, postb, postc, sig ✓

    witness = [
        sig.hex(),          # [0] → bottom of stack
        post_c.hex(),       # [1]
        post_b.hex(),       # [2]
        post_a.hex(),       # [3]
        pre.hex(),          # [4]
        sha.hex(),          # [5]
        a_prevout.hex(),    # [6] → top of stack
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
            print("  SUCCESS: Taproot-native UTXO binding verified on-chain!")
            state["spend_txid"] = spend_txid
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=2)
        else:
            reason = result[0].get("reject-reason", "?") if result else "?"
            print(f"\n  REJECTED: {reason}")
    except Exception as e:
        print(f"  Error: {e}")


# ---------------------------------------------------------------------------
# --attack
# ---------------------------------------------------------------------------
def do_attack():
    rpc = _rpc()
    if not os.path.exists(STATE_FILE):
        print("ERROR: run --fund first"); sys.exit(1)
    with open(STATE_FILE) as f:
        state = json.load(f)

    if "spend_txid" in state:
        print("ERROR: A already spent. Re-run --fund."); sys.exit(1)

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
    exp_c = hashlib.sha256(a_prevout + c_prevout).digest()
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

    print(f"\n  Testing (should FAIL)...")
    try:
        result = rpc("testmempoolaccept", [tx_final.hex])
        print(f"  testmempoolaccept: {json.dumps(result, indent=2)}")
        if result and not result[0].get("allowed", False):
            reason = result[0].get("reject-reason", "?")
            print(f"\n  EXPECTED FAILURE: {reason}")
            print("  Attack blocked by sha_prevouts verification!")
        else:
            print("\n  UNEXPECTED: Attack was NOT blocked!")
    except Exception as e:
        print(f"  REJECTED: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sighash Prevout Binding (Chunked)")
    parser.add_argument("--fund", action="store_true")
    parser.add_argument("--spend", action="store_true")
    parser.add_argument("--attack", action="store_true")
    args = parser.parse_args()

    if args.fund: do_fund()
    elif args.spend: do_spend()
    elif args.attack: do_attack()
    else:
        parser.print_help()
        print("\n  --fund     Fund UTXOs A and B")
        print("  --spend    Spend A+B (positive test)")
        print("  --attack   Replace B with C (negative test)")
