from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest
from actenon.core.json import loads_no_duplicate_keys
from actenon.proof.canonical import canonicalize_bytes
from actenon_protocol.canonicalisation import canonicalize_bytes as protocol_bytes
from actenon_protocol.canonicalisation import parse_strict


def test_protocol_raw_canonical_corpus():
    root = Path(__file__).resolve().parents[2]
    corpus = json.loads((root / 'fixtures/protocol_canonicalisation/raw-corpus.json').read_text())
    rows = []
    failures = []
    for case in corpus['cases']:
        raw = base64.b64decode(case['raw_base64'])
        assert hashlib.sha256(raw).hexdigest() == case['raw_sha256']
        row = {'id': case['id'], 'decision': 'REFUSE'}
        try:
            canonical = canonicalize_bytes(loads_no_duplicate_keys(raw))
            row.update(decision='ACCEPT', canonical_utf8=canonical.decode('utf-8'), canonical_sha256=hashlib.sha256(canonical).hexdigest())
        except Exception as exc:
            row['error'] = type(exc).__name__ + ': ' + str(exc)
        rows.append(row)
        if row['decision'] != case['expected_decision']:
            failures.append(row)
        elif row['decision'] == 'ACCEPT' and (row['canonical_utf8'] != case['canonical_utf8'] or row['canonical_sha256'] != case['canonical_sha256']):
            failures.append(row)
    if output := os.environ.get('ACTENON_PARITY_RESULTS'):
        Path(output).write_text(json.dumps(rows, indent=2, ensure_ascii=False) + '\n')
    assert failures == []


@pytest.mark.parametrize('parser,encoder', [
    (lambda raw: parse_strict(raw.decode('utf-8')), protocol_bytes),
    (lambda raw: loads_no_duplicate_keys(raw.decode('utf-8')), canonicalize_bytes),
], ids=['protocol', 'kernel'])
def test_adversarial_canonical_corpus(parser, encoder):
    """Adversarial extension of the frozen corpus: same decision, same bytes.

    51 cases covering gaps in the frozen 26: float negative zero, NaN and
    Infinity literals, exact i64/u64 boundaries, duplicate members nested in
    arrays and objects, surrogate-pair-escaped duplicate keys, dict and mixed
    nesting at the depth-32 boundary, 5000-deep DoS input, canonical output
    at and over the 1 MiB boundary, lexical malformations (leading zeros,
    +1, .5, 0x10, single quotes, trailing commas, comments, raw control
    characters), escape policy (U+007F, U+2028/9, \\u0000, astral pairs,
    \\/ keys), NFC/NFD distinctness, bool-vs-int, "1.0"-the-string vs 1.0,
    and multi-key byte-order locks.

    Expectations were computed by the Protocol Python reference at commit
    a2e0e08 (pinned in this repo's candidate graph), never hand-assigned.
    The same file was also run against the kernel TypeScript SDK, sdk-go
    and sdk-rust: every implementation matched the reference decision and,
    on ACCEPT, the canonical SHA-256 (255/255 verdicts; the only divergences
    are the documented typescript-safe-integer safe rejections on the four
    boundary integers, listed in each case's safe_rejection_profiles).
    """
    root = Path(__file__).resolve().parents[2]
    corpus = json.loads((root / 'fixtures/protocol_canonicalisation/raw-corpus-adversarial.json').read_text())
    failures = []
    for case in corpus['cases']:
        raw = base64.b64decode(case['raw_base64'])
        assert hashlib.sha256(raw).hexdigest() == case['raw_sha256'], case['id']
        row = {'id': case['id'], 'decision': 'REFUSE'}
        try:
            canonical = encoder(parser(raw))
            row.update(decision='ACCEPT', canonical_sha256=hashlib.sha256(canonical).hexdigest())
        except (ValueError, TypeError, UnicodeError, RecursionError):
            pass
        if row['decision'] != case['expected_decision']:
            failures.append(row)
        elif row['decision'] == 'ACCEPT' and row['canonical_sha256'] != case['canonical_sha256']:
            failures.append(row)
    assert failures == [], f'{len(failures)} decision/canonical mismatches: {[f["id"] for f in failures]}'
