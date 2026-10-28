from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from actenon.core.json import loads_no_duplicate_keys
from actenon.proof.canonical import canonicalize_bytes


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
