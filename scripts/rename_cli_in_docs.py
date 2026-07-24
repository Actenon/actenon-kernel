#!/usr/bin/env python3
"""Rename the kernel's `actenon` CLI to `actenon-kernel` in docs.

This is a careful rename: it only rewrites `actenon` invocations that look
like CLI calls (i.e. at the start of a shell line, possibly preceded by
$ or >). It does NOT rewrite:
  - `actenon-protocol`, `actenon-kernel`, `actenon-permit`, `actenon-scan`, `actenon-cloud`
  - `actenon.local_proof`, `actenon.cli`, etc. (Python module paths)
  - `Actenon` (proper noun)
  - `actenon` as a word in prose

The replacement is `actenon` -> `actenon-kernel` ONLY when:
  - the line starts with optional whitespace, then `actenon ` (with a space)
  - AND what follows is a CLI subcommand (lowercase letter or `-`)

This avoids false positives like `actenon-protocol` (already has a hyphen)
and `actenon.cli` (has a dot).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# Pattern: line-start, optional whitespace, optional $ or > prompt,
# then `actenon` followed by a space and a lowercase letter or hyphen
# (subcommand). Negative lookahead excludes `actenon-` (already renamed
# packages) and `actenon.` (Python module paths).
PATTERN = re.compile(
    r'(^|\s|\$|>|#|`)\s*actenon (?=[a-z-])',
    re.MULTILINE,
)


def rename_in_file(path: Path) -> int:
    """Rename `actenon` -> `actenon-kernel` in CLI invocations. Returns count."""
    text = path.read_text(encoding='utf-8')
    new_text, count = PATTERN.subn(lambda m: f'{m.group(1)}actenon-kernel ', text)
    if count > 0:
        path.write_text(new_text, encoding='utf-8')
    return count


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    total = 0
    files_changed = 0
    # Only touch markdown docs and the Makefile
    for pattern in ['**/*.md', 'Makefile']:
        for path in repo_root.glob(pattern):
            if '.git' in path.parts:
                continue
            count = rename_in_file(path)
            if count > 0:
                print(f'  {path.relative_to(repo_root)}: {count} replacements')
                files_changed += 1
                total += count
    print(f'\nTotal: {total} replacements across {files_changed} files')
    return 0


if __name__ == '__main__':
    sys.exit(main())
