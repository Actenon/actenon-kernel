"""Corpus hash: sha256 over sorted (relative path, sha256(file bytes)) lines."""
import hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
lines = []
for p in sorted(root.rglob("*")):
    if p.is_file():
        lines.append(f"{p.relative_to(root).as_posix()}  {hashlib.sha256(p.read_bytes()).hexdigest()}")
listing = "\n".join(lines) + "\n"
print(hashlib.sha256(listing.encode()).hexdigest(), len(lines))
if len(sys.argv) > 2:
    Path(sys.argv[2]).write_text(listing)
