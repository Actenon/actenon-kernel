"""Compare a rehearsal artefact with the published one by CONTENT (member name -> sha256 of bytes), ignoring
archive metadata (zip/tar timestamps, ordering). Wheels: every member including dist-info/RECORD; sdists
(.tar.gz) and .crate / npm .tgz: every regular file. Exit 0 only if identical.
usage: compare_artefact_contents.py REHEARSAL PUBLISHED"""
import hashlib, sys, tarfile, zipfile


def members(path):
    if path.endswith(".whl") or path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            return {n: hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if not n.endswith("/")}
    with tarfile.open(path) as t:
        return {m.name: hashlib.sha256(t.extractfile(m).read()).hexdigest() for m in t.getmembers() if m.isfile()}


a, b = members(sys.argv[1]), members(sys.argv[2])
only_a, only_b = sorted(set(a) - set(b)), sorted(set(b) - set(a))
diff = sorted(n for n in set(a) & set(b) if a[n] != b[n])
for label, items in (("only in rehearsal", only_a), ("only in published", only_b), ("content differs", diff)):
    for n in items:
        print(f"{label}: {n}")
print(f"{len(a)} vs {len(b)} members; identical: {not (only_a or only_b or diff)}")
sys.exit(0 if not (only_a or only_b or diff) else 1)
