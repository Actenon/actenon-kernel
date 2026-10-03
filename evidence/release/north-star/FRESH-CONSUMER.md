# FRESH-CONSUMER-TEST — CANDIDATE-ARTIFACT PASS (rehearsal 3)

**What was tested.** A consumer with no Actenon source tree, under `env -i` with a fresh HOME and fresh pip, npm,
Go and Cargo caches. It installs the release artefacts with its normal tool and an unmodified dependency
declaration: `pip install actenon-permit actenon-kernel actenon-protocol[...]`, `npm install @actenon/verifier-sdk
@actenon/sdk @actenon/protocol-types`, `go get github.com/Actenon/sdk-go@v1.1.0`, and `actenon-verifier-sdk = "0.2"`.
The artefacts are served by `fresh-consumer/local_registry.py` over the registries' own protocols: PEP 503,
npm packuments, the Cargo sparse index and a `file://` GOPROXY. Every other package comes from the public
registries. Provenance is asserted per artefact (registry URL, and digest = SHA256SUMS: pip `--report`, npm
lock `integrity`, Cargo.lock `checksum`, Go module-cache zip). No resolver state names a `/home/user` path.

**What this is not.** A published-artefact PASS. Until the release graph runs, the public registries serve the
old versions, which fail these checks (controls/). Published-artefact verification is RELEASE-GRAPH.md step 6.

## Artefacts

```
actenon-protocol e988c4d43f8b59d459628a306cd0117109e59d70
actenon-kernel 185e0fd834bda7318893f7cda51100c5708091bc
sdk-go 0198ef597e67a31de778c38628d10d99a5c60d8e
sdk-rust c149ab681be437b68f699b4f734a1a18ed7ad0e7
actenon-permit a0d2b8dae74972a06f5774e4667774df26fbad97

80572e8467024b4272be3edd66a70707ad3827a31f906113fd06dc7bd0ede81c  crates/actenon-verifier-sdk-0.2.0.crate
6bf25061d3caea72d34f961997d35aca8c8d960aaddac2413516882e6706c97e  goproxy/github.com/!actenon/sdk-go/@v/list
d5850d0b19594e7ae94da10f69b950230646f51eedca09e3564f36d5cd520d66  goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.info
6638604af0ce9e11a6ae64260a8548231d93ef01915e0e093cb1608e4907304a  goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.mod
7f34778dbf6f075d3228cce2b1485b3787e9480b85bbdeb2d124727122ba2bf6  goproxy/github.com/!actenon/sdk-go/@v/v1.1.0.zip
c01c86b684fd8edb810b340af670e5993b8794f3706d9b528a17eec70a0992a5  npm/actenon-protocol-types-1.4.0.tgz
0322270b9790235c8a56f498e54447028ecfc792b79c3a4da4237e4dcd3a9b1f  npm/actenon-sdk-2.0.0.tgz
adfa3bcc762b88fb96e7f1a4f741655065de8af26af8a917a27282ecfc57e8bb  npm/actenon-verifier-sdk-0.2.0.tgz
d4d5f45f175cef69087c7334f5e476f9ed01eca49396bddf73d7295c5510fdc3  pypi/actenon_kernel-1.3.0-py3-none-any.whl
3bb2e4da31cb592efe3b60ec57c190dd2623be61080ddd1f26cff5208b8793f4  pypi/actenon_kernel-1.3.0.tar.gz
e1fd3c13583cf620189a7335b4f6414e180ccd343f8dbfb558ecce00addad241  pypi/actenon_permit-2.0.0-py3-none-any.whl
528fce0718562129e4fd17290c7244e883debe969e1e7a08852011cab3b434f8  pypi/actenon_permit-2.0.0.tar.gz
bb21f93be62b15bf6d9d414ee17edcb0f79b9dc7bf306ea7a0e9df9b76a36e2d  pypi/actenon_protocol-1.4.0-py3-none-any.whl
ab4b596ed00bda14630e5976cfe944f1080f11403fb9f4b1d8e045aa0eacb70f  pypi/actenon_protocol-1.4.0.tar.gz
```

## Steps (`fresh-consumer/runs/rehearsal-3-final/results.tsv`)

| Step | Result |
|---|---|
| python-py310 kernel conformance (shipped suite) | PASS |
| python-py310 actenon-kernel scan | PASS |
| protocol tag vectors match vectors.sha256 | PASS |
| python-py310 protocol conformance runner (Actenon-compatible v1.4.0) | PASS |
| python-py310 protocol standalone runner, installed schemas only (control v2) | PASS |
| python-py310 protocol canonicalisation vectors | PASS |
| python-py310 permit steps | N/A (actenon-permit Requires-Python >=3.11) |
| python-py310 differential corpus run | PASS |
| python-py311 kernel conformance (shipped suite) | PASS |
| python-py311 actenon-kernel scan | PASS |
| protocol tag vectors match vectors.sha256 | PASS |
| python-py311 protocol conformance runner (Actenon-compatible v1.4.0) | PASS |
| python-py311 protocol standalone runner, installed schemas only (control v2) | PASS |
| python-py311 protocol canonicalisation vectors | PASS |
| python-py311 permit README quickstart | PASS |
| python-py311 'actenon demo' | PASS |
| python-py311 differential corpus run | PASS |
| python-py312 kernel conformance (shipped suite) | PASS |
| python-py312 actenon-kernel scan | PASS |
| protocol tag vectors match vectors.sha256 | PASS |
| python-py312 protocol conformance runner (Actenon-compatible v1.4.0) | PASS |
| python-py312 protocol standalone runner, installed schemas only (control v2) | PASS |
| python-py312 protocol canonicalisation vectors | PASS |
| python-py312 permit README quickstart | PASS |
| python-py312 'actenon demo' | PASS |
| python-py312 differential corpus run | PASS |
| typescript plain-node imports of all three packages | PASS |
| typescript @actenon/verifier-sdk kernel vectors (cases+timestamps+edge+revocation) | PASS |
| typescript @actenon/protocol-types canonicalisation vectors | PASS |
| typescript differential corpus run | PASS |
| go module provenance (v1.1.0 zip digest = artefact, module cache path) | PASS |
| go consumer: kernel vectors from installed wheel via public API | PASS |
| go module's own test suite from the module cache (lock = installed wheel) | PASS |
| go differential corpus run (strict) | PASS |
| go differential corpus run (usenumber) | PASS |
| rust crate provenance (Cargo.lock checksum = artefact, registry source) | PASS |
| rust consumer: kernel vectors from installed wheel via public API | PASS |
| rust crate's own test suite from the downloaded .crate (lock = installed wheel) | PASS |
| rust differential corpus run | PASS |
| no /home/user source path in any resolver state | PASS |

**40 steps, 0 failures** (one N/A: actenon-permit declares Requires-Python >=3.11).

## Evidence of the path to this result (preserved)

- `runs/rehearsal-1-dry3-harness-dev`: two harness defects (vector-lock path, missing Rust `ed25519` feature) and one
  **product defect**: kernel timestamps were interpreter-dependent (fixed in actenon-kernel 8c5c25e; sdk-go 8a87d6f).
- `runs/rehearsal-1-prefix-timestamp-measurement`: the frozen timestamp-grammar addendum through every language before the fix.
- `runs/rehearsal-2-run1`, `-run2`: rehearsal 2. Between rehearsals 2 and 3 a second product defect was found and fixed
  (PostgreSQL replay store: concurrent cold start, actenon-kernel 38dd580 + 185e0fd).
