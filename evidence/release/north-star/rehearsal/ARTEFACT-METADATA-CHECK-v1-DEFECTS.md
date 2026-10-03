# ARTEFACT-METADATA-CHECK v1 — criterion defects (result preserved as-is)

v1 reported two FAILs. Both are defects in the *check*, not in the artefacts:

1. "crate has no git/path dependencies" — v1 grepped the whole normalized Cargo.toml for `path =`.
   The matches are `[lib] path = "src/lib.rs"` and `[[test]] path = "tests/*.rs"` target paths,
   which every published crate carries. They are not dependency sources. v2 parses the TOML and
   inspects only `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` and target-specific tables.
2. "go module zip paths are github.com/!actenon/sdk-go@v1.1.0/..." — the Go module zip format
   (golang.org/x/mod/zip) requires entries prefixed with the *unescaped* module path
   `github.com/Actenon/sdk-go@v1.1.0/`; only the GOPROXY *directory* is case-escaped (`!actenon`).
   v2 asserts the spec-correct prefix, and additionally that `go mod download` through a
   file:// GOPROXY accepts the zip (proved in the fresh-consumer test).

No artefact was rebuilt between v1 and v2; hashes are unchanged.
