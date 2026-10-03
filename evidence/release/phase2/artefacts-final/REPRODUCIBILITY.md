# Reproducibility of the final artefacts

`artefacts-final/` and `../artefacts-e775389-permit-14f593f/` are two builds of the same kernel, sdk-go and sdk-rust
commits by `build_artefacts.sh` (`SOURCE_COMMITS`). The Permit commit differs only in `scripts/`.

| Artefact | Two builds | Note |
|---|---|---|
| `actenon_permit` wheel, `@actenon/sdk` tgz, `@actenon/verifier-sdk` tgz, sdk-go module zip, sdk-rust crate | byte-identical | |
| `actenon_permit` sdist | differs | it contains `scripts/`, which changed between the two Permit commits |
| `actenon_kernel` wheel | differs | contents byte-identical (`unzip` + `diff -r`); only 6 generated `dist-info` entries carry the build time as zip timestamps |
| `actenon_kernel` sdist | differs | build-time tar/gzip metadata |

Probe: building the kernel at e775389 twice with `SOURCE_DATE_EPOCH` set to the commit time gave byte-identical wheels
(`5141835…`); the sdist still differed. Recommendation (not done; it would change the release workflow): set
`SOURCE_DATE_EPOCH` in `publish.yml` so the published wheel can be rebuilt bit-for-bit from its tag.
