# Demo Capture

## Run The Demo

```bash
python3 -m pip install -e ".[asymmetric]"
bash scripts/demo_hero.sh
```

The demo is deterministic, local-only, and writes generated artifacts under
`artifacts/hero_demo_runtime/`, which is ignored by Git.

## Record With Asciinema

Recommended terminal size: 100 columns by 32 rows.

```bash
asciinema rec docs/assets/actenon-hero-demo.cast -c "bash scripts/demo_hero.sh"
```

Recommended pacing:

- start from a clean terminal prompt
- run the command directly
- do not narrate over the terminal output
- stop recording immediately after the final `Done:` line

## Convert To GIF

Do not add asciinema or GIF tooling as project runtime dependencies. Use a local
tooling environment outside the package, for example:

```bash
agg docs/assets/actenon-hero-demo.cast docs/assets/actenon-hero-demo.gif
```

Save outputs here:

- `docs/assets/actenon-hero-demo.cast`
- `docs/assets/actenon-hero-demo.gif`

Until the GIF exists, the README keeps a visible transcript fallback directly
under the placeholder.

