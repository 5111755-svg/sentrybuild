# SentryBuild

SentryBuild is a CLI tool that detects supply-chain tampering in compiled
artifacts by inspecting ELF binaries and shared libraries for structural
anomalies: unauthorized **IFUNC** resolvers, hijacked **GOT/PLT** entries,
new or retargeted dynamic symbol hooks, weakened hardening, and dependency
drift — all by diffing a candidate build against a trusted baseline
snapshot.

## Why this, specifically

Most "is this package tampered with" checks stop at a file hash. That
catches a byte-for-byte swap but says nothing about *what* changed, and a
hash comparison alone can't tell a legitimate recompilation from an
injected hook. SentryBuild instead:

1. **Extracts structure**, not just bytes — dynamic symbols (including
   `STT_GNU_IFUNC` resolvers), relocation entries (`GOT`/`PLT` slots and
   what symbol each one resolves to), `DT_NEEDED` dependencies, `RPATH`/
   `RUNPATH`, and standard hardening flags (`RELRO`, `BIND_NOW`, `PIE`,
   `NX`).
2. **Diffs that structure against a baseline**, because tampering shows up
   as *drift*: a PLT slot that used to resolve to `printf` now resolving
   to something else, a new `IFUNC` resolver that wasn't in the last known
   good build, a newly introduced `RPATH` that could redirect library
   resolution to an attacker-controlled path.
3. **Assigns severity** (`INFO` / `WARNING` / `CRITICAL`) to each kind of
   drift so it can gate a CI pipeline rather than just dump a wall of text.

## Install

```bash
pip install -r requirements.txt
pip install -e .
```

Requires Python 3.9+ and [`pyelftools`](https://github.com/eliben/pyelftools).

## Usage

### Scan a binary or a directory tree

```bash
sentrybuild scan /usr/lib/x86_64-linux-gnu/libcrypto.so.3 -o scan.json
sentrybuild scan /usr/lib/x86_64-linux-gnu/ -r -o dir_scan.json
```

### Save a trusted baseline

```bash
sentrybuild baseline /path/to/known-good/binary baseline.json
```

### Compare a candidate against a baseline

```bash
sentrybuild diff baseline.json candidate.json --format human --fail-on CRITICAL
```

`diff` also accepts directory-scan JSON (a list of per-file snapshots) on
either side, matching files by absolute path and reporting files that
appeared or disappeared between the two scans.

### Scan-and-diff in one step

```bash
sentrybuild verify /path/to/binary --baseline baseline.json --fail-on WARNING
```

or, using the positional form:

```bash
sentrybuild verify /path/to/binary baseline.json
```

### Exit codes

`diff` and `verify` return:

- `0` — nothing at or above `--fail-on` (default `CRITICAL`) was found
- `1` — a finding at or above that severity was found (use this to gate CI)
- `2` — usage or I/O error (missing file, unreadable JSON, etc.)

## What triggers each severity

| Code | Severity | Meaning |
|---|---|---|
| `IFUNC_ADDED` | CRITICAL | A new `STT_GNU_IFUNC` resolver appeared. IFUNC resolvers run at load time, before most control-flow protections apply. |
| `PLT_SLOT_RETARGETED` | CRITICAL | A PLT/GOT slot now resolves to a different symbol than in the baseline — the signature of a dynamic symbol hook. |
| `NEW_IRELATIVE_RELOCATION` | CRITICAL | A new indirect (`IRELATIVE`) relocation appeared that wasn't in the baseline. |
| `RPATH_INTRODUCED` | CRITICAL | `DT_RPATH` was added; it takes precedence over `LD_LIBRARY_PATH` and can redirect dynamic linking to an attacker path. |
| `NX_LOST` | CRITICAL | The stack went from non-executable to executable. |
| `IFUNC_REMOVED`, `RELOCATION_TARGET_CHANGED`, `NEEDED_LIBRARY_ADDED`, `RUNPATH_CHANGED`, `SONAME_CHANGED`, `RELRO_WEAKENED`, `PIE_LOST`, `SYMBOL_TYPE_OR_BINDING_CHANGED` | WARNING | Notable but not automatically conclusive — needs a human to confirm it matches an intended change. |
| `HASH_CHANGED`, `RELOCATION_ADDED`, `RELOCATION_REMOVED`, `NEEDED_LIBRARY_REMOVED`, `BIND_NOW_LOST`, `ENTRY_POINT_CHANGED`, `IDENTICAL_FILE`, `IFUNC_PRESENT` | INFO | Context and expected-with-recompilation changes. |

## Architecture

```
sentrybuild/
├── elf_scanner.py   # Extracts a JSON-serializable structural snapshot from one ELF file
├── diff_engine.py   # Compares two snapshots and produces severity-tagged findings
└── cli.py           # scan / baseline / diff / verify subcommands
```

`elf_scanner` has no opinion about what's malicious — it just describes
structure faithfully, including single-file hardening observations (no
`RELRO`, executable stack, `RPATH` present) that don't need a baseline to
flag. `diff_engine` is where cross-build tamper detection happens, since
almost none of the interesting hijacking patterns (a swapped PLT target,
an injected `IFUNC`) are visible from a single scan in isolation — they
only show up as a change from a known-good state.

## Limitations

- This detects *structural* drift, not runtime behavior — a resolver that
  legitimately returns a different implementation based on CPU features
  (a common, benign use of IFUNC in libraries like glibc for SIMD
  dispatch) will show up as `IFUNC_ADDED`/`IFUNC_REMOVED` across versions
  and needs human triage, same as a malicious one would.
- Symbol/relocation matching in the diff engine is by name and slot
  offset, not a full semantic equivalence check — a rename plus a hook in
  the same commit could evade slot-offset matching. Combine with
  reproducible builds and code review for defense in depth, not as your
  only integrity gate.
- Currently targets ELF (Linux) binaries only.

## Development

```bash
pip install -r requirements.txt
pip install -e .
pip install pytest ruff
pytest -v
ruff check sentrybuild tests
```

Tests compile small real ELF fixtures (including an actual `IFUNC`
resolver) with the system C compiler and run the real `pyelftools`-based
parsing path against them, rather than relying on pre-built binary blobs
or mocks.

## License

MIT — see [LICENSE](LICENSE).
