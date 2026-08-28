# domain-fuzzer

Advanced domain-based phishing and impersonating-domain detection tool.

Given a domain (e.g. `example.com`), it generates realistic typosquatting and
homoglyph variations (character insertion, deletion, substitution, homoglyph
swaps, hyphenation), then checks which of those variations are actually
registered/live — via HTTP and DNS — and tries to find an abuse-reporting
contact via WHOIS, so you can spot and report domains impersonating you.

## What changed from the original version

- **Fixed dead/duplicated code**: `network.py` and `whois_query.py` had
  free functions that took a stray, unused `self` argument and were never
  actually called — `fuzzer.py` had its own copy-pasted versions instead.
  The scanner now properly composes the split-out `network` and
  `whois_query` modules.
- **Concurrency**: the original scanned every variation (often 300+ for a
  single domain) one at a time — HTTP request, then DNS lookup, then a WHOIS
  query, sequentially. That's minutes of dead time. Scanning is now
  parallelized with a thread pool (`--threads`, default 20).
- **Deduplication**: character-insertion/substitution can regenerate the same
  string via different techniques; variations are now deduplicated and the
  original domain itself is excluded from results.
- **CLI**: `main.py` now takes the domain as an argument (falls back to the
  interactive prompt if omitted), plus flags for threads, timeout, skipping
  WHOIS, disabling the progress bar, and choosing a different homoglyph
  model file.
- **Export**: `--output results.csv` / `--output results.json` writes the
  full result set out, not just what's printed to the terminal.
- **Input validation**: `parser.py` now accepts bare domains or full URLs,
  strips ports/credentials, and rejects garbage input before wasting time
  fuzzing it.
- **Fixed `requirements.txt`**: it listed `whois`, which is a *different*,
  unrelated PyPI package from the one the code actually imports
  (`whois.whois(...)` with `.status`/`.emails` is the API of `python-whois`).
  Also added `python-Levenshtein` so `fuzzywuzzy` doesn't fall back to a slow
  pure-Python matcher.
- **Better error handling**: WHOIS/DNS/HTTP failures are caught per-technique
  instead of raising through the whole scan; a missing/invalid homoglyph
  model or empty input now fails with a clear message instead of a traceback.
- **Results sorted by similarity** (most dangerous look-alikes first) with
  a stable `#` index, instead of raw generation order.
- **Proper package layout** with `__init__.py` files, matching what `main.py`
  already expected (`core.services.fuzzer`, etc.).

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Interactive (prompts for a domain)
python main.py

# Non-interactive
python main.py example.com

# Faster scan, skip WHOIS (WHOIS servers are often rate-limited/slow)
python main.py example.com --no-whois --threads 40

# Save full results
python main.py example.com --output results.csv
python main.py example.com --output results.json
```

### Options

| Flag | Description |
|---|---|
| `domain` | Domain to analyze (optional; prompts if omitted) |
| `-o, --output FILE` | Write results to CSV or JSON (by extension) |
| `-t, --threads N` | Concurrent workers for HTTP/DNS/WHOIS (default: 20) |
| `--timeout SECONDS` | Per-request network timeout (default: 5) |
| `--no-whois` | Skip WHOIS abuse-contact lookups |
| `--no-progress` | Disable the progress bar |
| `--model PATH` | Path to a custom homoglyph model JSON |
| `-q, --quiet` | Suppress the startup banner |
| `-v, --verbose` | Debug logging |

## Techniques

| Code | Technique |
|---|---|
| `CA` | Character addition |
| `CD` | Character deletion |
| `CR` | Character replacement |
| `HM` | Homoglyph substitution (visually similar Unicode characters) |
| `HP` | Hyphenation |

## Project layout

```
main.py
core/
  services/
    fuzzer.py       # variation generation + concurrent scan orchestration
    network.py       # HTTP availability + DNS resolution
    whois_query.py   # WHOIS abuse-contact lookup
    parser.py         # domain parsing/validation
    input.py           # interactive prompt
    export.py         # CSV/JSON export
data/
  homoglyph/
    model.json        # character -> visually-similar-character map
```

## Notes

- This tool is intended for **defensive** use: monitoring for domains that
  impersonate your own brand/organization so they can be reported and taken
  down. Be mindful of target sites' terms of service and rate limits — the
  default 20 threads is a reasonable balance, but consider lowering it for
  large-scale scans.
- WHOIS lookups are the slowest and most rate-limit-prone step; use
  `--no-whois` for a quick availability sweep and re-run WHOIS only on the
  interesting hits if needed.
