# LPTana
**Linux PCAP Threat Pattern Analyzer**

LPTana is a Python-based CLI project that helps scope potentially suspicious network activity by analyzing packet capture (PCAP) data that has been exported into structured fields (CSV). The goal is to quickly identify patterns worth investigating (top talkers, protocols, unusual ports, repeated connections) in a lab or authorized environment.

This project is intentionally separate from my **PortScanner** project:
- **LPTana** = scoping/triage from capture data (what happened)
- **PortScanner** = active scanning (what is exposed)

---

## What this demonstrates
- PCAP analysis fundamentals (field-based analysis)
- Defensive thinking: triage → scope → prioritize
- Data parsing and reporting in Python
- Building a repeatable CLI workflow

---

## Repo structure
- `src/` — analysis scripts
- `data/` — sample/sanitized datasets only
- `docs/` — design notes, screenshots, how-it-works
- `evidence/` — sanitized example outputs/screenshots
- `examples/` — example commands and sample runs

---

## Workflow (high level)
1. Export PCAP fields to CSV (example: using tshark)
2. Run LPTana against the CSV
3. Review summary output to decide what needs deeper investigation

> Note: This repo does not include sensitive captures. Only sanitized or generated data should be stored in `data/`.

---

## Usage (placeholder)
I’m actively improving this project. Usage and examples will be updated as the tool stabilizes.

For now:
- See `src/` for the current implementation
- See `examples/` for example runs (coming next)
- See `evidence/` for sanitized output snapshots (coming next)

---

## Planned improvements
- More consistent CLI flags and help output
- Better reporting (JSON/CSV summaries)
- Detection-oriented summaries (beaconing hints, repeated connections, uncommon ports)
- Documentation and reproducible demo dataset

---

## Disclaimer
This project is for educational use and authorized environments only.

