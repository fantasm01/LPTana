printf "# LPTana\n\nLinux PCAP Threat Pattern Analyzer for CYB333.\n\nStatus: project initialized.\n" > README.md

## Usage (CSV Mode)

LPTana analyzes a CSV created from a PCAP using `tshark` field extraction.

### Run against the normal sample dataset
```bash
python3 src/lptana.py --csv data/sample_parsed.csv
