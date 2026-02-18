# How LPTana Works (High Level)

LPTana is designed as a quick triage/scoping tool for network capture analysis.

## Inputs
- A structured CSV exported from a PCAP (fields extracted with tools such as tshark).

## Output goals
- Summaries that help you decide what to investigate next:
  - top talkers (src/dst)
  - protocol distribution
  - port distribution (common/uncommon)
  - repeated connections over time (when timestamps exist)

## Why CSV instead of raw PCAP?
Using extracted fields keeps the workflow lightweight and makes it easier to:
- share sanitized datasets
- test parsing logic
- produce consistent summaries

## Next step
As this project matures, the docs will include:
- a stable command syntax
- a sample dataset
- example output snapshots in /evidence
