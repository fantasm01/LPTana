#!/usr/bin/env python3
"""
LPTana - Phase 4 (Output/Testing/Cleanup upgrades)
Reads tshark-exported CSV and flags simple suspicious patterns.

Examples:
  python3 src/lptana_phase3.py --csv data/sample_parsed.csv
  python3 src/lptana_phase3.py --csv data/scan_demo_parsed.csv
  python3 src/lptana_phase3.py --csv data/scan_demo_parsed.csv --portscan-threshold 20
"""

import argparse
import csv
from collections import defaultdict, Counter
from pathlib import Path


def parse_args():
    p = argparse.ArgumentParser(
        description="LPTana (Linux PCAP Threat Pattern Analyzer) - CSV analyzer"
    )
    p.add_argument(
        "--csv",
        default="data/sample_parsed.csv",
        help="Path to tshark-parsed CSV (default: data/sample_parsed.csv)",
    )
    p.add_argument(
        "--portscan-threshold",
        type=int,
        default=30,
        help="Unique dst ports threshold for port-scan alert (default: 30)",
    )
    p.add_argument(
        "--repeat-threshold",
        type=int,
        default=100,
        help="Repeat attempts threshold for dst:port alert (default: 100)",
    )
    p.add_argument(
        "--top",
        type=int,
        default=10,
        help="How many top talkers to display (default: 10)",
    )
    return p.parse_args()


def pick_ip(row: dict, key_v4: str, key_v6: str) -> str:
    """Prefer IPv4 field if present; else IPv6; else empty string."""
    v4 = (row.get(key_v4) or "").strip()
    if v4:
        return v4
    v6 = (row.get(key_v6) or "").strip()
    return v6


def pick_port(row: dict, key_tcp: str, key_udp: str) -> str:
    """Prefer TCP port if present; else UDP; else empty string."""
    tcp = (row.get(key_tcp) or "").strip()
    if tcp:
        return tcp
    udp = (row.get(key_udp) or "").strip()
    return udp


def is_mdns(dst_ip: str, dst_port: str) -> bool:
    """
    Very simple mDNS detector:
      - mDNS uses UDP/5353
      - common multicast targets: 224.0.0.251 (IPv4), ff02::fb (IPv6)
    """
    if (dst_port or "").strip() == "5353":
        return True
    ip = (dst_ip or "").strip()
    return ip in {"224.0.0.251", "ff02::fb"}


def main() -> None:
    args = parse_args()
    csv_path = Path(args.csv)

    portscan_thresh = args.portscan_threshold
    repeat_thresh = args.repeat_threshold
    top_n = args.top

    if not csv_path.exists():
        print(f"[!] Missing file: {csv_path}")
        print("    Run tshark extraction first (Phase 2B) or check your path.")
        return

    # src_ip -> stats
    src_to_unique_ports = defaultdict(set)         # {src: {dst_port, ...}}
    src_to_packet_count = Counter()                # {src: total_packets}
    src_to_dst_count = defaultdict(set)            # {src: {dst_ip, ...}}
    src_to_dstport_counter = defaultdict(Counter)  # {src: Counter({"dst:port": n})}

    # Read CSV
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Basic validation: ensure expected columns exist (not strict, but helpful)
        expected = {"ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport"}
        missing = [c for c in expected if c not in (reader.fieldnames or [])]
        if missing:
            print("[!] CSV is missing some expected columns (continuing anyway):")
            for c in missing:
                print(f"    - {c}")
            print()

        for row in reader:
            src_ip = pick_ip(row, "ip.src", "ipv6.src")
            dst_ip = pick_ip(row, "ip.dst", "ipv6.dst")
            dst_port = pick_port(row, "tcp.dstport", "udp.dstport")

            # Skip rows without a usable source IP
            if not src_ip:
                continue

            # Always count packets per source
            src_to_packet_count[src_ip] += 1

            # Track unique destinations per source
            if dst_ip:
                src_to_dst_count[src_ip].add(dst_ip)

            # Track unique destination ports per source
            if dst_port:
                src_to_unique_ports[src_ip].add(dst_port)

            # Repeat-attempt tracking:
            # Ignore noisy multicast/mDNS traffic so alerts are more meaningful.
            if dst_ip and dst_port and (not is_mdns(dst_ip, dst_port)):
                key = f"{dst_ip}:{dst_port}"
                src_to_dstport_counter[src_ip][key] += 1

    # --- Summary ---
    print("\n=== LPTana Summary ===")
    print(f"Input CSV: {csv_path}")
    print(f"Thresholds: portscan_unique_ports>={portscan_thresh}, repeat_attempts>={repeat_thresh} (DNS ignored in repeat alerts)")
    print(f"Unique sources seen: {len(src_to_packet_count)}\n")

    # Print top talkers by packet count
    print("Top sources by packet count:")
    for src, count in src_to_packet_count.most_common(top_n):
        uniq_ports = len(src_to_unique_ports[src])
        uniq_dsts = len(src_to_dst_count[src])
        print(f"  {src:<39} packets={count:<6} unique_dsts={uniq_dsts:<4} unique_ports={uniq_ports:<4}")

    # --- Alerts ---
    print("\n=== Alerts (simple heuristics) ===")
    any_alerts = False

    # 1) Port-scan-ish behavior: many unique destination ports
    for src, ports in src_to_unique_ports.items():
        if len(ports) >= portscan_thresh:
            any_alerts = True
            print(f"[ALERT] Possible port scan: {src} hit {len(ports)} unique dst ports")
            print("        Why: one source contacted many different destination ports in this capture.")

    # 2) Repeated attempts to same dst:port
    #    Option B: ignore DNS :53 in alerts (but we still counted it)
    for src, c in src_to_dstport_counter.items():
        if not c:
            continue

        non_dns = [(k, v) for k, v in c.items() if not k.endswith(":53")]
        if not non_dns:
            continue

        dstport, hits = max(non_dns, key=lambda x: x[1])

        if hits >= repeat_thresh:
            any_alerts = True
            print(f"[ALERT] Repeated attempts: {src} -> {dstport} ({hits} packets)")
            print("        Why: one source sent many packets to the same destination IP and port.")

    if not any_alerts:
        print("No alerts triggered with current thresholds.")

    print("\nDone.\n")


if __name__ == "__main__":
    main()
