"""Streaming/log-based ingestion utility for near real-time monitoring.

Usage:
  python -m backend.ingestion.stream_ingestion --file sample.csv --user-id 1 --interval 0.2
  python -m backend.ingestion.stream_ingestion --scapy --iface eth0 --limit 100 --user-id 1
"""
import argparse
import time
from typing import Iterator

from backend.ingestion.log_reader import LogIngestionService


def stream_lines_from_file(path: str) -> Iterator[str]:
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line


def stream_from_scapy(iface: str, limit: int) -> Iterator[str]:
    try:
        from scapy.all import sniff
    except Exception as exc:
        raise RuntimeError("Scapy is not installed. Install scapy to use packet ingestion.") from exc

    packets = sniff(iface=iface, count=limit)
    for pkt in packets:
        proto = "tcp" if pkt.haslayer("TCP") else "udp" if pkt.haslayer("UDP") else "icmp"
        src = getattr(pkt, "src", "0.0.0.0")
        dst = getattr(pkt, "dst", "0.0.0.0")
        size = len(pkt)
        row = f"0,{proto},other,SF,{size},0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,1,0,1,0,0,0,0,0,normal,0"
        _ = (src, dst)
        yield row


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--file")
    p.add_argument("--interval", type=float, default=0.0)
    p.add_argument("--user-id", type=int, required=True)
    p.add_argument("--scapy", action="store_true")
    p.add_argument("--iface", default="eth0")
    p.add_argument("--limit", type=int, default=200)
    args = p.parse_args()

    service = LogIngestionService()
    if args.scapy:
        source = stream_from_scapy(args.iface, args.limit)
        source_name = f"scapy_{args.iface}.csv"
    else:
        source = stream_lines_from_file(args.file)
        source_name = args.file

    buffer = []
    for line in source:
        buffer.append(line)
        if len(buffer) >= 100:
            service.ingest("\n".join(buffer), source_name, args.user_id)
            buffer.clear()
        if args.interval > 0:
            time.sleep(args.interval)

    if buffer:
        service.ingest("\n".join(buffer), source_name, args.user_id)


if __name__ == "__main__":
    main()
