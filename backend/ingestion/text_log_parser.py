"""Convert messy text logs into supported connection-level CSV rows."""
import re
from typing import List

PROTO_RE = re.compile(r"\b(tcp|udp|icmp)\b", re.IGNORECASE)
KV_RE = re.compile(r"(duration|src_bytes|dst_bytes|service|flag|protocol|protocol_type|label|land|wrong_fragment|urgent)=([^\s,;]+)", re.IGNORECASE)


def _build_row(fields: dict) -> str:
    duration = fields.get("duration", "0")
    protocol = fields.get("protocol_type", fields.get("protocol", "tcp")).lower()
    service = fields.get("service", "other").lower()
    flag = fields.get("flag", "SF")
    src_bytes = fields.get("src_bytes", "0")
    dst_bytes = fields.get("dst_bytes", "0")
    land = fields.get("land", "0")
    wrong_fragment = fields.get("wrong_fragment", "0")
    urgent = fields.get("urgent", "0")
    label = fields.get("label", "normal").lower()
    return f"{duration},{protocol},{service},{flag},{src_bytes},{dst_bytes},{land},{wrong_fragment},{urgent},{label}"


def text_to_compact_csv(raw_text: str) -> str:
    """Convert unstructured text lines into compact 10-column schema CSV."""
    rows: List[str] = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.count(",") >= 9:
            rows.append(line)
            continue

        fields = {k.lower(): v for k, v in KV_RE.findall(line)}
        if "protocol_type" not in fields:
            proto_match = PROTO_RE.search(line)
            if proto_match:
                fields["protocol_type"] = proto_match.group(1).lower()

        # heuristic bytes fallback e.g. "bytes=1234"
        bytes_match = re.search(r"\bbytes=(\d+)\b", line)
        if bytes_match and "src_bytes" not in fields:
            fields["src_bytes"] = bytes_match.group(1)

        if fields:
            rows.append(_build_row(fields))

    return "\n".join(rows)
