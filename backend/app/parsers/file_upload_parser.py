from __future__ import annotations

import csv
import io
import json
import struct
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.models.enums import EventSource

logger = get_logger(__name__)


class FileTypeDetector:
    """Detect evidence file type from extension and content sniffing."""

    EXTENSION_SOURCE_MAP: dict[str, EventSource] = {
        ".jsonl": EventSource.SYSMON,
        ".json":  EventSource.SYSMON,
        ".evtx":  EventSource.EVTX,
        ".xml":   EventSource.XML,
        ".csv":   EventSource.CSV,
        ".pcap":  EventSource.PCAP,
        ".pcapng": EventSource.PCAP,
        ".log":   EventSource.GENERIC,
        ".txt":   EventSource.GENERIC,
        ".e01":   EventSource.DISK_IMAGE,
        ".dd":    EventSource.DISK_IMAGE,
        ".img":   EventSource.DISK_IMAGE,
        ".vmdk":  EventSource.DISK_IMAGE,
        ".raw":   EventSource.DISK_IMAGE,
        ".dmp":   EventSource.MEMORY_DUMP,
        ".mem":   EventSource.MEMORY_DUMP,
    }

    # Raw PCAP magic bytes
    PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"
    PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"
    PCAPNG_MAGIC  = b"\x0a\x0d\x0d\x0a"

    @classmethod
    def is_raw_pcap(cls, content: bytes) -> bool:
        if len(content) < 4:
            return False
        return content[:4] in (cls.PCAP_MAGIC_LE, cls.PCAP_MAGIC_BE, cls.PCAPNG_MAGIC)

    def detect(self, filename: str, content: bytes) -> EventSource:
        # Raw binary PCAP/PCAPNG — check magic bytes first regardless of extension
        if self.is_raw_pcap(content):
            return EventSource.PCAP

        ext = Path(filename).suffix.lower()
        if ext in self.EXTENSION_SOURCE_MAP:
            source = self.EXTENSION_SOURCE_MAP[ext]
            # Refine JSON/JSONL by content sniffing
            if source == EventSource.SYSMON and content:
                return self._sniff_json(content)
            return source

        # Fallback content sniffing
        if content:
            if content[:4] in (b"ElfF", b"\x45\x6c\x66\x46"):
                return EventSource.EVTX
            if content[:5] == b"<?xml" or content[:1] == b"<":
                return EventSource.XML
        return EventSource.UNKNOWN

    @staticmethod
    def _sniff_json(content: bytes) -> EventSource:
        try:
            text = content[:8192].decode("utf-8", errors="ignore").strip()
            # Try full JSON parse first
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                # Fall back to first JSONL line
                first_line = text.splitlines()[0] if text else ""
                obj = json.loads(first_line) if first_line.startswith("{") else {}

            if isinstance(obj, dict):
                # Unwrap wrapper objects: {"flows": [...], "capture_id": ...}
                for key in ("flows", "records", "events", "data", "packets"):
                    if key in obj and isinstance(obj[key], list) and obj[key]:
                        sample = obj[key][0]
                        if isinstance(sample, dict) and "src_ip" in sample and "dst_ip" in sample:
                            return EventSource.PCAP

                # Direct PCAP metadata at top level
                if "src_ip" in obj and "dst_ip" in obj:
                    return EventSource.PCAP

                # Sysmon / EVTX detection
                if "EventID" in obj:
                    channel = str(obj.get("Channel", "")).lower()
                    if "sysmon" in channel or "ProcessGuid" in obj:
                        return EventSource.SYSMON
                    return EventSource.EVTX

            if isinstance(obj, list) and obj:
                sample = obj[0]
                if isinstance(sample, dict):
                    if "src_ip" in sample and "dst_ip" in sample:
                        return EventSource.PCAP
                    if "EventID" in sample:
                        channel = str(sample.get("Channel", "")).lower()
                        if "sysmon" in channel or "ProcessGuid" in sample:
                            return EventSource.SYSMON
                        return EventSource.EVTX
        except Exception:
            pass
        return EventSource.SYSMON


class EvidenceFileParser:
    """Parse uploaded evidence files into raw records for normalization."""

    def __init__(self) -> None:
        self.detector = FileTypeDetector()

    def parse(
        self, filename: str, content: bytes
    ) -> tuple[EventSource, list[dict[str, Any]]]:
        source = self.detector.detect(filename, content)
        logger.info(
            "Detected evidence type",
            extra={"extra_data": {"filename": filename, "source": str(source), "bytes": len(content)}},
        )

        if source in (EventSource.SYSMON, EventSource.EVTX):
            return source, self._parse_jsonl(content)
        if source == EventSource.PCAP:
            if FileTypeDetector.is_raw_pcap(content):
                return source, self._parse_raw_pcap(content)
            return source, self._parse_pcap_metadata(content)
        if source == EventSource.XML:
            return source, self._parse_xml_events(content)
        if source == EventSource.CSV:
            return source, self._parse_csv(content)
        if source in (EventSource.DISK_IMAGE, EventSource.MEMORY_DUMP):
            return source, self._parse_binary_manifest(filename, content)
        if source == EventSource.GENERIC:
            return source, self._parse_generic_log(content)
        if source == EventSource.EVTX and content[:4] in (b"ElfF", b"\x45\x6c\x66\x46"):
            return source, self._evtx_binary_placeholder(filename)
        return EventSource.UNKNOWN, []

    # ------------------------------------------------------------------ #

    @staticmethod
    def _parse_jsonl(content: bytes) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        text = content.decode("utf-8", errors="replace")
        stripped = text.strip()
        if stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return records

    @staticmethod
    def _parse_pcap_metadata(content: bytes) -> list[dict[str, Any]]:
        """Parse PCAP flow metadata JSON — handles arrays and wrapper objects."""
        text = content.decode("utf-8", errors="replace").strip()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None

        if isinstance(obj, list):
            return obj

        if isinstance(obj, dict):
            # Unwrap common wrapper keys
            for key in ("flows", "records", "events", "data", "packets"):
                if key in obj and isinstance(obj[key], list):
                    return obj[key]
            # Single flow object
            if "src_ip" in obj:
                return [obj]

        # Fallback: JSONL
        records: list[dict[str, Any]] = []
        for line in (text or "").splitlines():
            line = line.strip()
            if line.startswith("{"):
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return records

    @staticmethod
    def _parse_raw_pcap(content: bytes) -> list[dict[str, Any]]:
        """
        Parse raw binary PCAP files using pure Python struct parsing.
        Extracts TCP/UDP flows — no scapy required.
        Supports little-endian (d4 c3 b2 a1) and big-endian (a1 b2 c3 d4).
        """
        records: list[dict[str, Any]] = []
        if len(content) < 24:
            return records

        magic = content[:4]
        if magic == FileTypeDetector.PCAP_MAGIC_LE:
            endian = "<"
        elif magic == FileTypeDetector.PCAP_MAGIC_BE:
            endian = ">"
        else:
            # PCAPNG — return a placeholder
            return [{
                "timestamp": "",
                "src_ip": "unknown", "dst_ip": "unknown",
                "src_port": 0, "dst_port": 0,
                "protocol": "unknown",
                "bytes_sent": len(content), "bytes_received": 0,
                "note": "PCAPNG format. Convert with: editcap -F pcap input.pcapng output.pcap",
            }]

        try:
            _, _, _, _, _, _, link_type = struct.unpack_from(endian + "IHHiIII", content, 0)
        except struct.error:
            return records

        if link_type not in (1, 101):
            return [{
                "timestamp": "", "src_ip": "unknown", "dst_ip": "unknown",
                "protocol": "unknown", "bytes_sent": len(content), "bytes_received": 0,
                "note": f"Unsupported link type {link_type}. Ethernet(1) and raw IP(101) supported.",
            }]

        offset = 24
        flow_map: dict[tuple, dict[str, Any]] = {}
        packet_count = 0

        while offset + 16 <= len(content) and packet_count < 100000:
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", content, offset)
            except struct.error:
                break

            offset += 16
            pkt_data = content[offset: offset + incl_len]
            offset += incl_len
            packet_count += 1

            if len(pkt_data) < incl_len:
                break

            ip_offset = 14 if link_type == 1 else 0
            if len(pkt_data) < ip_offset + 20:
                continue

            ip_byte = pkt_data[ip_offset]
            if (ip_byte >> 4) != 4:
                continue  # skip non-IPv4

            ihl = (ip_byte & 0xF) * 4
            protocol_num = pkt_data[ip_offset + 9]
            src_ip = ".".join(str(b) for b in pkt_data[ip_offset + 12: ip_offset + 16])
            dst_ip = ".".join(str(b) for b in pkt_data[ip_offset + 16: ip_offset + 20])

            src_port = dst_port = 0
            protocol = "ip"
            transport_offset = ip_offset + ihl

            if protocol_num == 6 and len(pkt_data) >= transport_offset + 4:
                src_port, dst_port = struct.unpack_from(">HH", pkt_data, transport_offset)
                protocol = "tcp"
            elif protocol_num == 17 and len(pkt_data) >= transport_offset + 4:
                src_port, dst_port = struct.unpack_from(">HH", pkt_data, transport_offset)
                protocol = "udp"
            elif protocol_num == 1:
                protocol = "icmp"

            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)

            if flow_key not in flow_map:
                flow_map[flow_key] = {
                    "timestamp": _ts_to_iso(ts_sec),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "bytes_sent": orig_len,
                    "bytes_received": 0,
                    "packet_count": 1,
                }
            else:
                flow_map[flow_key]["bytes_sent"] += orig_len
                flow_map[flow_key]["packet_count"] += 1

        result = list(flow_map.values())
        logger.info(
            "Parsed raw PCAP",
            extra={"extra_data": {"packets": packet_count, "flows": len(result)}},
        )
        return result

    @staticmethod
    def _parse_xml_events(content: bytes) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(content.decode("utf-8", errors="replace"))
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            events = root.findall(".//e:Event", ns) or root.findall(".//Event")
            if not events and root.tag in ("Event", "{http://schemas.microsoft.com/win/2004/08/events/event}Event"):
                events = [root]
            for event in events:
                record: dict[str, Any] = {}
                system = event.find("e:System", ns) or event.find("System")
                if system is not None:
                    eid = system.find("e:EventID", ns) or system.find("EventID")
                    if eid is not None:
                        record["EventID"] = int(eid.text or 0)
                    tc = system.find("e:TimeCreated", ns) or system.find("TimeCreated")
                    if tc is not None:
                        record["TimeCreated"] = tc.get("SystemTime", "")
                    comp = system.find("e:Computer", ns) or system.find("Computer")
                    if comp is not None:
                        record["Computer"] = comp.text
                    channel = system.find("e:Channel", ns) or system.find("Channel")
                    if channel is not None:
                        record["Channel"] = channel.text
                event_data = event.find("e:EventData", ns) or event.find("EventData")
                if event_data is not None:
                    for data in event_data:
                        name = data.get("Name")
                        if name:
                            record[name] = data.text
                if record:
                    records.append(record)
        except ET.ParseError as exc:
            logger.warning("XML parse error", extra={"extra_data": {"error": str(exc)}})
        return records

    @staticmethod
    def _parse_csv(content: bytes) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        text = content.decode("utf-8", errors="replace")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            records.append(dict(row))
        return records

    @staticmethod
    def _parse_binary_manifest(filename: str, content: bytes) -> list[dict[str, Any]]:
        return [{
            "EventID": 0,
            "source_type": "disk_image" if any(
                filename.endswith(e) for e in (".e01", ".dd", ".img", ".vmdk")
            ) else "memory_dump",
            "filename": filename,
            "size_bytes": len(content),
            "note": (
                "Binary forensic image detected. "
                "For full analysis, convert with Autopsy/Volatility and re-ingest the extracted artefacts."
            ),
            "Computer": "unknown",
            "UtcTime": "",
        }]

    @staticmethod
    def _parse_generic_log(content: bytes) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for i, line in enumerate(content.decode("utf-8", errors="replace").splitlines()):
            line = line.strip()
            if not line:
                continue
            records.append({"EventID": 0, "Message": line, "LineNumber": i + 1, "Computer": "unknown"})
        return records

    @staticmethod
    def _evtx_binary_placeholder(filename: str) -> list[dict[str, Any]]:
        return [{
            "EventID": 0,
            "source_type": "evtx_binary",
            "filename": filename,
            "note": (
                "Binary EVTX file detected. "
                "Export to JSON with: python-evtx or wevtutil qe <file> /lf:true /f:xml "
                "then re-ingest the JSON/XML output."
            ),
            "Computer": "unknown",
            "UtcTime": "",
        }]


def _ts_to_iso(ts_sec: int) -> str:
    try:
        return datetime.fromtimestamp(ts_sec, tz=timezone.utc).isoformat()
    except Exception:
        return ""
