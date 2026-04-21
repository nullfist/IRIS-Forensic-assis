from __future__ import annotations

from collections import defaultdict
from typing import Any

from backend.app.schemas.events import NormalizedEvent


class CorrelationLink:
    def __init__(
        self,
        link_id: str,
        event_ids: list[str],
        reason: str,
        link_type: str,
        shared_attributes: dict[str, Any],
        confidence: float,
    ) -> None:
        self.link_id = link_id
        self.event_ids = event_ids
        self.reason = reason
        self.link_type = link_type
        self.shared_attributes = shared_attributes
        self.confidence = confidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "link_id": self.link_id,
            "event_ids": self.event_ids,
            "reason": self.reason,
            "link_type": self.link_type,
            "shared_attributes": self.shared_attributes,
            "confidence": round(self.confidence, 2),
        }


class CorrelationIntelligenceService:
    """
    Make hidden event relationships explicit with human-readable reasoning.

    Finds connections between events based on:
    - Same user account across different hosts (credential reuse / lateral movement)
    - Same process chain (parent-child GUID linkage)
    - Same destination IP/domain (C2 beaconing / exfiltration)
    - Same file hash (malware propagation)
    - Temporal proximity with shared entity (burst activity)
    """

    def analyze(self, events: list[NormalizedEvent]) -> dict[str, Any]:
        if not events:
            return {"links": [], "total_links": 0, "summary": "No events to correlate."}

        links: list[CorrelationLink] = []
        link_counter = 0

        def next_id() -> str:
            nonlocal link_counter
            link_counter += 1
            return f"link-{link_counter:04d}"

        links.extend(self._correlate_by_user_across_hosts(events, next_id))
        links.extend(self._correlate_by_process_chain(events, next_id))
        links.extend(self._correlate_by_destination(events, next_id))
        links.extend(self._correlate_by_file_hash(events, next_id))
        links.extend(self._correlate_temporal_burst(events, next_id))

        summary = self._build_summary(links, events)

        return {
            "links": [lnk.to_dict() for lnk in links],
            "total_links": len(links),
            "summary": summary,
        }

    # ------------------------------------------------------------------ #

    def _correlate_by_user_across_hosts(
        self, events: list[NormalizedEvent], next_id: Any
    ) -> list[CorrelationLink]:
        """Same user seen on multiple hosts — credential reuse or lateral movement."""
        user_hosts: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
        for e in events:
            if e.user and e.host:
                user_hosts[e.user][e.host].append(e.event_id)

        links: list[CorrelationLink] = []
        for user, host_map in user_hosts.items():
            if len(host_map) < 2:
                continue
            all_event_ids = [eid for eids in host_map.values() for eid in eids]
            host_list = list(host_map.keys())
            links.append(
                CorrelationLink(
                    link_id=next_id(),
                    event_ids=all_event_ids[:20],
                    reason=(
                        f"Account '{user}' was active on {len(host_list)} hosts: "
                        f"{', '.join(host_list[:4])}. "
                        "This pattern indicates credential reuse or lateral movement."
                    ),
                    link_type="user_across_hosts",
                    shared_attributes={"user": user, "hosts": host_list},
                    confidence=0.85,
                )
            )
        return links

    def _correlate_by_process_chain(
        self, events: list[NormalizedEvent], next_id: Any
    ) -> list[CorrelationLink]:
        """Parent-child process relationships via ProcessGuid."""
        guid_to_event: dict[str, NormalizedEvent] = {}
        for e in events:
            if e.process and e.process.process_guid:
                guid_to_event[e.process.process_guid] = e

        links: list[CorrelationLink] = []
        for e in events:
            if not (e.process and e.process.parent_process_guid):
                continue
            parent = guid_to_event.get(e.process.parent_process_guid)
            if not parent:
                continue
            parent_name = (parent.process.image or "").rsplit("\\", 1)[-1] if parent.process else "unknown"
            child_name = (e.process.image or "").rsplit("\\", 1)[-1] if e.process else "unknown"
            links.append(
                CorrelationLink(
                    link_id=next_id(),
                    event_ids=[parent.event_id, e.event_id],
                    reason=(
                        f"'{parent_name}' spawned '{child_name}' via process chain. "
                        f"These events are directly linked by ProcessGuid."
                    ),
                    link_type="process_chain",
                    shared_attributes={
                        "parent_image": parent_name,
                        "child_image": child_name,
                        "parent_guid": e.process.parent_process_guid,
                    },
                    confidence=0.95,
                )
            )
        return links[:30]  # cap to avoid noise

    def _correlate_by_destination(
        self, events: list[NormalizedEvent], next_id: Any
    ) -> list[CorrelationLink]:
        """Multiple events connecting to the same external IP/domain — C2 or exfil."""
        dest_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in events:
            if e.network:
                key = e.network.domain or e.network.dst_ip
                if key:
                    dest_events[key].append(e)

        links: list[CorrelationLink] = []
        for dest, dest_evs in dest_events.items():
            if len(dest_evs) < 2:
                continue
            hosts = list({e.host for e in dest_evs if e.host})
            total_bytes = sum((e.network.bytes_sent or 0) for e in dest_evs if e.network)
            reason = (
                f"{len(dest_evs)} events connected to '{dest}' from {len(hosts)} host(s). "
            )
            if total_bytes > 500_000:
                reason += f"Total outbound data: {total_bytes / (1024*1024):.1f} MB — possible exfiltration."
            else:
                reason += "Repeated connections suggest C2 beaconing or staged downloads."
            links.append(
                CorrelationLink(
                    link_id=next_id(),
                    event_ids=[e.event_id for e in dest_evs[:20]],
                    reason=reason,
                    link_type="shared_destination",
                    shared_attributes={"destination": dest, "hosts": hosts, "total_bytes": total_bytes},
                    confidence=0.80,
                )
            )
        return links

    def _correlate_by_file_hash(
        self, events: list[NormalizedEvent], next_id: Any
    ) -> list[CorrelationLink]:
        """Same file hash seen on multiple hosts — malware propagation."""
        hash_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in events:
            if e.file and e.file.file_hashes:
                for algo, value in e.file.file_hashes.items():
                    if algo in ("SHA256", "MD5") and value:
                        hash_events[f"{algo}:{value}"].append(e)

        links: list[CorrelationLink] = []
        for hash_key, hash_evs in hash_events.items():
            if len(hash_evs) < 2:
                continue
            hosts = list({e.host for e in hash_evs if e.host})
            algo, value = hash_key.split(":", 1)
            links.append(
                CorrelationLink(
                    link_id=next_id(),
                    event_ids=[e.event_id for e in hash_evs[:20]],
                    reason=(
                        f"File with {algo} hash '{value[:16]}…' was observed on "
                        f"{len(hosts)} host(s): {', '.join(hosts[:3])}. "
                        "This indicates the same malware binary was deployed across multiple systems."
                    ),
                    link_type="shared_file_hash",
                    shared_attributes={"hash": hash_key, "hosts": hosts},
                    confidence=0.92,
                )
            )
        return links

    def _correlate_temporal_burst(
        self, events: list[NormalizedEvent], next_id: Any
    ) -> list[CorrelationLink]:
        """Events from the same host within a 60-second window — automated activity burst."""
        host_events: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in sorted(events, key=lambda x: x.timestamp):
            if e.host:
                host_events[e.host].append(e)

        links: list[CorrelationLink] = []
        for host, host_evs in host_events.items():
            if len(host_evs) < 4:
                continue
            # Sliding window: find bursts of ≥4 events within 60 seconds
            for i in range(len(host_evs) - 3):
                window = host_evs[i:i + 8]
                span = (window[-1].timestamp - window[0].timestamp).total_seconds()
                if span <= 60 and len(window) >= 4:
                    event_types = list({e.event_type for e in window})
                    links.append(
                        CorrelationLink(
                            link_id=next_id(),
                            event_ids=[e.event_id for e in window],
                            reason=(
                                f"{len(window)} events on '{host}' within {span:.0f} seconds "
                                f"({', '.join(event_types[:3])}). "
                                "Rapid sequential activity suggests automated or scripted execution."
                            ),
                            link_type="temporal_burst",
                            shared_attributes={
                                "host": host,
                                "window_seconds": span,
                                "event_types": event_types,
                            },
                            confidence=0.70,
                        )
                    )
                    break  # one burst per host is enough
        return links

    @staticmethod
    def _build_summary(links: list[CorrelationLink], events: list[NormalizedEvent]) -> str:
        if not links:
            return f"Analyzed {len(events)} events. No significant hidden correlations found."
        type_counts: dict[str, int] = defaultdict(int)
        for lnk in links:
            type_counts[lnk.link_type] += 1
        parts = [f"Found {len(links)} correlation link(s) across {len(events)} events:"]
        labels = {
            "user_across_hosts": "cross-host user activity",
            "process_chain": "process chain link(s)",
            "shared_destination": "shared C2/exfil destination(s)",
            "shared_file_hash": "shared malware hash(es)",
            "temporal_burst": "automated activity burst(s)",
        }
        for link_type, count in type_counts.items():
            parts.append(f"{count} {labels.get(link_type, link_type)}")
        return " | ".join(parts) + "."
