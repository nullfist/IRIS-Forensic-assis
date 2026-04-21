from __future__ import annotations

from collections import defaultdict

from backend.app.models.enums import AttackPhase
from backend.app.schemas.events import NormalizedEvent


class CorrelationService:
    """Correlate related events into higher-level incident patterns."""

    def process_chains(self, events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
        by_parent: dict[str, list[NormalizedEvent]] = defaultdict(list)
        roots: list[NormalizedEvent] = []

        for event in events:
            if event.process and event.process.parent_process_guid:
                by_parent[event.process.parent_process_guid].append(event)
            else:
                roots.append(event)

        chains: list[list[NormalizedEvent]] = []
        for root in roots:
            if not root.process:
                continue
            chain = [root]
            pending = [root.process.process_guid] if root.process.process_guid else []
            while pending:
                guid = pending.pop()
                for child in by_parent.get(guid, []):
                    chain.append(child)
                    if child.process and child.process.process_guid:
                        pending.append(child.process.process_guid)
            if len(chain) > 1:
                chains.append(sorted(chain, key=lambda item: item.timestamp))
        return chains

    def credential_dumping_indicators(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        suspicious_terms = (
            "lsass",
            "sekurlsa",
            "minidump",
            "comsvcs.dll",
            "procdump",
            "rundll32",
        )
        indicators: list[NormalizedEvent] = []
        for event in events:
            haystack = " ".join(
                filter(
                    None,
                    [
                        event.title,
                        event.description,
                        event.process.image if event.process else None,
                        event.process.command_line if event.process else None,
                        str(event.raw_data),
                    ],
                )
            ).lower()
            if any(term in haystack for term in suspicious_terms):
                indicators.append(event)
        return indicators

    def lateral_movement_groups(self, events: list[NormalizedEvent]) -> dict[str, list[NormalizedEvent]]:
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            if event.attack_phase == AttackPhase.LATERAL_MOVEMENT:
                key = event.host or "unknown-host"
                groups[key].append(event)
                continue
            network = event.network
            if network and network.dst_port in {445, 135, 139, 5985, 5986}:
                groups[event.host or "unknown-host"].append(event)
        return dict(groups)

    def correlate_incident_clusters(self, events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
        clusters: dict[tuple[str | None, str | None], list[NormalizedEvent]] = defaultdict(list)
        for event in events:
            clusters[(event.host, event.user)].append(event)

        correlated = [sorted(cluster, key=lambda item: item.timestamp) for cluster in clusters.values() if cluster]
        return sorted(correlated, key=len, reverse=True)