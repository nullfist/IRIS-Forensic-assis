"""Feature engineering notes shared by anomaly scoring implementations.

This module intentionally stays lightweight so it can be reused by the backend
service layer without introducing an additional runtime dependency boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

FEATURE_COLUMNS = [
    "hour_of_day",
    "event_category",
    "event_source",
    "severity_score",
    "process_depth",
    "dest_port",
    "bytes_out_log10",
    "bytes_in_log10",
    "is_external_ip",
    "is_privileged_user",
    "is_remote_auth",
    "command_entropy_bucket",
]

FEATURE_ASSUMPTIONS = {
    "hour_of_day": "UTC-normalized event hour to capture off-hours behavior.",
    "event_category": "Numerically encoded canonical event category.",
    "event_source": "Numerically encoded telemetry source such as sysmon, evtx, or pcap.",
    "severity_score": "Prior risk hint derived from event severity or parser confidence.",
    "process_depth": "Approximate parent-child chain depth when process ancestry is available.",
    "dest_port": "Network destination port or 0 for non-network events.",
    "bytes_out_log10": "Log-scaled egress volume to reduce skew from large transfers.",
    "bytes_in_log10": "Log-scaled ingress volume to capture unusual data movement.",
    "is_external_ip": "Binary feature indicating destination outside private address space.",
    "is_privileged_user": "Binary indicator for admin, service, or SYSTEM-like contexts.",
    "is_remote_auth": "Binary indicator for remote-interactive or network logon semantics.",
    "command_entropy_bucket": "Rough encoded-command signal based on token diversity or base64 usage.",
}


@dataclass(slots=True)
class FeatureVectorSpec:
    """Describes the vector generated from a normalized event."""

    columns: list[str]
    assumptions: dict[str, str]


def get_feature_spec() -> FeatureVectorSpec:
    """Return the canonical anomaly feature specification."""
    return FeatureVectorSpec(columns=list(FEATURE_COLUMNS), assumptions=dict(FEATURE_ASSUMPTIONS))


def summarize_feature_payload(feature_payload: dict[str, Any]) -> dict[str, Any]:
    """Return a compact analyst-facing summary for debug and explainability use."""
    return {
        "feature_count": len(feature_payload),
        "populated_features": sorted([name for name, value in feature_payload.items() if value not in (None, 0, "", False)]),
        "sparse": sum(1 for value in feature_payload.values() if value in (None, 0, "", False)) > len(feature_payload) // 2,
    }