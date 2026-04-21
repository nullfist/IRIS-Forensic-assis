from __future__ import annotations

from backend.app.schemas.alerts import Alert, ExplanationResponse, ReasoningStep
from backend.app.schemas.events import NormalizedEvent


class ReasoningEngine:
    """Translate detections into analyst-friendly reasoning and follow-up guidance."""

    def explain_alert(self, alert: Alert, supporting_events: list[NormalizedEvent]) -> ExplanationResponse:
        reasoning_steps = self._build_reasoning_steps(alert, supporting_events)
        confidence_summary = self._build_confidence_summary(alert, supporting_events)
        # Serialize steps to strings so the frontend can render them directly
        reasoning_chain_strings = [
            f"{step.title}: {step.detail}" for step in reasoning_steps
        ]
        return ExplanationResponse(
            alert_id=alert.alert_id,
            summary=alert.summary,
            reasoning_chain=reasoning_steps,
            attack_tactics=alert.tactics or [alert.phase.replace("_", " ").title()],
            confidence_summary=confidence_summary,
            confidence_explanation=confidence_summary,
            next_steps=self._build_next_steps(alert),
        )

    def _build_reasoning_steps(
        self,
        alert: Alert,
        supporting_events: list[NormalizedEvent],
    ) -> list[ReasoningStep]:
        steps: list[ReasoningStep] = [
            ReasoningStep(
                title="Detection family matched",
                detail=f"The alert was raised under the {alert.family.replace('_', ' ')} family based on correlated telemetry.",
                supporting_event_ids=alert.source_event_ids,
            )
        ]

        for event in supporting_events[:4]:
            detail_bits = [event.title]
            if event.process and event.process.command_line:
                detail_bits.append(f"Command line: {event.process.command_line}")
            if event.network and event.network.dst_ip:
                detail_bits.append(f"Destination: {event.network.dst_ip}:{event.network.dst_port}")
            steps.append(
                ReasoningStep(
                    title=event.event_type.replace("_", " ").title(),
                    detail=" | ".join(detail_bits),
                    supporting_event_ids=[event.event_id],
                )
            )

        steps.append(
            ReasoningStep(
                title="Alert prioritization",
                detail=f"Severity {alert.severity} with risk score {alert.risk_score:.1f} reflects attack phase impact and evidence confidence.",
                supporting_event_ids=alert.source_event_ids[:5],
            )
        )
        return steps

    @staticmethod
    def _build_confidence_summary(alert: Alert, supporting_events: list[NormalizedEvent]) -> str:
        evidence_count = len(alert.evidence)
        source_count = len(supporting_events)
        return (
            f"Confidence {alert.confidence:.2f} is supported by {evidence_count} evidence items "
            f"across {source_count} normalized events, weighted by phase {alert.phase.replace('_', ' ')}."
        )

    @staticmethod
    def _build_next_steps(alert: Alert) -> list[str]:
        family = alert.family.lower()
        if "credential" in family:
            return [
                "Inspect LSASS access telemetry and memory dump artifacts on the affected host.",
                "Review the initiating account for privilege escalation or token theft.",
                "Reset credentials and search for reused authentication across peer systems.",
            ]
        if "lateral" in family:
            return [
                "Pivot into remote service creation, SMB admin share usage, and WinRM session records.",
                "Validate whether the target hosts show corresponding logon and process creation events.",
                "Scope for additional east-west movement using the same user or source host.",
            ]
        return [
            "Validate the full parent-child process chain and identify the originating user action.",
            "Review neighboring events on the timeline for persistence or outbound connections.",
            "Collect host artifacts and confirm whether the activity aligns with expected administration.",
        ]