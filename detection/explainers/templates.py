"""Reusable explanation templates for IRIS detection families and attack phases."""

from __future__ import annotations

from typing import Any

EXPLANATION_TEMPLATES: dict[str, dict[str, dict[str, Any]]] = {
    "suspicious_process_chain": {
        "initial_access": {
            "title": "Suspicious user-driven execution chain",
            "reasoning": [
                "A user-facing application launched a script or living-off-the-land binary.",
                "The parent-child relationship is uncommon for normal productivity workflows.",
                "Command-line characteristics suggest execution of staged or downloaded content.",
            ],
            "next_steps": [
                "Review the originating document, attachment, or download source.",
                "Capture the spawned process tree and any dropped files.",
                "Determine whether outbound connections followed the execution event.",
            ],
        },
        "execution": {
            "title": "Potential malicious execution chain",
            "reasoning": [
                "The observed process sequence indicates proxy execution rather than direct user action.",
                "Tooling selection aligns with adversaries attempting to evade allowlists or detections.",
            ],
            "next_steps": [
                "Validate signer, prevalence, and file location of each binary in the chain.",
                "Inspect script content, encoded arguments, and child process fan-out.",
            ],
        },
        "command_and_control": {
            "title": "Execution chain followed by external communications",
            "reasoning": [
                "A script-capable process exhibited suspicious command-line syntax and then communicated externally.",
                "This pattern is consistent with download cradle, stager, or beacon establishment behavior.",
            ],
            "next_steps": [
                "Enumerate network destinations and any returned payloads.",
                "Hunt for the same infrastructure across other hosts and time ranges.",
            ],
        },
    },
    "credential_dumping": {
        "credential_access": {
            "title": "Credential dumping indicators detected",
            "reasoning": [
                "The process name or command line references known LSASS or secret extraction behavior.",
                "Activity targets memory, registry hives, or credential material that normally requires elevated access.",
                "Follow-on remote authentication or privilege escalation may indicate successful credential theft.",
            ],
            "next_steps": [
                "Isolate the host if credential material may have been exposed.",
                "Reset impacted credentials and review privileged account use.",
                "Acquire memory, registry, and process execution artifacts for confirmation.",
            ],
        }
    },
    "secret_store_access": {
        "credential_access": {
            "title": "Sensitive credential store access observed",
            "reasoning": [
                "Files or commands associated with Windows or browser credential stores were accessed.",
                "The access pattern is unusual for ordinary end-user behavior and may indicate collection of secrets.",
            ],
            "next_steps": [
                "Identify which credentials may have been stored in the accessed path.",
                "Review subsequent authentication events for the same user or host.",
            ],
        }
    },
    "lateral_movement": {
        "lateral_movement": {
            "title": "Probable lateral movement activity",
            "reasoning": [
                "The event sequence indicates remote administration channels being used to execute commands or install services.",
                "Authentication, admin share usage, or WinRM/SMB communications support a cross-host pivot.",
            ],
            "next_steps": [
                "Confirm whether the user or host normally administers the remote asset.",
                "Inspect the destination host for service creation, task registration, or staged binaries.",
                "Scope additional targets contacted with the same credentials or tooling.",
            ],
        }
    },
}


def get_template(detection_family: str, phase: str) -> dict[str, Any]:
    """Return the closest explanation template for a detection family and phase."""
    family_templates = EXPLANATION_TEMPLATES.get(detection_family, {})
    if phase in family_templates:
        return family_templates[phase]
    if family_templates:
        return next(iter(family_templates.values()))
    return {
        "title": "Analyst review required",
        "reasoning": [
            "The alert matched one or more suspicious behaviors.",
            "Additional context is needed to determine scope and impact.",
        ],
        "next_steps": [
            "Review supporting events and enrich with host, user, and network context.",
            "Assess containment needs based on affected systems and accounts.",
        ],
    }