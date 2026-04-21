from __future__ import annotations

from backend.app.services.detection_service import DetectionService
from backend.app.services.normalization_service import NormalizationService


def _extract_text(value):
    if isinstance(value, list):
        return " ".join(_extract_text(item) for item in value)
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _field(obj, name: str):
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj.get(name)
    return None


def test_detection_service_builds_expected_alert_families():
    normalizer = NormalizationService()
    detector = DetectionService()

    records = [
        {
            "EventID": 1,
            "UtcTime": "2025-01-12T08:14:21Z",
            "Computer": "WKSTN-07",
            "User": "CORP\\jdoe",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ=",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "ParentProcessGuid": "{GUID-PARENT}",
            "ProcessGuid": "{GUID-1}",
            "ProcessId": 4321,
        },
        {
            "EventID": 1,
            "UtcTime": "2025-01-12T08:18:42Z",
            "Computer": "WKSTN-07",
            "User": "CORP\\jdoe",
            "Image": "C:\\Tools\\procdump64.exe",
            "CommandLine": "procdump64.exe -ma lsass.exe C:\\ProgramData\\lsass.dmp",
            "ParentImage": "C:\\ProgramData\\stage\\adsvc.exe",
            "ParentProcessGuid": "{GUID-1}",
            "ProcessGuid": "{GUID-2}",
            "ProcessId": 4672,
        },
        {
            "EventID": 1,
            "UtcTime": "2025-01-12T08:25:43Z",
            "Computer": "WKSTN-07",
            "User": "CORP\\jdoe",
            "Image": "C:\\Windows\\System32\\sc.exe",
            "CommandLine": "sc.exe \\\\APP-02 create TempUpdater binPath= C:\\Windows\\Temp\\updater.exe start= auto",
            "ParentImage": "C:\\ProgramData\\stage\\adsvc.exe",
            "ParentProcessGuid": "{GUID-1}",
            "ProcessGuid": "{GUID-3}",
            "ProcessId": 4892,
        },
    ]

    events = normalizer.normalize("sysmon", records)
    alerts = detector.build_alerts(events)

    serialized = " | ".join(
        [
            " ".join(
                filter(
                    None,
                    [
                        _extract_text(_field(alert, "name")),
                        _extract_text(_field(alert, "family")),
                        _extract_text(_field(alert, "phase")),
                        _extract_text(_field(alert, "description")),
                    ],
                )
            )
            for alert in alerts
        ]
    ).lower()

    assert "process" in serialized or "office" in serialized
    assert "credential" in serialized or "lsass" in serialized
    assert "lateral" in serialized or "service" in serialized


def test_detection_service_rule_engine_returns_evidence_for_matches():
    normalizer = NormalizationService()
    detector = DetectionService()
    events = normalizer.normalize(
        "sysmon",
        [
            {
                "EventID": 1,
                "UtcTime": "2025-01-12T08:14:21Z",
                "Computer": "WKSTN-07",
                "User": "CORP\\jdoe",
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc ZQBjAGgAbwAgAHQAZQBzAHQ=",
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "ProcessGuid": "{GUID-1}",
                "ProcessId": 4321,
            }
        ],
    )

    rule_hits = detector.run_rules(events)
    serialized = _extract_text(rule_hits).lower()

    assert rule_hits
    assert "powershell" in serialized or "office" in serialized or "process" in serialized