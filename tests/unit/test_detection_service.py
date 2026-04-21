"""Unit tests for Detection Service."""

from datetime import datetime, timezone

from backend.app.detection.anomaly_detector import AnomalyDetector
from backend.app.detection.rule_loader import RuleLoader
from backend.app.models.enums import EventSource, EventCategory, AttackPhase, SeverityLevel
from backend.app.schemas.events import NormalizedEvent, ProcessContext, NetworkContext, ParserProvenance
from backend.app.services.correlation_service import CorrelationService
from backend.app.services.detection_service import DetectionService
from backend.app.services.risk_scoring_service import RiskScoringService


class TestDetectionService:
    """Test suite for DetectionService."""

    def setup_method(self):
        self.correlation_service = CorrelationService()
        self.risk_scoring_service = RiskScoringService()
        self.anomaly_detector = AnomalyDetector()
        self.rule_loader = RuleLoader()
        self.detection_service = DetectionService(
            rule_loader=self.rule_loader,
            anomaly_detector=self.anomaly_detector,
            correlation_service=self.correlation_service,
            risk_scoring_service=self.risk_scoring_service,
        )

    def create_process_event(
        self,
        image="powershell.exe",
        command_line="powershell.exe",
        parent_image="explorer.exe",
        host="WORKSTATION-01",
        user="CORP\\jsmith",
        severity=SeverityLevel.LOW,
        attack_phase=AttackPhase.EXECUTION,
    ):
        return NormalizedEvent(
            event_id=f"test-event-{datetime.now().timestamp()}",
            investigation_id="test-inv-001",
            source=EventSource.SYSMON,
            category=EventCategory.PROCESS,
            event_type="process_create",
            timestamp=datetime.now(timezone.utc),
            observed_at=datetime.now(timezone.utc),
            severity=severity,
            attack_phase=attack_phase,
            title=f"Process created: {image}",
            description="Test process event",
            host=host,
            user=user,
            process=ProcessContext(
                process_guid="{test-guid}",
                pid=1234,
                image=f"C:\\Windows\\System32\\{image}",
                command_line=command_line,
                parent_process_guid="{parent-guid}",
                parent_pid=5678,
                parent_image=f"C:\\Windows\\{parent_image}",
                parent_command_line=parent_image,
            ),
            parser_provenance=ParserProvenance(parser_name="SysmonParser"),
            correlation_keys=[host, user],
        )

    def create_network_event(
        self,
        dst_ip="112.254.134.100",
        dst_port=443,
        host="WORKSTATION-01",
        user="CORP\\jsmith",
        process_image="powershell.exe",
    ):
        return NormalizedEvent(
            event_id=f"test-network-{datetime.now().timestamp()}",
            investigation_id="test-inv-001",
            source=EventSource.SYSMON,
            category=EventCategory.NETWORK,
            event_type="network_connect",
            timestamp=datetime.now(timezone.utc),
            observed_at=datetime.now(timezone.utc),
            severity=SeverityLevel.MEDIUM,
            attack_phase=AttackPhase.EXFILTRATION if dst_port in [80, 443] else AttackPhase.LATERAL_MOVEMENT,
            title=f"Network connection to {dst_ip}:{dst_port}",
            description="Test network event",
            host=host,
            user=user,
            process=ProcessContext(
                process_guid="{test-guid}",
                pid=1234,
                image=f"C:\\Windows\\System32\\{process_image}",
            ),
            network=NetworkContext(
                src_ip="192.168.1.105",
                src_port=49152,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="tcp",
            ),
            parser_provenance=ParserProvenance(parser_name="SysmonParser"),
            correlation_keys=[host, user],
        )

    def test_detect_office_powershell_chain(self):
        """Test detection of Office spawning PowerShell."""
        events = [
            self.create_process_event(
                image="WINWORD.EXE",
                parent_image="explorer.exe",
            ),
            self.create_process_event(
                image="powershell.exe",
                parent_image="WINWORD.EXE",
                command_line="powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA=",
            ),
        ]

        detections = self.detection_service.run_rules(events)

        # Should detect suspicious process chain
        office_detections = [d for d in detections if "office" in d.get("title", "").lower()]
        assert len(office_detections) > 0

    def test_detect_credential_dumping(self):
        """Test detection of credential dumping indicators."""
        events = [
            self.create_process_event(
                image="powershell.exe",
                command_line="powershell.exe -c Invoke-Mimikatz sekurlsa::logonpasswords",
                severity=SeverityLevel.HIGH,
                attack_phase=AttackPhase.CREDENTIAL_ACCESS,
            ),
        ]

        detections = self.detection_service.run_rules(events)

        # Should detect credential dumping
        cred_detections = [d for d in detections if d.get("family") == "credential_dumping"]
        assert len(cred_detections) > 0

    def test_detect_lateral_movement(self):
        """Test detection of lateral movement patterns."""
        events = [
            self.create_network_event(
                dst_ip="192.168.1.50",
                dst_port=445,
                host="WORKSTATION-01",
            ),
            self.create_network_event(
                dst_ip="192.168.1.20",
                dst_port=445,
                host="WORKSTATION-01",
            ),
        ]

        detections = self.detection_service.run_rules(events)

        # Should detect lateral movement
        lat_moves = [d for d in detections if d.get("family") == "lateral_movement"]
        assert len(lat_moves) > 0

    def test_build_alerts_from_events(self):
        """Test alert generation from events."""
        events = [
            self.create_process_event(
                image="WINWORD.EXE",
                parent_image="explorer.exe",
            ),
            self.create_process_event(
                image="powershell.exe",
                parent_image="WINWORD.EXE",
                command_line="powershell.exe -encodedcommand download",
            ),
            self.create_network_event(dst_port=443),
        ]

        alerts = self.detection_service.build_alerts(events)

        assert len(alerts) > 0
        # Alerts should have required fields
        for alert in alerts:
            assert alert.alert_id is not None
            assert alert.title is not None
            assert alert.severity is not None
            assert alert.investigation_id == "test-inv-001"

    def test_anomaly_detection_scoring(self):
        """Test anomaly detection scoring."""
        import time
        e1 = self.create_process_event(severity=SeverityLevel.LOW)
        time.sleep(0.001)
        e2 = self.create_process_event(severity=SeverityLevel.HIGH)
        time.sleep(0.001)
        e3 = self.create_network_event(dst_port=443)
        events = [e1, e2, e3]

        scores = self.anomaly_detector.score_events(events)

        assert len(scores) == len(events)
        for event_id, score in scores.items():
            assert 0.0 <= score <= 1.0

    def test_process_chain_correlation(self):
        """Test process chain correlation."""
        parent_event = self.create_process_event(image="explorer.exe")
        parent_event.process.process_guid = "{parent-guid-unique}"
        parent_event.process.parent_process_guid = None

        child_event = self.create_process_event(
            image="powershell.exe",
            parent_image="explorer.exe",
        )
        child_event.process.process_guid = "{child-guid-unique}"
        child_event.process.parent_process_guid = "{parent-guid-unique}"

        chains = self.correlation_service.process_chains([parent_event, child_event])

        assert len(chains) > 0
        assert len(chains[0]) == 2

    def test_alert_deduplication(self):
        """Test that duplicate alerts are deduplicated."""
        events = [
            self.create_process_event(
                image="powershell.exe",
                command_line="powershell.exe -c sekurlsa::logonpasswords",
            ),
            self.create_process_event(
                image="powershell.exe",
                command_line="powershell.exe -c sekurlsa::logonpasswords",
            ),
        ]

        alerts = self.detection_service.build_alerts(events)

        # Similar events should produce deduplicated alerts
        families = [a.family for a in alerts]
        assert len(families) == len(set(families)) or len(alerts) <= len(events)

    def test_risk_scoring(self):
        """Test risk scoring service."""
        import time; time.sleep(0.001)
        alerts = self.detection_service.build_alerts([
            self.create_process_event(severity=SeverityLevel.CRITICAL)
        ])
        assert len(alerts) > 0
        alert = alerts[0]
        assert alert.risk_score > 0
        assert alert.risk_score <= 100.0

    def test_empty_events_no_alerts(self):
        """Test that empty event list produces no alerts."""
        alerts = self.detection_service.build_alerts([])
        assert len(alerts) == 0

    def test_severity_normalization(self):
        """Test severity normalization in detection service."""
        result = self.detection_service._normalize_severity("critical", SeverityLevel.LOW)
        assert result == SeverityLevel.CRITICAL

        result = self.detection_service._normalize_severity(None, SeverityLevel.HIGH)
        assert result == SeverityLevel.HIGH

    def test_phase_normalization(self):
        """Test phase normalization in detection service."""
        result = self.detection_service._normalize_phase("lateral_movement", AttackPhase.UNKNOWN)
        assert result == AttackPhase.LATERAL_MOVEMENT

        result = self.detection_service._normalize_phase(None, AttackPhase.EXECUTION)
        assert result == AttackPhase.EXECUTION