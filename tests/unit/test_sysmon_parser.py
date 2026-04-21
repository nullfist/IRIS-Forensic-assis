"""Unit tests for Sysmon parser."""

from datetime import datetime, timezone

from backend.app.parsers.sysmon_parser import SysmonParser
from backend.app.models.enums import EventCategory, EventSource, AttackPhase, SeverityLevel


class TestSysmonParser:
    """Test suite for SysmonParser normalization logic."""

    def setup_method(self):
        self.parser = SysmonParser()

    def test_can_parse_sysmon_source(self):
        assert self.parser.can_parse("sysmon") is True
        assert self.parser.can_parse("SYSMON") is True
        assert self.parser.can_parse("evtx") is False

    def test_can_parse_by_event_id(self):
        record = {"EventID": "1"}
        assert self.parser.can_parse("unknown", record) is True

    def test_can_parse_by_channel(self):
        record = {"Channel": "Microsoft-Windows-Sysmon/Operational"}
        assert self.parser.can_parse("unknown", record) is True

    def test_parse_process_create_event(self):
        record = {
            "EventID": 1,
            "UtcTime": "2024-01-15T09:23:45.123Z",
            "Computer": "WORKSTATION-01",
            "User": "CORP\\jsmith",
            "ProcessGuid": "{a1b2c3d4-0001-0001-0000-000000000001}",
            "ProcessId": 4532,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA=",
            "ParentProcessGuid": "{a1b2c3d4-0000-0001-0000-000000000000}",
            "ParentProcessId": 8924,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "Hashes": "SHA256=ABC123,MD5=DEF456",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        event = events[0]

        assert event.source == EventSource.SYSMON
        assert event.category == EventCategory.PROCESS
        assert event.event_type == "process_create"
        assert event.host == "WORKSTATION-01"
        assert event.user == "CORP\\jsmith"
        assert event.process.process_guid == "{a1b2c3d4-0001-0001-0000-000000000001}"
        assert event.process.pid == 4532
        assert event.process.image == "C:\\Windows\\System32\\powershell.exe"
        assert event.process.command_line == "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA="
        assert event.process.parent_process_guid == "{a1b2c3d4-0000-0001-0000-000000000000}"
        assert event.process.parent_image == "C:\\Windows\\explorer.exe"
        assert "SHA256" in event.process.hashes
        assert event.process.hashes["SHA256"] == "ABC123"

    def test_parse_network_connect_event(self):
        record = {
            "EventID": 3,
            "UtcTime": "2024-01-15T09:23:48.789Z",
            "Computer": "WORKSTATION-01",
            "User": "CORP\\jsmith",
            "ProcessGuid": "{a1b2c3d4-0002-0001-0000-000000000002}",
            "ProcessId": 7821,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "Protocol": "tcp",
            "SourceIp": "192.168.1.105",
            "SourcePort": "49152",
            "DestinationIp": "112.254.134.100",
            "DestinationPort": "443",
            "DestinationHostname": "malware-c2.evil.com",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        event = events[0]

        assert event.source == EventSource.SYSMON
        assert event.category == EventCategory.NETWORK
        assert event.event_type == "network_connect"
        assert event.network.src_ip == "192.168.1.105"
        assert event.network.src_port == 49152
        assert event.network.dst_ip == "112.254.134.100"
        assert event.network.dst_port == 443
        assert event.network.protocol == "tcp"
        assert event.network.domain == "malware-c2.evil.com"

    def test_network_event_lateral_movement_phase(self):
        """Test that connections to SMB/WinRM ports are classified as lateral movement."""
        record = {
            "EventID": 3,
            "UtcTime": "2024-01-15T09:28:32.456Z",
            "Computer": "WORKSTATION-01",
            "ProcessGuid": "{guid}",
            "ProcessId": 1234,
            "Image": "test.exe",
            "Protocol": "tcp",
            "SourceIp": "192.168.1.105",
            "SourcePort": "49155",
            "DestinationIp": "192.168.1.50",
            "DestinationPort": "445",
            "DestinationHostname": "FILESERVER-01",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        assert events[0].attack_phase == AttackPhase.LATERAL_MOVEMENT

    def test_network_event_exfiltration_phase(self):
        """Test that connections to HTTP/HTTPS ports are classified as exfiltration."""
        record = {
            "EventID": 3,
            "UtcTime": "2024-01-15T09:35:12.678Z",
            "Computer": "FILESERVER-01",
            "ProcessGuid": "{guid}",
            "ProcessId": 7823,
            "Image": "powershell.exe",
            "Protocol": "tcp",
            "SourceIp": "192.168.1.50",
            "SourcePort": "49200",
            "DestinationIp": "203.0.113.50",
            "DestinationPort": "443",
            "DestinationHostname": "exfil-server.attacker.com",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        assert events[0].attack_phase == AttackPhase.EXFILTRATION

    def test_parse_file_create_event(self):
        record = {
            "EventID": 11,
            "UtcTime": "2024-01-15T09:23:49.012Z",
            "Computer": "WORKSTATION-01",
            "User": "CORP\\jsmith",
            "ProcessGuid": "{guid}",
            "ProcessId": 7821,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "TargetFilename": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe",
            "Hashes": "SHA256=MALWARE123...",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        event = events[0]

        assert event.category == EventCategory.FILE
        assert event.event_type == "file_create"
        assert event.file.path == "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe"
        assert event.file.extension == "exe"

    def test_parse_registry_set_event(self):
        record = {
            "EventID": 13,
            "UtcTime": "2024-01-15T09:30:00.000Z",
            "Computer": "WORKSTATION-01",
            "ProcessGuid": "{guid}",
            "ProcessId": 1234,
            "Image": "malware.exe",
            "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "Details": "C:\\Users\\Public\\malware.exe",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        event = events[0]

        assert event.category == EventCategory.REGISTRY
        assert event.event_type == "registry_set"
        assert event.registry.key_path == "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"
        assert event.attack_phase == AttackPhase.PERSISTENCE

    def test_detects_suspicious_powershell_command_line(self):
        """Test that PowerShell with sekurlsa is flagged as credential access."""
        record = {
            "EventID": 1,
            "UtcTime": "2024-01-15T09:25:15.567Z",
            "Computer": "WORKSTATION-01",
            "ProcessGuid": "{guid}",
            "ProcessId": 8432,
            "Image": "powershell.exe",
            "CommandLine": "powershell.exe -c Invoke-Mimikatz sekurlsa::logonpasswords",
            "ParentImage": "cmd.exe",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 1
        assert events[0].severity == SeverityLevel.HIGH
        assert events[0].attack_phase == AttackPhase.CREDENTIAL_ACCESS

    def test_entity_extraction(self):
        """Test that entities are properly extracted from events."""
        record = {
            "EventID": 1,
            "UtcTime": "2024-01-15T09:23:45.123Z",
            "Computer": "WORKSTATION-01",
            "User": "CORP\\jsmith",
            "ProcessGuid": "{guid}",
            "ProcessId": 4532,
            "Image": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe",
            "ParentImage": "explorer.exe",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        event = events[0]
        entity_types = [e.entity_type for e in event.entities]

        assert "host" in entity_types
        assert "user" in entity_types
        assert "process" in entity_types

    def test_unknown_event_id_returns_none(self):
        """Test that unknown EventIDs are skipped."""
        record = {
            "EventID": 999,
            "UtcTime": "2024-01-15T09:00:00.000Z",
            "Computer": "WORKSTATION-01",
        }

        events = self.parser.parse_records(
            investigation_id="test-inv-001",
            records=[record],
            artifact_name="test_sysmon.jsonl",
        )

        assert len(events) == 0

    def test_timestamp_parsing(self):
        """Test various timestamp formats are parsed correctly."""
        test_cases = [
            "2024-01-15T09:23:45.123Z",
            "2024-01-15 09:23:45.123",
            "01/15/2024 09:23:45",
        ]

        for ts in test_cases:
            result = self.parser._parse_timestamp(ts)
            assert isinstance(result, datetime)
            assert result.tzinfo is not None

    def test_hash_parsing_dict_format(self):
        """Test parsing hashes in dictionary format."""
        hashes = {"SHA256": "abc123", "MD5": "def456"}
        result = self.parser._parse_hashes(hashes)
        assert result == {"SHA256": "abc123", "MD5": "def456"}

    def test_hash_parsing_string_format(self):
        """Test parsing hashes in string format."""
        hashes = "SHA256=abc123,MD5=def456"
        result = self.parser._parse_hashes(hashes)
        assert result == {"SHA256": "abc123", "MD5": "def456"}

    def test_hash_parsing_empty(self):
        """Test parsing empty hash values."""
        assert self.parser._parse_hashes(None) == {}
        assert self.parser._parse_hashes("") == {}

    def test_extension_extraction(self):
        """Test file extension extraction."""
        assert self.parser._extract_extension("C:\\Users\\test\\malware.exe") == "exe"
        assert self.parser._extract_extension("C:\\Users\\test\\file.docm") == "docm"
        assert self.parser._extract_extension("C:\\Users\\test\\noextension") is None
        assert self.parser._extract_extension(None) is None