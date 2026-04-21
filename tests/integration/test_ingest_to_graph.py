"""Integration tests for end-to-end ingestion to graph workflow."""

import json
from datetime import datetime, timezone

from backend.app.repository.memory_store import MemoryStore
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.normalization_service import NormalizationService
from backend.app.services.detection_service import DetectionService
from backend.app.services.graph_service import GraphService
from backend.app.services.timeline_service import TimelineService
from backend.app.schemas.ingestion import IngestRequest, IngestArtifact
from backend.app.models.enums import EventSource


class TestIngestToGraphIntegration:
    """End-to-end integration test simulating real attack scenario ingestion."""

    def setup_method(self):
        self.store = MemoryStore()
        self.normalization_service = NormalizationService()
        self.detection_service = DetectionService()
        self.graph_service = GraphService(store=self.store)
        self.timeline_service = TimelineService()
        self.ingestion_service = IngestionService(
            store=self.store,
            normalization_service=self.normalization_service,
            detection_service=self.detection_service,
            graph_service=self.graph_service,
        )

    def load_sample_records(self):
        """Load sample Sysmon records from the phishing-to-exfiltration scenario."""
        sample_records = [
            {
                "EventID": 1,
                "UtcTime": "2024-01-15T09:23:45.123Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0001-0001-0000-000000000001}",
                "ProcessId": 4532,
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "CommandLine": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" /n "C:\\Users\\jsmith\\Downloads\\Invoice_2024.docm"',
                "ParentProcessGuid": "{a1b2c3d4-0000-0001-0000-000000000000}",
                "ParentProcessId": 8924,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Hashes": "SHA256=ABC123",
            },
            {
                "EventID": 1,
                "UtcTime": "2024-01-15T09:23:47.456Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0002-0001-0000-000000000002}",
                "ProcessId": 7821,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAA=",
                "ParentProcessGuid": "{a1b2c3d4-0001-0001-0000-000000000001}",
                "ParentProcessId": 4532,
                "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "Hashes": "SHA256=DEF789",
            },
            {
                "EventID": 3,
                "UtcTime": "2024-01-15T09:23:48.789Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0002-0001-0000-000000000002}",
                "ProcessId": 7821,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "Protocol": "tcp",
                "SourceIp": "192.168.1.105",
                "SourcePort": "49152",
                "DestinationIp": "112.254.134.100",
                "DestinationPort": "80",
                "DestinationHostname": "malware-c2.evil.com",
            },
            {
                "EventID": 11,
                "UtcTime": "2024-01-15T09:23:49.012Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0002-0001-0000-000000000002}",
                "ProcessId": 7821,
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "TargetFilename": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe",
                "Hashes": "SHA256=MALWARE123",
            },
            {
                "EventID": 1,
                "UtcTime": "2024-01-15T09:23:50.345Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0003-0001-0000-000000000003}",
                "ProcessId": 9234,
                "Image": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe",
                "CommandLine": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe --beacon",
                "ParentProcessGuid": "{a1b2c3d4-0002-0001-0000-000000000002}",
                "ParentProcessId": 7821,
                "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "Hashes": "SHA256=MALWARE456",
            },
            {
                "EventID": 3,
                "UtcTime": "2024-01-15T09:28:32.456Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0003-0001-0000-000000000003}",
                "ProcessId": 9234,
                "Image": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe",
                "Protocol": "tcp",
                "SourceIp": "192.168.1.105",
                "SourcePort": "49155",
                "DestinationIp": "192.168.1.50",
                "DestinationPort": "445",
                "DestinationHostname": "FILESERVER-01",
            },
            {
                "EventID": 1,
                "UtcTime": "2024-01-15T09:25:15.567Z",
                "Computer": "WORKSTATION-01",
                "User": "CORP\\jsmith",
                "ProcessGuid": "{a1b2c3d4-0005-0001-0000-000000000005}",
                "ProcessId": 8432,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 648 lsass C:\\Users\\jsmith\\AppData\\Local\\Temp\\lsass.dmp full",
                "ParentProcessGuid": "{a1b2c3d4-0004-0001-0000-000000000004}",
                "ParentProcessId": 1245,
                "ParentImage": "C:\\Users\\jsmith\\AppData\\Local\\Temp\\stage.exe",
                "Hashes": "SHA256=SYSTEM789",
            },
        ]
        return sample_records

    def test_full_ingestion_workflow(self):
        """Test complete ingestion workflow from raw records to graph."""
        # Step 1: Submit ingestion job
        request = IngestRequest(
            investigation_id="integration-test-001",
            enrich_graph=True,
            artifacts=[
                IngestArtifact(
                    source=EventSource.SYSMON,
                    artifact_name="test_sysmon.jsonl",
                    records=self.load_sample_records(),
                )
            ],
        )

        response = self.ingestion_service.submit_ingestion(request)

        # Step 2: Verify job completed
        assert response.job_id is not None
        assert response.status == "completed"

        # Step 3: Verify events were stored
        job_status = self.ingestion_service.get_job_status(response.job_id)
        assert job_status.normalized_events > 0
        assert job_status.generated_alerts > 0

        # Step 4: Verify events can be retrieved
        events = self.store.get_events("integration-test-001")
        assert len(events) > 0

        # Step 5: Verify alerts were generated
        alerts = self.store.get_alerts("integration-test-001")
        assert len(alerts) > 0

        # Step 6: Verify graph was built
        graph = self.graph_service.get_graph("integration-test-001")
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0

        # Step 7: Verify timeline was created
        timeline = self.timeline_service.build_timeline("integration-test-001", events)
        assert timeline.total > 0
        assert len(timeline.phases) > 0

    def test_attack_chain_detection(self):
        """Test that the full attack chain is detected."""
        request = IngestRequest(
            investigation_id="attack-chain-test",
            enrich_graph=True,
            artifacts=[
                IngestArtifact(
                    source=EventSource.SYSMON,
                    artifact_name="test_sysmon.jsonl",
                    records=self.load_sample_records(),
                )
            ],
        )

        self.ingestion_service.submit_ingestion(request)

        alerts = self.store.get_alerts("attack-chain-test")

        # Should have detected various attack phases
        alert_titles = [a.title.lower() for a in alerts]
        all_titles = " ".join(alert_titles)

        # Check for key detection indicators
        assert any(term in all_titles for term in ["office", "powershell", "chain"]) or \
               any(term in all_titles for term in ["credential", "dumping", "lsass"]) or \
               any(term in all_titles for term in ["lateral", "movement"])

    def test_entity_extraction_across_events(self):
        """Test that entities are properly extracted and linked across events."""
        request = IngestRequest(
            investigation_id="entity-test",
            enrich_graph=True,
            artifacts=[
                IngestArtifact(
                    source=EventSource.SYSMON,
                    artifact_name="test_sysmon.jsonl",
                    records=self.load_sample_records(),
                )
            ],
        )

        self.ingestion_service.submit_ingestion(request)

        events = self.store.get_events("entity-test")

        # Collect all entity IDs
        all_entities = set()
        for event in events:
            for entity in event.entities:
                all_entities.add(entity.entity_id)

        # Should have hosts, users, processes, and IPs
        entity_types = {e.split(":")[0] for e in all_entities}
        assert "host" in entity_types
        assert "user" in entity_types
        assert "process" in entity_types
        assert "ip" in entity_types

    def test_timeline_phase_ordering(self):
        """Test that timeline events are properly ordered by phase."""
        request = IngestRequest(
            investigation_id="timeline-test",
            enrich_graph=True,
            artifacts=[
                IngestArtifact(
                    source=EventSource.SYSMON,
                    artifact_name="test_sysmon.jsonl",
                    records=self.load_sample_records(),
                )
            ],
        )

        self.ingestion_service.submit_ingestion(request)

        events = self.store.get_events("timeline-test")
        timeline = self.timeline_service.build_timeline("timeline-test", events)

        # Verify phases are in chronological order
        for i in range(len(timeline.phases) - 1):
            current_phase = timeline.phases[i]
            next_phase = timeline.phases[i + 1]
            assert current_phase.started_at <= next_phase.started_at

    def test_graph_connectivity(self):
        """Test that graph nodes are properly connected."""
        request = IngestRequest(
            investigation_id="graph-test",
            enrich_graph=True,
            artifacts=[
                IngestArtifact(
                    source=EventSource.SYSMON,
                    artifact_name="test_sysmon.jsonl",
                    records=self.load_sample_records(),
                )
            ],
        )

        self.ingestion_service.submit_ingestion(request)

        graph = self.graph_service.get_graph("graph-test")

        # Every edge should connect existing nodes
        node_ids = {node.id for node in graph.nodes}
        for edge in graph.edges:
            assert edge.source in node_ids
            assert edge.target in node_ids