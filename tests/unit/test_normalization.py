from __future__ import annotations

from backend.app.services.normalization_service import NormalizationService


def _get_attr_or_key(obj, name: str):
    if hasattr(obj, name):
        return getattr(obj, name)
    if isinstance(obj, dict):
        return obj[name]
    raise AttributeError(name)


def test_normalization_service_parses_sysmon_process_and_network_records():
    service = NormalizationService()
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
            "EventID": 3,
            "UtcTime": "2025-01-12T08:14:27Z",
            "Computer": "WKSTN-07",
            "User": "CORP\\jdoe",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ProcessGuid": "{GUID-1}",
            "ProcessId": 4321,
            "Protocol": "tcp",
            "SourceIp": "10.10.20.57",
            "SourcePort": 49713,
            "DestinationIp": "185.199.110.153",
            "DestinationPort": 443,
            "DestinationHostname": "cdn.update-support.com",
            "Initiated": "true",
        },
    ]

    events = service.normalize("sysmon", records)

    assert len(events) == 2
    first = events[0]
    second = events[1]

    assert _get_attr_or_key(first, "source").value if hasattr(_get_attr_or_key(first, "source"), "value") else _get_attr_or_key(first, "source")
    assert _get_attr_or_key(first, "category").value if hasattr(_get_attr_or_key(first, "category"), "value") else _get_attr_or_key(first, "category")
    assert "WKSTN-07" in str(_get_attr_or_key(first, "host"))
    assert "powershell" in str(_get_attr_or_key(_get_attr_or_key(first, "process"), "image")).lower()
    assert "winword" in str(_get_attr_or_key(_get_attr_or_key(first, "process"), "parent_image")).lower()

    network = _get_attr_or_key(second, "network")
    assert str(_get_attr_or_key(network, "dst_ip")) == "185.199.110.153"
    assert int(_get_attr_or_key(network, "dst_port")) == 443


def test_normalization_service_parses_evtx_and_pcap_records():
    service = NormalizationService()

    evtx_events = service.normalize(
        "evtx",
        [
            {
                "EventID": 4624,
                "TimeCreated": "2025-01-12T08:24:58Z",
                "Computer": "APP-02.corp.local",
                "Channel": "Security",
                "TargetUserName": "jdoe",
                "TargetDomainName": "CORP",
                "LogonType": 3,
                "IpAddress": "10.10.20.57",
            }
        ],
    )
    pcap_events = service.normalize(
        "pcap",
        [
            {
                "timestamp": "2025-01-12T08:33:09Z",
                "src_ip": "10.10.20.57",
                "src_port": 49980,
                "dst_ip": "45.77.22.91",
                "dst_port": 443,
                "protocol": "tcp",
                "bytes_out": 8245731,
                "bytes_in": 382921,
                "domain": "storage.sync-preview.net",
            }
        ],
    )

    assert len(evtx_events) == 1
    assert len(pcap_events) == 1

    auth_event = evtx_events[0]
    flow_event = pcap_events[0]

    assert "APP-02" in str(_get_attr_or_key(auth_event, "host"))
    assert "jdoe" in str(_get_attr_or_key(auth_event, "user")).lower()
    assert int(_get_attr_or_key(_get_attr_or_key(flow_event, "network"), "bytes_sent")) == 8245731
    assert "storage.sync-preview.net" in str(_get_attr_or_key(_get_attr_or_key(flow_event, "network"), "domain"))