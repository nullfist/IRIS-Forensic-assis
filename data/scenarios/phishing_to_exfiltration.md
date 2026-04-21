# Demo Scenario: Phishing to Exfiltration

## Overview

This scenario models a compact but realistic intrusion path for the IRIS analyst workbench:

1. **Initial access** via a phishing document opened by a user on `WKSTN-07`.
2. **Execution** through `WINWORD.EXE` spawning encoded `powershell.exe`.
3. **Payload staging** into `C:\ProgramData\stage\adsvc.exe`.
4. **Credential access** using `procdump64.exe` against `lsass.exe`.
5. **Lateral movement** to `APP-02` over SMB/RPC and to `DB-01` via scheduled task / WinRM style activity.
6. **Exfiltration** of a ZIP archive over HTTPS to an external domain.

## Data Sources

### Sysmon
File: `data/sample_logs/sysmon_attack_chain.jsonl`

Key events:
- Office process execution
- Encoded PowerShell
- External HTTPS connection to `cdn.update-support.com`
- Payload drop to `C:\ProgramData\stage\adsvc.exe`
- `procdump64.exe` dumping LSASS
- Registry Run key persistence
- SMB/RPC connections to `APP-02`
- `sc.exe` and `schtasks.exe` usage
- Outbound HTTPS transfer to `storage.sync-preview.net`

### EVTX-exported JSON
File: `data/sample_logs/evtx_process_events.jsonl`

Key events:
- Security 4624 network logon on `APP-02`
- Security 4697 service installation
- Security 4698 scheduled task creation on `DB-01`
- PowerShell 4104 script block logging
- Security 4688 for remote service creation tooling

### PCAP metadata
File: `data/pcaps/lateral_movement_metadata.json`

Key flows:
- TCP/445 SMB transfer from `WKSTN-07` to `APP-02`
- TCP/135 RPC communication
- TCP/5985 WinRM session toward `DB-01`
- High-volume outbound TCP/443 transfer to `storage.sync-preview.net`

## Analyst Storyline

A finance-themed document named `Q1_Benefits_Update.docm` is opened by `CORP\jdoe`. Within seconds, Word launches PowerShell using encoded content that retrieves a stage-two script. The script drops `adsvc.exe`, which becomes the primary execution node for the rest of the incident.

The staged binary then launches `procdump64.exe` to dump LSASS into `C:\ProgramData\lsass_20250112.dmp`, strongly suggesting credential theft. Shortly after, the host starts reaching `APP-02` over SMB and RPC, and `sc.exe` is used to create a temporary service remotely. A scheduled task is then pushed to `DB-01`, implying expansion into a second host.

Finally, the actor creates `finance_q1.zip` and initiates a large outbound HTTPS transfer to `storage.sync-preview.net`, representing probable exfiltration.

## Expected Detection Outcomes

- Suspicious process chain: `WINWORD.EXE -> powershell.exe`
- Credential dumping: `procdump64.exe` with LSASS arguments and dump output
- Lateral movement: remote service creation, SMB/RPC, scheduled task creation
- Timeline phases from **initial_access** through **exfiltration**
- Graph pivots connecting user, host, processes, files, remote IPs/domains, and alerts

## Suggested Demo Flow

1. Ingest the Sysmon sample.
2. Ingest the EVTX sample.
3. Optionally enrich with PCAP metadata.
4. Open the workbench graph and select `powershell.exe` or `adsvc.exe`.
5. Review alerts and inspect the explanation for the credential dumping alert.
6. Replay the timeline up to `08:20Z` to show the transition from execution to credential access.
7. Pivot to graph attack paths between `host:WKSTN-07` and `host:APP-02` or the external IP.