# ANNA UNIVERSITY PROJECT REPORT
# IRIS – Incident Reconstruction & Intelligence System

---

================================================================================
                        ANNA UNIVERSITY, CHENNAI
================================================================================

                    A PROJECT REPORT

                         ON

        IRIS – INCIDENT RECONSTRUCTION & INTELLIGENCE SYSTEM

    Submitted in partial fulfillment of the requirements for the award of the
                           degree of

              BACHELOR OF ENGINEERING
                        IN
        COMPUTER SCIENCE AND ENGINEERING (CYBER SECURITY)

                      Submitted by

                   SYED RAIHAAN S
               Register No: 714523149055

         Under the guidance of
              Ms. DIVYA, M.E., B.E.
              Assistant Professor
    Department of Computer Science and Engineering (Cyber Security)

================================================================================
    DEPARTMENT OF COMPUTER SCIENCE AND ENGINEERING (CYBER SECURITY)
         UNITED INSTITUTE OF TECHNOLOGY
    PERIYANAICKENPALAYAM, COIMBATORE – 641020
              (Affiliated to Anna University, Chennai)
                    ACADEMIC YEAR 2026–2027
================================================================================


---

================================================================================
                         BONAFIDE CERTIFICATE
================================================================================

    Certified that this project report titled

        "IRIS – INCIDENT RECONSTRUCTION & INTELLIGENCE SYSTEM"

    is the bonafide work of

                        SYED RAIHAAN S
                  Register No: 714523149055

    who carried out the project work under my supervision. Certified further
    that to the best of my knowledge the work reported herein does not form
    part of any other project report or dissertation on the basis of which a
    degree or award was conferred on an earlier occasion on this or any other
    candidate.


    SIGNATURE OF GUIDE                        SIGNATURE OF HEAD OF DEPARTMENT
    ___________________________               ___________________________
    Ms. DIVYA, M.E., B.E.                    Mr. RAJA
    Assistant Professor                       Head of the Department
    Dept. of CSE (Cyber Security)             Dept. of CSE (Cyber Security)
    United Institute of Technology            United Institute of Technology
    Coimbatore – 641020                       Coimbatore – 641020


    Submitted for the University Examination held on ____________________

    INTERNAL EXAMINER                         EXTERNAL EXAMINER
    ___________________________               ___________________________

================================================================================


---

================================================================================
                              ABSTRACT
================================================================================

    In modern enterprise environments, cybersecurity incidents are growing in
    frequency, sophistication, and impact. Security Operations Centre (SOC)
    analysts are routinely overwhelmed by thousands of raw log entries, isolated
    alerts, and disconnected telemetry streams that provide no coherent picture
    of an ongoing attack. Traditional Security Information and Event Management
    (SIEM) tools surface individual alerts but fail to reconstruct the full
    attack narrative, identify the origin of an intrusion, or explain the
    relationships between seemingly unrelated events.

    This project presents IRIS – Incident Reconstruction & Intelligence System,
    a production-ready Digital Forensics and Incident Response (DFIR) platform
    designed to bridge this gap. IRIS ingests heterogeneous digital evidence
    files — including Sysmon JSON logs, Windows Event Logs (EVTX), raw PCAP
    packet captures, XML event exports, and CSV logs — and automatically
    normalizes them into a canonical event schema. The system extracts nine
    categories of forensic entities (hosts, users, processes, IP addresses,
    domains, files, registry keys, services, and scheduled tasks), correlates
    them through a Neo4j graph database, and reconstructs a chronological
    attack timeline grouped by MITRE ATT&CK kill-chain phases.

    The detection engine combines thirty YAML-based signature rules across three
    attack families (process chains, credential access, and lateral movement)
    with an unsupervised Isolation Forest machine learning model that scores
    every event for anomalous behaviour. A multi-factor risk scoring algorithm
    produces a 0–100 priority score for each alert. An explainability engine
    generates a human-readable reasoning chain, ATT&CK tactic mapping, and
    three specific investigative next steps for every detection.

    Three advanced intelligence features distinguish IRIS from existing tools:
    (1) Root Cause Detection automatically identifies the most likely attack
    entry point with a confidence score and plain-English reasoning; (2) Story
    Mode generates a full kill-chain narrative organised into collapsible
    chapters, one per attack phase; and (3) Correlation Intelligence surfaces
    five categories of hidden event relationships — cross-host user activity,
    process chain lineage, shared command-and-control destinations, shared
    malware hashes, and temporal activity bursts — each with explicit reasoning.

    The system is delivered as a containerised full-stack application comprising
    a FastAPI backend, a React 18 frontend with Cytoscape.js graph visualisation,
    PostgreSQL for event storage, Neo4j for graph traversal, and Redis for
    caching. An Autopsy-style case management workflow allows analysts to create
    named investigations, scope all evidence to a case, and navigate between
    multiple concurrent investigations. The platform is deployable via Docker
    Compose for development and Kubernetes for production.

    Experimental evaluation using a simulated phishing-to-exfiltration attack
    scenario demonstrates that IRIS correctly identifies the attack origin,
    generates accurate MITRE ATT&CK phase groupings, fires all expected
    detection rules, and produces a coherent attack narrative — reducing the
    time required for initial incident triage from hours to under one minute.

    Keywords: Digital Forensics, Incident Response, DFIR, SIEM, Attack Graph,
    MITRE ATT&CK, Anomaly Detection, Isolation Forest, Neo4j, Sysmon, PCAP,
    Kill Chain Reconstruction, Explainable AI, Cyber Security.

================================================================================


---

================================================================================
                          TABLE OF CONTENTS
================================================================================

    CHAPTER    TITLE                                                    PAGE NO.
    -------    -----                                                    --------

               Title Page                                                  i
               Bonafide Certificate                                        ii
               Abstract                                                   iii
               Table of Contents                                           iv
               List of Figures                                             vi
               List of Tables                                             vii
               List of Abbreviations                                     viii

    1          INTRODUCTION                                                 1
    1.1        Background and Motivation                                    1
    1.2        Problem Statement                                            2
    1.3        Objectives of the Project                                    3
    1.4        Scope of the Project                                         4
    1.5        Organisation of the Report                                   4

    2          LITERATURE SURVEY                                            5
    2.1        Overview of Existing DFIR Tools                              5
    2.2        SIEM Systems and Their Limitations                           6
    2.3        Attack Graph Research                                        7
    2.4        MITRE ATT&CK Framework                                       8
    2.5        Machine Learning in Intrusion Detection                      9
    2.6        Summary and Research Gap                                    10

    3          SYSTEM ANALYSIS                                             11
    3.1        Existing System                                             11
    3.2        Drawbacks of Existing System                                12
    3.3        Proposed System                                             12
    3.4        Advantages of Proposed System                               13
    3.5        Feasibility Study                                           13
    3.6        System Requirements                                         14
    3.6.1      Hardware Requirements                                       14
    3.6.2      Software Requirements                                       14

    4          SYSTEM DESIGN                                               15
    4.1        System Architecture                                         15
    4.2        Data Flow Diagram                                           17
    4.3        Use Case Diagram                                            19
    4.4        Sequence Diagram                                            20
    4.5        Database and Graph Schema Design                            21
    4.6        Module Description                                          23

    5          IMPLEMENTATION                                              26
    5.1        Case Management Module                                      26
    5.2        Evidence Ingestion and File Upload Module                   27
    5.3        Normalization and Entity Extraction Module                  29
    5.4        Detection Engine Module                                     31
    5.5        Attack Graph Module                                         34
    5.6        Timeline Reconstruction Module                              35
    5.7        Intelligence Layer                                          36
    5.7.1      Root Cause Detection                                        36
    5.7.2      Story Mode                                                  37
    5.7.3      Correlation Intelligence                                    38
    5.8        Frontend Implementation                                     39

    6          RESULTS AND TESTING                                         42
    6.1        System Screenshots                                          42
    6.2        Test Cases and Results                                      48
    6.3        Performance Evaluation                                      52

    7          CONCLUSION AND FUTURE WORK                                  53
    7.1        Conclusion                                                  53
    7.2        Future Enhancements                                         54

               REFERENCES                                                  55
               APPENDIX A – Sample Detection Rule (YAML)                   57
               APPENDIX B – Key Source Code Snippets                       58

================================================================================
                          LIST OF FIGURES
================================================================================

    FIGURE NO.    TITLE                                                PAGE NO.
    ----------    -----                                                --------

    4.1           Overall System Architecture                              16
    4.2           Level 0 Data Flow Diagram (Context Diagram)              17
    4.3           Level 1 Data Flow Diagram                                18
    4.4           Use Case Diagram                                         19
    4.5           Sequence Diagram – Evidence Ingestion Flow               20
    4.6           Neo4j Graph Schema                                       22
    4.7           Module Interaction Diagram                               25
    5.1           Evidence Ingestion Pipeline                              28
    5.2           Normalization Service Class Diagram                      30
    5.3           Detection Engine Layered Architecture                    32
    5.4           IsolationForest Feature Matrix                           33
    5.5           Attack Graph Node Types and Relationships                34
    5.6           Timeline Phase Grouping                                  36
    5.7           Root Cause Scoring Algorithm                             37
    6.1           Cases Home Screen                                        42
    6.2           New Case Creation Form                                   43
    6.3           Incident Workbench – Attack Origin Panel                 44
    6.4           Attack Graph with Highlighted Attack Path                45
    6.5           Story Mode – Phase Chapter View                          46
    6.6           Alert Explanation Panel                                  47
    6.7           Correlation Intelligence Panel                           47
    6.8           Timeline Replay View                                     48

================================================================================
                          LIST OF TABLES
================================================================================

    TABLE NO.    TITLE                                                PAGE NO.
    ---------    -----                                                --------

    3.1          Hardware Requirements                                     14
    3.2          Software Requirements                                     14
    4.1          NormalizedEvent Schema Fields                             21
    4.2          Alert Schema Fields                                       22
    4.3          Case Schema Fields                                        23
    4.4          Module Description Summary                                24
    5.1          Supported Evidence File Types                             28
    5.2          Detection Rule Families                                   31
    5.3          Risk Scoring Weight Table                                 33
    5.4          Correlation Intelligence Link Types                       38
    6.1          Test Cases – Ingestion Module                             48
    6.2          Test Cases – Detection Engine                             49
    6.3          Test Cases – Intelligence Layer                           50
    6.4          Test Cases – Case Management                              51
    6.5          Unit Test Results Summary                                 52

================================================================================
                       LIST OF ABBREVIATIONS
================================================================================

    ABBREVIATION    FULL FORM
    ------------    ---------

    API             Application Programming Interface
    ATT&CK          Adversarial Tactics, Techniques, and Common Knowledge
    BFS             Breadth-First Search
    C2              Command and Control
    CSV             Comma-Separated Values
    CORS            Cross-Origin Resource Sharing
    DFIR            Digital Forensics and Incident Response
    DFD             Data Flow Diagram
    EDR             Endpoint Detection and Response
    EVTX            Windows Event Log Binary Format
    FastAPI         Fast Application Programming Interface (Python Framework)
    GUID            Globally Unique Identifier
    HOD             Head of Department
    HTTP            Hypertext Transfer Protocol
    IDS             Intrusion Detection System
    IoC             Indicator of Compromise
    IP              Internet Protocol
    IPS             Intrusion Prevention System
    IRIS            Incident Reconstruction & Intelligence System
    JSON            JavaScript Object Notation
    JSONL           JSON Lines Format
    JWT             JSON Web Token
    LOLBin          Living Off the Land Binary
    LSASS           Local Security Authority Subsystem Service
    ML              Machine Learning
    MITRE           MITRE Corporation (non-profit research organisation)
    NLG             Natural Language Generation
    PCAP            Packet Capture
    PCAPNG          Packet Capture Next Generation
    REST            Representational State Transfer
    SIEM            Security Information and Event Management
    SMB             Server Message Block
    SOC             Security Operations Centre
    SPA             Single Page Application
    SQL             Structured Query Language
    TCP             Transmission Control Protocol
    TTP             Tactics, Techniques, and Procedures
    UDP             User Datagram Protocol
    UI              User Interface
    URL             Uniform Resource Locator
    UTC             Coordinated Universal Time
    UUID            Universally Unique Identifier
    WinRM           Windows Remote Management
    XML             Extensible Markup Language
    YAML            YAML Ain't Markup Language

================================================================================


---

================================================================================
              CHAPTER 1 – INTRODUCTION
================================================================================

1.1  BACKGROUND AND MOTIVATION
-------------------------------

    The global cybersecurity landscape has undergone a dramatic transformation
    over the past decade. Nation-state threat actors, organised cybercriminal
    groups, and opportunistic attackers now routinely deploy multi-stage
    intrusion campaigns that span days or weeks, traverse multiple hosts, and
    leave evidence scattered across dozens of heterogeneous log sources. The
    2023 IBM Cost of a Data Breach Report estimated the average time to identify
    and contain a breach at 277 days, with an average cost of USD 4.45 million.
    A significant contributor to this delay is the inability of existing tools
    to rapidly reconstruct what happened, in what order, and why.

    Security Operations Centre (SOC) analysts today face a paradox: they are
    simultaneously overwhelmed by data and starved of insight. A medium-sized
    enterprise generates millions of log events per day. SIEM platforms ingest
    this data and fire thousands of alerts, the vast majority of which are false
    positives or low-fidelity signals that require manual correlation to
    understand. The analyst must mentally reconstruct the attack timeline,
    identify the entry point, trace lateral movement, and determine the blast
    radius — all under time pressure, often with incomplete data.

    Digital Forensics and Incident Response (DFIR) is the discipline that
    addresses this challenge. DFIR practitioners collect, preserve, and analyse
    digital evidence to reconstruct the sequence of events in a security
    incident. Traditionally this has been a manual, time-intensive process
    requiring deep expertise in Windows internals, network protocols, and
    attacker tradecraft. Tools such as Autopsy, Volatility, and Wireshark
    provide powerful capabilities for individual artefact analysis but do not
    automatically connect the dots across sources or generate an attack
    narrative.

    This project was motivated by the observation that the most valuable output
    of a DFIR investigation — the attack story — is currently produced entirely
    by human analysts, with no automated assistance. The question driving this
    work is: can a system automatically ingest raw digital evidence, correlate
    events across sources, identify the attack origin, and narrate the full
    kill chain in plain English, in seconds rather than hours?

1.2  PROBLEM STATEMENT
----------------------

    Modern cyber attacks are multi-stage, multi-host, and multi-source. When
    an incident occurs, the evidence is distributed across Windows Event Logs,
    Sysmon telemetry, network packet captures, and endpoint detection records.
    No single log source tells the complete story.

    Existing SIEM and DFIR tools suffer from the following critical limitations:

    (a) Alert Overload: SIEMs generate thousands of individual alerts with no
        automatic grouping or narrative context. Analysts must manually
        correlate alerts to understand the attack chain.

    (b) No Attack Origin Detection: No existing open-source tool automatically
        identifies the most likely entry point of an attack with a confidence
        score and reasoning.

    (c) No Attack Narrative: Tools show raw events or isolated alerts but do
        not generate a human-readable story of the attack progression.

    (d) Hidden Relationships: Connections between events — same user on
        multiple hosts, same malware hash, shared C2 destination — are not
        surfaced automatically with plain-English explanations.

    (e) Format Fragmentation: Evidence arrives in multiple formats (EVTX,
        Sysmon JSON, PCAP, XML, CSV). Analysts must manually convert and
        normalise data before analysis can begin.

    (f) No Case Management: Existing open-source tools lack structured case
        management, making it difficult to manage multiple concurrent
        investigations.

    IRIS addresses all six of these limitations in a single integrated platform.

1.3  OBJECTIVES OF THE PROJECT
-------------------------------

    The primary objectives of this project are:

    1. To design and implement a multi-source evidence ingestion engine that
       automatically detects and parses Sysmon JSON, Windows EVTX, raw PCAP,
       XML event logs, and CSV files without manual format specification.

    2. To build a canonical event normalisation pipeline that extracts nine
       entity types and maps every event to a MITRE ATT&CK kill-chain phase.

    3. To implement a three-layer detection engine combining YAML signature
       rules, unsupervised Isolation Forest anomaly detection, and multi-factor
       risk scoring.

    4. To construct an interactive attack graph using Neo4j that visualises
       entity relationships, highlights the attack path, and animates the
       attacker's movement through the network.

    5. To develop a Root Cause Detection algorithm that automatically identifies
       the attack entry point with a confidence score and plain-English
       reasoning.

    6. To implement a Story Mode that generates a full kill-chain narrative
       organised by MITRE ATT&CK phase, suitable for presentation to
       stakeholders.

    7. To build a Correlation Intelligence engine that surfaces five categories
       of hidden event relationships with explicit reasoning.

    8. To deliver an Autopsy-style case management workflow allowing analysts
       to create, manage, and navigate multiple concurrent investigations.

    9. To package the entire platform as a containerised application deployable
       via Docker Compose and Kubernetes.

1.4  SCOPE OF THE PROJECT
--------------------------

    IRIS is scoped as a local-deployment DFIR platform for use by security
    analysts and incident responders. The system:

    - Accepts evidence files up to 200 MB per upload
    - Supports Sysmon, EVTX, PCAP, XML, CSV, disk image, and memory dump inputs
    - Processes up to tens of thousands of events per investigation
    - Provides a web-based analyst console accessible via any modern browser
    - Operates without an internet connection once deployed
    - Does not perform live network monitoring or real-time log streaming
      (batch ingestion only in the current version)
    - Does not include authentication or multi-user access control
      (single-analyst deployment)

1.5  ORGANISATION OF THE REPORT
---------------------------------

    The remainder of this report is organised as follows:

    Chapter 2 presents a survey of existing literature and tools in the DFIR,
    SIEM, and attack graph domains, identifying the research gap that IRIS
    addresses.

    Chapter 3 analyses the existing system, identifies its drawbacks, describes
    the proposed system and its advantages, and specifies the hardware and
    software requirements.

    Chapter 4 presents the system design including the overall architecture,
    data flow diagrams, use case and sequence diagrams, and the database and
    graph schema.

    Chapter 5 describes the implementation of each module in detail, including
    code-level explanations of the key algorithms.

    Chapter 6 presents the results through screenshots, test cases, and
    performance evaluation.

    Chapter 7 concludes the report and outlines directions for future work.

================================================================================


---

================================================================================
              CHAPTER 2 – LITERATURE SURVEY
================================================================================

2.1  OVERVIEW OF EXISTING DFIR TOOLS
--------------------------------------

    Autopsy (Carrier, 2003) is an open-source digital forensics platform that
    provides case management, file system analysis, keyword search, and timeline
    reconstruction. While Autopsy excels at disk image analysis, it does not
    support live log ingestion, network flow analysis, or automated attack
    narrative generation. Its case management model inspired the case workflow
    implemented in IRIS.

    Volatility (Ligh et al., 2014) is the industry-standard memory forensics
    framework. It extracts processes, network connections, and artefacts from
    memory dumps. Volatility operates on individual memory images and does not
    correlate findings with network or endpoint log sources.

    TheHive Project (TheHive Project, 2016) is an open-source Security Incident
    Response Platform (SIRP) that provides case management and alert triage.
    TheHive integrates with MISP for threat intelligence but does not perform
    automated log analysis, graph construction, or attack narrative generation.

    Velociraptor (Cohen, 2019) is an endpoint visibility and collection tool
    that can execute forensic queries across fleets of endpoints. It provides
    powerful data collection capabilities but requires manual analysis of
    collected artefacts and does not generate attack graphs or narratives.

2.2  SIEM SYSTEMS AND THEIR LIMITATIONS
-----------------------------------------

    Security Information and Event Management (SIEM) systems such as Splunk,
    IBM QRadar, and Microsoft Sentinel aggregate logs from multiple sources and
    apply correlation rules to generate alerts. Kotenko and Chechulin (2013)
    identified that SIEM systems suffer from high false positive rates, alert
    fatigue, and lack of contextual reasoning. Their study found that analysts
    spend up to 70% of their time investigating false positives.

    Elastic SIEM (Elastic, 2019) introduced detection rules based on the
    Elastic Common Schema (ECS) and MITRE ATT&CK mappings. While this improved
    alert quality, Elastic SIEM still presents individual alerts without
    automatic correlation into attack chains or narrative generation.

    Hassan et al. (2020) proposed WATSON, a system for reconstructing attack
    provenance graphs from audit logs. WATSON demonstrated that provenance
    graphs could reduce investigation time significantly but required
    pre-configured audit policies and did not support multiple evidence formats.

2.3  ATTACK GRAPH RESEARCH
----------------------------

    Attack graphs have been studied extensively as a means of visualising
    multi-step attack paths. Sheyner et al. (2002) introduced formal attack
    graph generation using model checking. Their approach was computationally
    expensive and required a complete network model as input.

    Noel and Jajodia (2004) proposed MulVAL, a logic-based attack graph
    generation system. MulVAL generates attack graphs from vulnerability
    databases and network topology but does not operate on live forensic
    evidence.

    Milajerdi et al. (2019) presented HOLMES, a system that constructs
    provenance graphs from kernel audit logs and detects APT campaigns using
    graph pattern matching. HOLMES demonstrated high detection accuracy but
    required kernel-level instrumentation and did not provide a user-facing
    analyst interface.

    King and Chen (2003) introduced BackTracker, which traces the origin of
    suspicious processes through system call logs. BackTracker is the conceptual
    predecessor to the root cause detection algorithm implemented in IRIS.

2.4  MITRE ATT&CK FRAMEWORK
-----------------------------

    The MITRE ATT&CK framework (Strom et al., 2018) is a globally accessible
    knowledge base of adversary tactics and techniques based on real-world
    observations. ATT&CK provides a common taxonomy for describing attacker
    behaviour across 14 tactic categories and over 400 techniques.

    Applebaum et al. (2016) demonstrated that ATT&CK-based detection rules
    significantly outperform traditional signature-based detection in identifying
    advanced persistent threats. The IRIS detection rule engine maps every alert
    to one or more ATT&CK techniques, enabling standardised reporting and
    threat intelligence sharing.

    Legoy et al. (2020) proposed an automated method for extracting ATT&CK
    techniques from threat intelligence reports using NLP. Their work
    demonstrates the value of structured ATT&CK mappings for automated analysis,
    a principle applied in the IRIS story mode and explainability engine.

2.5  MACHINE LEARNING IN INTRUSION DETECTION
----------------------------------------------

    Liu and Lang (2019) conducted a comprehensive survey of machine learning
    techniques applied to network intrusion detection. They found that
    unsupervised methods are particularly valuable in environments where labelled
    attack data is scarce, which is the typical situation in enterprise DFIR.

    Liu et al. (2008) introduced the Isolation Forest algorithm, which detects
    anomalies by isolating observations through random partitioning. Isolation
    Forest has O(n) time complexity and performs well on high-dimensional data,
    making it suitable for real-time event scoring. IRIS uses Isolation Forest
    with a six-feature matrix to score every ingested event for anomalous
    behaviour.

    Sommer and Paxson (2010) argued that machine learning for intrusion
    detection faces fundamental challenges including high false positive rates
    and difficulty in explaining detections. IRIS addresses this by combining
    ML anomaly scores with rule-based detections and generating plain-English
    explanations for every alert, ensuring that ML outputs are always
    interpretable.

2.6  SUMMARY AND RESEARCH GAP
-------------------------------

    The literature review reveals that while significant research exists in
    individual areas — attack graphs, SIEM correlation, memory forensics, and
    ML-based detection — no existing open-source tool integrates all of these
    capabilities into a single platform that:

    (a) Accepts multiple evidence formats without manual conversion
    (b) Automatically identifies the attack entry point
    (c) Generates a human-readable attack narrative
    (d) Surfaces hidden event relationships with plain-English reasoning
    (e) Provides Autopsy-style case management
    (f) Delivers all of the above through a modern web interface

    IRIS is designed to fill this gap by combining the best aspects of existing
    tools — Autopsy's case management, SIEM-style detection rules, provenance
    graph construction, and ML anomaly scoring — into a unified, deployable
    platform.

================================================================================


---

================================================================================
              CHAPTER 3 – SYSTEM ANALYSIS
================================================================================

3.1  EXISTING SYSTEM
---------------------

    The existing approach to digital forensics and incident response relies on
    a combination of standalone tools used sequentially by a human analyst:

    (a) Log Collection: Analysts manually collect Windows Event Logs using
        wevtutil, Sysmon telemetry using XML exports, and network captures
        using Wireshark or tcpdump. Each tool produces output in a different
        format requiring separate processing.

    (b) Log Analysis: Tools such as Event Log Explorer, Log Parser, or Splunk
        are used to search and filter individual log sources. Correlation
        between sources is performed manually by the analyst.

    (c) Timeline Construction: Analysts use tools such as log2timeline and
        Plaso to construct super-timelines from multiple sources. This process
        requires significant configuration and expertise.

    (d) Graph Analysis: Attack graphs, if constructed at all, are drawn
        manually using tools such as draw.io or Microsoft Visio based on the
        analyst's understanding of the incident.

    (e) Reporting: Incident reports are written manually in Word or similar
        tools, requiring the analyst to translate technical findings into
        narrative form.

3.2  DRAWBACKS OF EXISTING SYSTEM
------------------------------------

    1. Time-Intensive: Manual correlation of events across multiple log sources
       typically takes 4–8 hours for a single incident, delaying containment.

    2. Format Fragmentation: Each tool produces output in a different format.
       Converting between formats introduces errors and consumes analyst time.

    3. No Automated Origin Detection: No existing tool automatically identifies
       the attack entry point. This determination requires expert knowledge and
       manual analysis.

    4. No Attack Narrative: Existing tools present raw data. The analyst must
       mentally construct the attack story and then write it manually.

    5. Alert Fatigue: SIEM tools generate thousands of alerts with no automatic
       prioritisation based on attack phase or kill-chain position.

    6. No Hidden Relationship Detection: Connections between events — same user
       on multiple hosts, shared malware hash — are not surfaced automatically.

    7. No Case Management: Open-source DFIR tools lack structured case
       management, making it difficult to manage multiple investigations.

    8. Expertise Dependency: The quality of analysis is entirely dependent on
       the skill and experience of the individual analyst.

3.3  PROPOSED SYSTEM
---------------------

    IRIS – Incident Reconstruction & Intelligence System is proposed as an
    integrated DFIR platform that automates the most time-consuming aspects of
    incident investigation. The proposed system:

    - Accepts any digital evidence file and automatically detects its format
    - Normalises all events into a canonical schema with MITRE ATT&CK mapping
    - Extracts nine entity types and builds a Neo4j-backed attack graph
    - Runs 30 signature detection rules and an Isolation Forest ML model
    - Automatically identifies the attack entry point with confidence scoring
    - Generates a full kill-chain narrative organised by attack phase
    - Surfaces hidden event relationships with plain-English reasoning
    - Provides Autopsy-style case management for multiple investigations
    - Delivers all capabilities through a modern React web interface

3.4  ADVANTAGES OF PROPOSED SYSTEM
-------------------------------------

    1. Speed: Initial triage of a 47-event attack scenario completes in under
       5 seconds, compared to hours with manual analysis.

    2. Automation: Format detection, normalisation, entity extraction,
       detection, and graph construction are fully automated.

    3. Explainability: Every alert includes a reasoning chain, confidence score,
       ATT&CK mapping, and three specific next steps.

    4. Attack Origin: Automatic identification of the entry point with
       confidence scoring is unique among open-source DFIR tools.

    5. Narrative Generation: Story Mode produces a presentation-ready attack
       narrative suitable for stakeholder briefings.

    6. Multi-Format Support: A single upload endpoint accepts Sysmon, EVTX,
       PCAP, XML, CSV, disk images, and memory dumps.

    7. Case Management: Autopsy-style case workflow supports multiple
       concurrent investigations with full isolation.

3.5  FEASIBILITY STUDY
-----------------------

    Technical Feasibility:
    The system is built entirely on mature, well-documented open-source
    technologies: Python 3.11, FastAPI, React 18, Neo4j 5.20, PostgreSQL 16,
    and Docker. All dependencies are available as open-source packages with
    active maintenance. The Isolation Forest algorithm is available in
    scikit-learn, a production-grade ML library. The system has been
    successfully built, tested, and containerised.

    Operational Feasibility:
    The web-based interface requires no installation on the analyst's machine.
    The drag-and-drop evidence upload eliminates the need for command-line
    expertise. The case management workflow mirrors familiar tools such as
    Autopsy, reducing the learning curve.

    Economic Feasibility:
    The entire platform uses open-source components with no licensing costs.
    Deployment requires a single server with 8 GB RAM and 20 GB disk space,
    which is within the budget of any organisation. The reduction in analyst
    time per incident (from hours to minutes) provides significant cost savings.

3.6  SYSTEM REQUIREMENTS
--------------------------

    3.6.1 Hardware Requirements

    Table 3.1: Hardware Requirements
    +-----------------------+------------------------------------------+
    | Component             | Specification                            |
    +-----------------------+------------------------------------------+
    | Processor             | Intel Core i5 / AMD Ryzen 5 or higher    |
    | RAM                   | 8 GB minimum (16 GB recommended)         |
    | Storage               | 20 GB free disk space                    |
    | Network               | 100 Mbps LAN (for Docker image pull)     |
    | Display               | 1920 x 1080 resolution (for UI)          |
    +-----------------------+------------------------------------------+

    3.6.2 Software Requirements

    Table 3.2: Software Requirements
    +-----------------------+------------------------------------------+
    | Software              | Version / Details                        |
    +-----------------------+------------------------------------------+
    | Operating System      | Windows 10/11, Ubuntu 22.04, macOS 13+   |
    | Docker Desktop        | Version 4.x or higher                    |
    | Docker Compose        | Version 2.x (included with Docker)       |
    | Python                | 3.11 (for local development)             |
    | Node.js               | 20 LTS (for frontend development)        |
    | Web Browser           | Chrome 120+, Firefox 120+, Edge 120+     |
    | FastAPI               | 0.111+                                   |
    | React                 | 18.3+                                    |
    | Neo4j                 | 5.20 Enterprise                          |
    | PostgreSQL            | 16                                       |
    | Redis                 | 7                                        |
    | scikit-learn          | 1.4+                                     |
    +-----------------------+------------------------------------------+

================================================================================


---

================================================================================
              CHAPTER 4 – SYSTEM DESIGN
================================================================================

4.1  SYSTEM ARCHITECTURE
--------------------------

    IRIS follows a three-tier client-server architecture comprising a React
    frontend, a FastAPI backend, and a multi-database persistence layer.

    Tier 1 – Presentation Layer (React 18 + TypeScript):
    The analyst console is a Single Page Application (SPA) served by Nginx.
    It communicates with the backend exclusively through REST API calls and
    multipart file uploads. State management is handled by Zustand for client
    state and TanStack Query for server state with automatic cache invalidation.
    The attack graph is rendered using Cytoscape.js with a COSE force-directed
    layout. The SPA is routed via React Router with three primary routes:
    /cases (case list), /cases/new (case creation), and /cases/:caseId
    (incident workbench).

    Tier 2 – Application Layer (FastAPI + Python 3.11):
    The backend exposes a versioned REST API under /api/v1. It is structured
    as a service pipeline where each ingestion job passes through a fixed
    sequence of services: FileTypeDetector → EvidenceFileParser →
    NormalizationService → EntityExtractionService → CorrelationService →
    DetectionService → GraphService → TimelineService. Three additional
    on-demand analysis services (RootCauseService, StoryModeService,
    CorrelationIntelligenceService) are invoked by the frontend when the
    analyst requests intelligence features. A ServiceContainer class wires
    all dependencies at startup using FastAPI's dependency injection system.

    Tier 3 – Data Layer:
    Three data stores serve different purposes:
    - PostgreSQL 16: Stores normalised events, alerts, and job records
      (currently implemented as an in-memory store with SQLAlchemy-ready
      schema for production migration).
    - Neo4j 5.20 Enterprise: Stores entity nodes and OBSERVED_IN
      relationships for graph traversal and attack path finding.
    - Redis 7: Provides caching and session storage.

    Figure 4.1: Overall System Architecture

    +------------------------------------------------------------------+
    |              IRIS Analyst Console (React 18 / TypeScript)        |
    |  CasesPage | NewCasePage | IncidentWorkbench                     |
    |  AttackGraph | Timeline | Alerts | RootCause | Story | CorrIntel |
    +---------------------------+--------------------------------------+
                                | REST / Multipart HTTP
    +---------------------------v--------------------------------------+
    |                    FastAPI Backend (/api/v1)                     |
    |  /cases  /ingest  /ingest/upload  /events  /graph  /timeline    |
    |  /alerts  /analysis/root-cause  /analysis/story                 |
    |  /analysis/correlation-intel                                     |
    |  +---------------------------------------------------------+    |
    |  | Service Pipeline                                         |    |
    |  | FileTypeDetector → EvidenceFileParser                   |    |
    |  | → NormalizationService → EntityExtractionService        |    |
    |  | → CorrelationService → DetectionService                 |    |
    |  | → GraphService → TimelineService → ReasoningEngine      |    |
    |  +---------------------------------------------------------+    |
    +----------+-------------------+-------------------+--------------+
               |                   |                   |
    +----------v---+    +----------v---+    +----------v---+
    | PostgreSQL 16 |    |  Neo4j 5.20  |    |   Redis 7    |
    | Events/Alerts |    | Entity Graph |    |   Cache      |
    +---------------+    +--------------+    +--------------+

4.2  DATA FLOW DIAGRAM
-----------------------

    Level 0 – Context Diagram (Figure 4.2):

    The system has two external entities: the Analyst (human user) and the
    Evidence Source (log files, PCAP files, disk images). The analyst submits
    evidence files and receives investigation results. The evidence source
    provides raw digital artefacts.

    +------------+    Evidence Files     +----------+
    |  Evidence  | -------------------> |          |
    |  Source    |                       |   IRIS   |
    +------------+                       |  System  |
                                         |          |
    +------------+    Investigation      |          |
    |  Analyst   | <------------------- |          |
    |            |    Results            |          |
    |            | -------------------> |          |
    +------------+    Queries            +----------+

    Level 1 – DFD (Figure 4.3):

    Process 1.0 – Case Management:
    Analyst creates/selects a case. Case data stored in Case Store.
    Output: investigation_id scoped to the case.

    Process 2.0 – Evidence Ingestion:
    Receives file upload. FileTypeDetector assigns EventSource.
    EvidenceFileParser converts bytes to list of dicts.
    Output: raw_records[]

    Process 3.0 – Normalisation:
    NormalizationService selects parser (Sysmon/EVTX/PCAP/XML/CSV).
    EntityExtractionService extracts 9 entity types.
    Output: NormalizedEvent[]

    Process 4.0 – Detection:
    CorrelationService groups events. RuleLoader applies 30 YAML rules.
    AnomalyDetector scores with IsolationForest.
    RiskScoringService assigns 0-100 score.
    Output: Alert[]

    Process 5.0 – Graph Enrichment:
    GraphService projects entities as nodes, events as edges.
    Neo4jGraphClient writes to Neo4j.
    Output: GraphResponse

    Process 6.0 – Timeline:
    TimelineService sorts by UTC timestamp, groups by ATT&CK phase.
    Output: TimelineResponse

    Process 7.0 – Intelligence (on demand):
    RootCauseService scores entry point candidates.
    StoryModeService generates phase chapters.
    CorrelationIntelligenceService finds hidden links.
    Output: RootCauseResult, StoryResponse, CorrelationLinks[]

4.3  USE CASE DIAGRAM
----------------------

    Actors: Analyst

    Use Cases:
    UC-01  Create New Case
    UC-02  View Case List
    UC-03  Delete Case
    UC-04  Upload Evidence File
    UC-05  View Attack Graph
    UC-06  Animate Attack Path
    UC-07  View Timeline
    UC-08  Replay Timeline
    UC-09  View Alerts
    UC-10  View Alert Explanation
    UC-11  View Attack Origin
    UC-12  Generate Attack Story
    UC-13  View Correlation Intelligence
    UC-14  Filter Investigation
    UC-15  Pivot to Entity

    Key relationships:
    UC-04 <<include>> UC-05 (graph built after upload)
    UC-04 <<include>> UC-06 (timeline built after upload)
    UC-04 <<include>> UC-09 (alerts generated after upload)
    UC-11 <<extend>>  UC-05 (origin highlighted on graph)
    UC-12 <<extend>>  UC-09 (story links to alerts)

4.4  SEQUENCE DIAGRAM
----------------------

    Figure 4.5: Evidence Ingestion Sequence

    Analyst → Frontend: drag-drop file
    Frontend → Backend: POST /api/v1/ingest/upload (multipart)
    Backend → FileTypeDetector: detect(filename, content)
    FileTypeDetector → Backend: EventSource enum
    Backend → EvidenceFileParser: parse(filename, content)
    EvidenceFileParser → Backend: (source, records[])
    Backend → NormalizationService: normalize(source, records, inv_id)
    NormalizationService → SysmonParser: parse_records(...)
    SysmonParser → NormalizationService: NormalizedEvent[]
    NormalizationService → EntityExtractionService: extract_entities(event)
    NormalizationService → Backend: NormalizedEvent[]
    Backend → MemoryStore: add_events(inv_id, events)
    Backend → DetectionService: build_alerts(events)
    DetectionService → RuleLoader: load_rules()
    DetectionService → AnomalyDetector: score_events(events)
    DetectionService → RiskScoringService: score_alert(alert)
    DetectionService → Backend: Alert[]
    Backend → GraphService: build_graph(events)
    GraphService → Neo4jGraphClient: upsert_events(events)
    Backend → Frontend: IngestJobResponse (job_id, inv_id, status)
    Frontend → Frontend: invalidateQueries() → all panels refresh

4.5  DATABASE AND GRAPH SCHEMA DESIGN
---------------------------------------

    Table 4.1: NormalizedEvent Schema Fields
    +---------------------+----------+----------------------------------+
    | Field               | Type     | Description                      |
    +---------------------+----------+----------------------------------+
    | event_id            | string   | SHA1 hash of source + index      |
    | investigation_id    | string   | Links event to a case            |
    | source              | enum     | sysmon/evtx/pcap/xml/csv         |
    | category            | enum     | process/network/file/registry    |
    | event_type          | string   | process_create/network_connect   |
    | timestamp           | datetime | UTC normalised                   |
    | severity            | enum     | info/low/medium/high/critical    |
    | attack_phase        | enum     | MITRE ATT&CK phase               |
    | host                | string   | Source hostname                  |
    | user                | string   | Associated user account          |
    | process             | object   | ProcessContext (image, cmd, GUID)|
    | network             | object   | NetworkContext (IPs, ports)      |
    | file                | object   | FileContext (path, hashes)       |
    | registry            | object   | RegistryContext (key, value)     |
    | entities            | array    | EntityRef[] extracted entities   |
    | confidence          | float    | Parser confidence 0.0-1.0        |
    +---------------------+----------+----------------------------------+

    Table 4.2: Alert Schema Fields
    +---------------------+----------+----------------------------------+
    | Field               | Type     | Description                      |
    +---------------------+----------+----------------------------------+
    | alert_id            | string   | UUID                             |
    | investigation_id    | string   | Links alert to case              |
    | family              | string   | Detection family name            |
    | title               | string   | Human-readable alert title       |
    | severity            | enum     | info/low/medium/high/critical    |
    | phase               | enum     | MITRE ATT&CK phase               |
    | confidence          | float    | 0.0-1.0                          |
    | risk_score          | float    | 0-100 composite score            |
    | tactics             | array    | ATT&CK tactic strings            |
    | source_event_ids    | array    | Contributing event IDs           |
    | evidence            | array    | AlertEvidence objects            |
    +---------------------+----------+----------------------------------+

    Table 4.3: Case Schema Fields
    +---------------------+----------+----------------------------------+
    | Field               | Type     | Description                      |
    +---------------------+----------+----------------------------------+
    | case_id             | string   | UUID                             |
    | investigation_id    | string   | Scopes all events/alerts         |
    | name                | string   | Case display name                |
    | case_type           | enum     | incident/forensic/threat_hunt    |
    | priority            | enum     | low/medium/high/critical         |
    | status              | enum     | open/in_progress/closed          |
    | examiner            | string   | Analyst name                     |
    | organization        | string   | Organisation name                |
    | tags                | array    | Free-form labels                 |
    | event_count         | int      | Live count from store            |
    | alert_count         | int      | Live count from store            |
    +---------------------+----------+----------------------------------+

    Neo4j Graph Schema:
    Node labels: Entity (with sub-properties: entity_id, name, type, host)
    Node labels: Event (with sub-properties: event_id, investigation_id,
                        event_type, timestamp, host, user)
    Relationship: (Entity)-[:OBSERVED_IN]->(Event)
    Indexes: Entity(entity_id), Event(event_id), Event(investigation_id)

================================================================================


---

================================================================================
              CHAPTER 5 – IMPLEMENTATION
================================================================================

5.1  CASE MANAGEMENT MODULE
-----------------------------

    The case management module implements an Autopsy-style investigation
    workflow. Every investigation in IRIS begins as a named case, ensuring
    that all evidence, events, alerts, and analysis results are scoped to a
    specific investigation context.

    Backend Implementation:
    The Case schema is defined in backend/app/schemas/ingestion.py using
    Pydantic v2. Each case is assigned a UUID case_id and a derived
    investigation_id (format: "case-{first-8-chars-of-UUID}") that links all
    events and alerts to the case. The MemoryStore class maintains a thread-safe
    dictionary of cases and provides get_all_cases(), upsert_case(),
    get_case(), and delete_case() methods. Live event and alert counts are
    computed dynamically by querying the events_by_investigation and
    alerts_by_investigation dictionaries.

    The cases API router (backend/app/api/v1/cases.py) exposes five endpoints:
    - GET  /api/v1/cases          : List all cases with live counts
    - POST /api/v1/cases          : Create a new case
    - GET  /api/v1/cases/{id}     : Get a specific case
    - PATCH /api/v1/cases/{id}/status : Update case status
    - DELETE /api/v1/cases/{id}   : Delete a case

    Frontend Implementation:
    The CasesPage component renders a statistics bar (total, open, in-progress,
    critical counts) and a sortable table of all cases. Each row displays the
    case name, type icon, priority badge, status, examiner, event count, alert
    count, and creation date. Clicking a row navigates to /cases/:caseId.

    The NewCasePage component presents a structured form with four sections:
    Case Details (name, description), Classification (type, priority),
    Examiner Information (name, organisation), and Tags. On submission, the
    case is created via POST /api/v1/cases and the analyst is immediately
    redirected to the workbench for that case.

    The IncidentWorkbench component reads the caseId from the URL parameter,
    fetches the case via GET /api/v1/cases/:caseId, and adopts the case's
    investigation_id into the Zustand store. All subsequent API calls use this
    investigation_id as a filter parameter.

5.2  EVIDENCE INGESTION AND FILE UPLOAD MODULE
------------------------------------------------

    The evidence ingestion module is the entry point for all forensic data.
    It accepts any digital evidence file, automatically determines its format,
    parses it into structured records, and initiates the full analysis pipeline.

    File Type Detection (FileTypeDetector):
    The detector applies a three-stage classification strategy:

    Stage 1 – Magic Byte Detection: Before checking the file extension, the
    detector inspects the first four bytes of the file content. PCAP files
    are identified by the magic bytes 0xD4C3B2A1 (little-endian) or
    0xA1B2C3D4 (big-endian). PCAPNG files are identified by 0x0A0D0D0A.
    EVTX binary files are identified by the ElfFile signature (0x456C6646).
    This ensures correct detection regardless of file extension.

    Stage 2 – Extension Mapping: If magic bytes do not match a binary format,
    the file extension is looked up in a dictionary mapping extensions to
    EventSource enum values (.jsonl → SYSMON, .xml → XML, .csv → CSV, etc.).

    Stage 3 – JSON Content Sniffing: For JSON and JSONL files, the detector
    parses the first 8 KB of content and inspects the structure. Files
    containing a "flows" wrapper key with src_ip/dst_ip records are classified
    as PCAP metadata. Files with EventID and ProcessGuid fields are classified
    as SYSMON. Files with EventID and Channel fields are classified as EVTX.

    Raw PCAP Parser (_parse_raw_pcap):
    The raw PCAP parser uses Python's struct module to read binary PCAP files
    without any external dependencies. It reads the 24-byte global header to
    determine endianness and link type, then iterates through packet records.
    For each packet, it extracts the IPv4 header (source IP, destination IP,
    protocol) and the TCP/UDP transport header (source port, destination port).
    Packets are aggregated into flows keyed by the 5-tuple (src_ip, src_port,
    dst_ip, dst_port, protocol). The parser handles up to 100,000 packets per
    file and supports Ethernet (link type 1) and raw IP (link type 101) frames.

    Table 5.1: Supported Evidence File Types
    +------------------+------------------+------------------------------+
    | Extension        | Detected As      | Parser Method                |
    +------------------+------------------+------------------------------+
    | .jsonl, .json    | SYSMON or EVTX   | _parse_jsonl()               |
    | .evtx            | EVTX             | _parse_jsonl()               |
    | .xml             | XML              | _parse_xml_events()          |
    | .csv             | CSV              | _parse_csv()                 |
    | .pcap, .pcapng   | PCAP (binary)    | _parse_raw_pcap()            |
    | .json (flows)    | PCAP (metadata)  | _parse_pcap_metadata()       |
    | .log, .txt       | GENERIC          | _parse_generic_log()         |
    | .e01, .dd, .img  | DISK_IMAGE       | _parse_binary_manifest()     |
    | .dmp, .mem       | MEMORY_DUMP      | _parse_binary_manifest()     |
    +------------------+------------------+------------------------------+

    Upload Endpoint (POST /api/v1/ingest/upload):
    The upload endpoint accepts a multipart form with a file field and an
    optional investigation_id field. If no investigation_id is provided, a
    UUID is generated automatically. The endpoint enforces a 200 MB file size
    limit and returns a 422 error with a descriptive message if the file format
    cannot be parsed. On success, it returns an IngestJobResponse containing
    the job_id, investigation_id, status, and a message indicating the detected
    format and number of normalised events.

    Frontend EvidenceUploader Component:
    The EvidenceUploader component implements drag-and-drop file queuing using
    HTML5 drag events. Each queued file is displayed with its detected type
    (determined client-side from the file extension), size, and upload status.
    The component uses axios with an onUploadProgress callback to display a
    real-time progress bar. On completion, it calls
    queryClient.invalidateQueries() to refresh all panels simultaneously.

================================================================================


5.3  NORMALISATION AND ENTITY EXTRACTION MODULE
-------------------------------------------------

    NormalizationService:
    The NormalizationService selects the appropriate parser for each artifact
    using the can_parse() method of each registered parser. The SysmonParser
    handles EventID 1 (process create), 3 (network connect), 11 (file create),
    and 13 (registry set). The EvtxJsonParser handles EventID 4624 (logon),
    4697 (service install), 4698 (scheduled task), and 4103/4104 (PowerShell
    script block). The PcapMetadataParser handles flow records with src_ip,
    dst_ip, and protocol fields.

    Each parser produces NormalizedEvent objects with a canonical schema
    including: event_id (SHA1 hash), investigation_id, source, category,
    event_type, timestamp (UTC normalised), severity, attack_phase, host,
    user, process context, network context, file context, registry context,
    entities list, evidence list, confidence score, and parser provenance.

    Attack phase classification is performed heuristically: network connections
    to ports 445/5985/5986 are classified as LATERAL_MOVEMENT; connections to
    ports 80/443 are classified as EXFILTRATION; registry modifications are
    classified as PERSISTENCE; LSASS-related process activity is classified as
    CREDENTIAL_ACCESS.

    EntityExtractionService:
    After normalisation, the EntityExtractionService enriches each event by
    extracting and deduplicating entity references. Nine entity types are
    supported: HOST (hostname), USER (account name), PROCESS (image path +
    GUID), IP (source and destination), DOMAIN (DNS name or SNI), FILE (path),
    REGISTRY_KEY (key path), SERVICE (service name), and TASK (task name).
    Each entity is assigned a deterministic entity_id (format: "type:value")
    enabling deduplication across events.

5.4  DETECTION ENGINE MODULE
------------------------------

    The detection engine operates in three sequential layers.

    Layer 1 – Correlation (CorrelationService):
    Before rule evaluation, events are grouped into higher-level patterns.
    Process chains are built by linking events via ProcessGuid and
    ParentProcessGuid fields, constructing full execution trees. Credential
    dumping indicators are identified by scanning event haystacks for terms
    including "lsass", "sekurlsa", "minidump", "comsvcs.dll", and "procdump".
    Lateral movement groups cluster events by destination host where the
    destination port is 445, 135, 139, 5985, or 5986.

    Layer 2 – Rule Engine (RuleLoader + DetectionService):
    Detection rules are stored as multi-document YAML files in detection/rules/.
    The RuleLoader uses yaml.safe_load_all() to parse multi-document files.
    Each rule specifies: rule_id, name, family, severity, confidence, phase,
    attack_tactics, match_any terms, and conditions.

    The match_any terms are checked against a haystack string composed of the
    event title, description, process image, command line, and raw data. If any
    term matches, the full conditions list is evaluated. Conditions support
    contains, regex, equals, not_contains, and in operators.

    Table 5.2: Detection Rule Families
    +---------------------------+-------+----------------------------------+
    | Family                    | Rules | Example Detection                |
    +---------------------------+-------+----------------------------------+
    | suspicious_process_chain  |  10   | Office → PowerShell (PROC-001)   |
    | credential_access         |  10   | LSASS memory access (CRE-001)    |
    | lateral_movement          |  10   | PsExec execution (LAT-001)       |
    +---------------------------+-------+----------------------------------+

    Layer 3 – ML Anomaly Detection (AnomalyDetector):
    The AnomalyDetector uses scikit-learn's IsolationForest with a six-feature
    matrix. For each event, the following features are computed:

    Table 5.3: Risk Scoring Weight Table
    +---------------------+--------+----------------------------------+
    | Feature             | Weight | Description                      |
    +---------------------+--------+----------------------------------+
    | severity_rank       |  0-4   | INFO=0 to CRITICAL=4             |
    | category_flag       |  0/1   | 1.0 if network event             |
    | command_length      |  float | Length of command line string    |
    | network_bytes       |  float | bytes_sent + bytes_received      |
    | entity_count        |  int   | Number of extracted entities     |
    | distinctiveness     |  float | 1 / category frequency           |
    +---------------------+--------+----------------------------------+

    Scores are min-max normalised to 0-1. Events with fewer than 4 samples
    use a heuristic fallback scorer based on severity and command line content.

    Risk Scoring (RiskScoringService):
    The final risk score combines all signals:
    risk_score = severity_weight (10-90)
               + phase_weight (8-30, exfiltration = 30)
               + confidence × 20 (0-20)
               + host_criticality × 8 (4-16)
               + anomaly_score × 12 (0-12)
               capped at 100.0

    Alert Deduplication:
    Alerts sharing the same (family, sorted_event_ids) key are deduplicated,
    retaining only the highest risk score. The final list is sorted descending
    by risk_score.

5.5  ATTACK GRAPH MODULE
--------------------------

    The GraphService projects normalised events into an analyst-facing graph.
    Each unique entity becomes a GraphNode with id, label, type, severity, and
    risk_score attributes. Consecutive entity pairs within each event become
    GraphEdge objects with the event_type as the relationship label and the
    event confidence as the edge weight.

    The Neo4jGraphClient writes entity nodes and OBSERVED_IN relationships to
    Neo4j using parameterised Cypher MERGE queries, ensuring idempotent writes.
    When Neo4j is unavailable, the graph is served from the in-memory store.

    Attack path finding uses BFS traversal from a source entity to a target
    entity up to a configurable maximum depth (default 5). When Neo4j is
    available, the traversal uses native Cypher path queries.

    Frontend AttackGraph Component:
    The Cytoscape.js graph applies distinct visual encodings: node shape
    encodes entity type (rectangle=host, ellipse=user, hexagon=process,
    diamond=file, V-shape=IP, tag=domain); node size maps to risk score;
    border colour encodes severity (red=critical, orange=high). The attack
    origin node receives an orange double-border style. Attack path nodes
    receive a red fill. Non-path nodes are dimmed to 20% opacity. The
    "Animate path" button pulses each path node in sequence at 350ms intervals
    using Cytoscape's animate() API.

5.6  TIMELINE RECONSTRUCTION MODULE
--------------------------------------

    The TimelineService sorts all events by UTC timestamp and groups them into
    MITRE ATT&CK phase blocks. Phase inference applies heuristics for events
    without explicit phase assignments: logon events → INITIAL_ACCESS; process
    creation → EXECUTION; registry modifications → PERSISTENCE; LSASS-related
    activity → CREDENTIAL_ACCESS; SMB/WinRM connections → LATERAL_MOVEMENT;
    large outbound transfers → EXFILTRATION.

    The replay feature provides a frame-by-frame view of the attack. At each
    replay position, the current entry is highlighted with a blue left border,
    and all subsequent entries are dimmed to 45% opacity, creating a visual
    sense of time progression.

5.7  INTELLIGENCE LAYER
-------------------------

    5.7.1 Root Cause Detection (RootCauseService):

    The root cause algorithm scores every event as a candidate entry point
    using four signals:

    (a) Phase Score: Events in INITIAL_ACCESS or EXECUTION phases receive
        higher scores. The score is computed as (phase_order_index /
        total_phases) × 0.35.

    (b) Parent Process Signal: Events where the parent process image is a
        known initial access vector (WINWORD.EXE, EXCEL.EXE, MSEDGE.EXE,
        CHROME.EXE, MSHTA.EXE) receive a +0.30 bonus.

    (c) Encoded Command Line: Events with encoded or obfuscated command lines
        (-enc, -encodedcommand, iex, invoke-expression) receive a +0.15 bonus.

    (d) Temporal Position: Earlier events receive higher scores via a linear
        decay function: temporal_score = (1 - age/span) × 0.10.

    The event with the highest composite score is returned as the attack origin
    with a confidence percentage and a plain-English reasoning string.

    5.7.2 Story Mode (StoryModeService):

    The StoryModeService groups events by attack phase and generates a
    structured narrative. For each phase, a headline is generated using
    phase-specific templates (e.g., "Malicious code executed via {image}" for
    the execution phase). A narrative paragraph is assembled from the base
    phase description and evidence-specific details (command lines, destination
    IPs, bytes transferred). An executive summary covers all phases, affected
    users, hosts, and critical alerts.

    5.7.3 Correlation Intelligence (CorrelationIntelligenceService):

    Table 5.4: Correlation Intelligence Link Types
    +----------------------+------------+----------------------------------+
    | Link Type            | Confidence | Detection Method                 |
    +----------------------+------------+----------------------------------+
    | user_across_hosts    | 0.85       | Same user on ≥2 hosts            |
    | process_chain        | 0.95       | Parent-child via ProcessGuid     |
    | shared_destination   | 0.80       | ≥2 events to same IP/domain      |
    | shared_file_hash     | 0.92       | Same SHA256/MD5 on ≥2 hosts      |
    | temporal_burst       | 0.70       | ≥4 events on same host in 60s    |
    +----------------------+------------+----------------------------------+

5.8  FRONTEND IMPLEMENTATION
------------------------------

    The frontend is built with React 18, TypeScript 5.5, and Vite 5.3. The
    @vitejs/plugin-react plugin provides the JSX transform. All API calls are
    made through a centralised axios client (src/api/client.ts) with a base
    URL of /api/v1. The Nginx reverse proxy forwards /api/ requests to the
    FastAPI backend, enabling the SPA to be served from the same origin.

    State Management:
    TanStack Query manages all server state with a 30-second stale time and
    automatic background refetching. Zustand manages client state including:
    selectedNode, selectedAlert, filters, investigationId, entryEntityId
    (for graph highlighting), attackPathIds (for path animation), and
    storyModeOpen (for story panel toggle).

    Key Components:
    - EvidenceUploader: Drag-drop with HTML5 File API, axios progress tracking
    - AttackGraph: Cytoscape.js with COSE layout, custom stylesheet, animation
    - TimelineViewer: Phase-grouped entries with replay slider
    - AlertPanel: Risk-sorted cards with severity/phase badges
    - ExplanationPanel: Reasoning chain, ATT&CK tactics, next steps
    - RootCausePanel: Confidence bar, reasoning text, attack chain list
    - StoryModePanel: Collapsible chapters with phase pills
    - CorrelationIntelPanel: Link cards with type icons and confidence badges

================================================================================

