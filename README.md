# IOA-Based Detection Framework for Windows Living-Off-the-Land (LOTL) Techniques using Sysmon and SilkETW

> **IT9115 — Project Thesis**
> Sudharshiya Ganesan | Student ID: 20232004
> Master of Information Technology, Whitecliffe, New Zealand
> Supervised by: Dr. Simon Yusuf Enoch

---

## 📌 Overview

Living-off-the-Land (LOTL) attacks abuse legitimate Windows binaries (`powershell.exe`, `wmic.exe`, `rundll32.exe`, `certutil.exe`, etc.) to carry out malicious activity while blending into normal administrative behaviour. Because no new files are dropped, traditional **Indicator of Compromise (IOC)** detection (file hashes, static signatures) fails to catch these techniques.

This project designs, implements and evaluates an **open-source, Indicator of Attack (IOA)-centric detection framework** that identifies LOTL techniques through behavioural telemetry rather than static signatures. It uses two telemetry sources (Sysmon and SilkETW), a Docker-deployed HELK SIEM, ATT&CK-enriched alert rules, and adversary emulation with Atomic Red Team to measure how well each ATT&CK technique is actually detected.

---

## 🎯 Problem Statement

Organisations increasingly use MITRE ATT&CK technique "coverage" as a measure of security posture, and commercial EDR and SIEM products advertise their ATT&CK mappings. It is unclear how reliable that measure is.

- **Coverage is not consistent across products.** Virkud et al. (USENIX Security 2024) analysed ATT&CK-annotated detection rulesets from commercial providers and a crowdsourced ruleset. They found that many techniques cannot realistically be turned into detection rules, and that covering a technique does not reliably mean covering the same real-world threats ([paper](https://www.usenix.org/conference/usenixsecurity24)).
- **Telemetry differs by product.** The [EDR-Telemetry](https://www.edr-telemetry.com/windows) project compares which telemetry feature categories each EDR provides (process creation, image/library loaded, remote thread creation, process call stacks, Win32 API telemetry and others). Capabilities vary between vendors, and a single source such as Sysmon does not cover every category. This motivates the dual-telemetry design used here.
- **Adversaries exploit the gaps.** LOTL binaries (LOLBins) are used to evade EDR detection, and default Windows logging gives limited visibility for behavioural (IOA) detection.
- **Reported EDR coverage is partial.** Commercial EDR products are reported to implement only 48–55% of MITRE ATT&CK techniques.
- **Inconsistent baselines are costly.** Real-world incidents (e.g. the 2025 Qilin ransomware attack on Malaysia Airports) show the cost of inconsistent baselines and untuned EDR.

**Research question:** Can a dual-telemetry, open-source pipeline combining Sysmon, ETW, Sigma-style rules and machine learning achieve high-fidelity LOTL detection, per ATT&CK technique, without commercial tooling?

---

## 🧠 Architecture

```
Adversary Emulation Layer (Kali Linux / Atomic Red Team, remote execution over WinRM)
            │
            ▼
Telemetry Collection Layer (Sysmon + SilkETW — dual source, Winlogbeat shipper)
            │
            ▼
Ingestion & Pre-processing Layer (HELK: Kafka → Logstash → Elasticsearch)
            │
            ▼
Detection Layer
   ├── ElastAlert rules (IOA-centric, MITRE ATT&CK enriched)
   └── ML Anomaly Layer (LSTM Autoencoder + Isolation Forest)
            │
            ▼
Analysis & Validation Layer (Kibana dashboards, confusion matrix, ROC, MTTD)
```

**Core platform:** HELK (Hunting ELK), chosen over standalone ELK for its ready-made hunting pipeline, ATT&CK-aligned enrichment and ElastAlert integration.

---

## 🧪 Lab Setup

The lab is an isolated, three-VM environment (see `Lab_architecture.png`):

| VM | Role |
|----|------|
| Windows endpoint | Target host running Sysmon, SilkETW/SilkService and Winlogbeat |
| Kali Linux | Adversary emulation (Atomic Red Team) |
| Ubuntu 24.04 (noble) | HELK SIEM, 8 GB RAM |

### HELK deployment (Docker Compose)

HELK (build `v0.1.9-alpha10082020`, ELK 7.6.2) was deployed on Ubuntu 24.04 with its Docker Compose installer using **build choice 2: Kafka + KSQL + ELK + Nginx + ElastAlert**. The Spark/Jupyter options (builds 3 and 4) were not deployed, so the ML analysis is done separately in Python.

### Log collection (Winlogbeat)

Winlogbeat on the Windows endpoint ships these channels to HELK:

- Application, System, Security and Setup
- `Microsoft-Windows-Sysmon/Operational`
- `Windows PowerShell` (event IDs 400, 403, 600, 800)
- `Microsoft-Windows-PowerShell/Operational` (event IDs 4103, 4104, 4105, 4106, which cover module and script block logging)
- `SilkETW-Log` and `SilkService-Log` (ETW telemetry)
- `ForwardedEvents`

Event-ID filters and `ignore_older: 72h` on selected channels keep ingestion volume under control in the resource-limited lab.

### Adversary emulation (Atomic Red Team over WinRM)

The [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) repository is cloned on the Kali VM. Tests are run against the Windows endpoint through remote WinRM sessions driven from Python, using a low-privilege test account. A `whoami` call was used to confirm remote execution before running technique tests. WinRM is exposed only inside the isolated lab network.

---

## 🛠️ Tools & Technologies

| Layer | Tool |
|-------|------|
| Adversary emulation | Kali Linux, Atomic Red Team, Python (`pywinrm`) over WinRM |
| Endpoint telemetry | Sysmon (custom config), SilkETW/SilkService |
| Log shipping | Winlogbeat |
| SIEM platform | HELK (Docker Compose, build 2: Kafka, KSQL, ELK 7.6.2, Nginx, ElastAlert) |
| Detection rules | Sigma-style detection logic, deployed as ElastAlert rules |
| Anomaly detection | Isolation Forest, LSTM Autoencoder (PyTorch) |
| Evaluation | scikit-learn (confusion matrix, ROC-AUC, F1) |
| Visualisation | Kibana, Matplotlib |
| Scripting | Python 3 (pandas, numpy, torch, sklearn) |

---

## 📊 Detection Coverage

- **12 MITRE ATT&CK techniques** emulated with Atomic Red Team tests across **6 tactics** (Execution, Defense Evasion, Persistence, Credential Access, Command and Control, Discovery).
- **18,943 endpoint events** evaluated in the controlled lab dataset: 15,201 malicious and 3,742 benign.
- **20 of 44 CISA-referenced LOLBins** applicable to a single-host lab were tested, and all were detected.
- 3 high-priority LOLBins (`ntdsutil.exe`, `vssadmin.exe`, `PsExec.exe`) require Active Directory infrastructure and are documented as future work.

### Techniques Covered (per-technique results)

| Technique ID | Name | Tactic | TPR | FPR | F1 | TP | FN |
|--------------|------|--------|-----|-----|----|----|----|
| T1059.001 | PowerShell | Execution | 100% | 0% | 1.00 | 147 | 0 |
| T1047 | Windows Management Instrumentation | Execution | 100% | 0% | 1.00 | 2 | 0 |
| T1059.005 | Visual Basic Script | Execution | 100% | 0% | 1.00 | 1 | 0 |
| T1218.011 | Rundll32 | Defense Evasion | 100% | 0% | 1.00 | 103 | 0 |
| T1218.010 | Regsvr32 | Defense Evasion | 100% | 0% | 1.00 | 2 | 0 |
| T1218.005 | Mshta | Defense Evasion | 100% | 0% | 1.00 | 1 | 0 |
| T1055.001 | DLL Injection | Defense Evasion | 100% | 0% | 1.00 | 1,378 | 0 |
| T1547.001 | Registry Run Keys | Persistence | 100% | 0% | 1.00 | 6,199 | 0 |
| T1053.005 | Scheduled Task | Persistence | 100% | 0% | 1.00 | 23 | 0 |
| T1003.001 | LSASS Memory | Credential Access | 100% | 0% | 1.00 | 7,341 | 0 |
| T1105 | Ingress Tool Transfer | Command and Control | 100% | 0% | 1.00 | 3 | 0 |
| T1046 | Network Service Scanning | Discovery | 100% | 0% | 1.00 | 1 | 0 |

Full evaluation output is in `lotl_metrics_terminal.png`.

---

## 🔎 Example Finding: SilkETW Telemetry in Kibana

Searching the `logs-endpoint-winevent-etw-*` index in Kibana for `telemetry.summary: dll_injection, network_conn` returned matching `rundll32` events. Each event was enriched with ATT&CK fields (`threat.framework`, `threat.tactic.id/name`, `threat.technique.id`) and detection fields (`detection.severity`, `detection.actions_needed`). The matches were mapped to **T1071.001 (Web Protocols), Command and Control**. This shows how ETW telemetry adds behavioural context (injection followed by network activity) that a single event source can miss.

---

## 📈 Results Summary

| Detector | TPR | Precision | F1 | ROC-AUC |
|----------|-----|-----------|----|---------|
| **Sigma/ElastAlert Rules** | 100% | 100% | 1.00 | 1.000* |
| **LSTM Autoencoder** | 50% | 93% | 0.65 | 0.709 |
| **Isolation Forest** | 15% | 82% | 0.26 | 0.568 |

\* AUC of 1.0 reflects the deterministic binary nature of rule-based detection in a controlled lab environment, not generalised real-world performance.

**Rule-based confusion matrix:** TP 15,201, FP 0, FN 0, TN 3,742 (accuracy 100%, F1 1.0).

**Key finding:** Isolation Forest's low recall (15%) shows empirically that LOTL techniques are designed to evade generic statistical anomaly detection. This supports IOA-centric, behaviour-aware Sigma rules as the primary detection layer, with ML as a complementary signal rather than a replacement.

- **False Positive Rate:** 0% across all 12 emulated techniques in the controlled lab environment.
- **Mean Time To Detect (MTTD):** Sub-second to low-second detection latency for rule-based alerts.

### Limitations

- Results come from a single-host, controlled lab, so they should not be read as real-world performance.
- Event counts are uneven across techniques. Registry Run Keys, LSASS memory access and DLL injection account for most malicious events, so aggregate metrics are weighted towards them. Per-technique results are shown for that reason.
- The ML detectors were evaluated on the same lab dataset and show clearly lower recall than the rules.

---

## 📁 Repository Structure

```
.
├── README.md
├── Sudha_project.pdf                  # Full thesis report (IT9115)
├── Lab_architecture.png               # 3-VM HELK lab architecture diagram
├── LOTL_taxonomy.png                  # LOLBins / LOLScripts / LOLLibs taxonomy
├── Attackbasedontactics.png           # Techniques grouped by ATT&CK tactic
├── Mitreattack coverage_compare.png   # Per-technique severity/tactic card grid
├── Confusion matrix.png               # Sigma detection confusion matrix
├── Model comparison.png               # Sigma vs LSTM vs Isolation Forest (TPR/Precision/F1)
├── ROCcurve.png                       # ROC curves for all three detectors
├── lotl_metrics_terminal.png          # Terminal output of the evaluation pipeline run
├── HELK_install.png                   # HELK Docker Compose build choice 2
├── winlog_input.png                   # Winlogbeat event log configuration
├── Atomicredteamclone_kali.png        # Atomic Red Team cloned on Kali
├── Winrm_kali.png                     # Remote execution check over WinRM
└── SilkETWfindings.png                # SilkETW findings in Kibana
```

> 📩 **Sigma rules and ElastAlert rule files are not committed to this public repository.** Detection rule logic is shared on request to avoid publishing tuned detection thresholds and lab-specific, evasion-relevant detail in a public index. Please reach out via the contact details on my GitHub profile.

---

## ⚖️ Legal, Ethical & Cultural Considerations

- All experiments were conducted in an isolated lab environment with no personal or production data.
- Telemetry sources (Sysmon, SilkETW) can capture command-line data containing usernames, file paths and URLs. This is handled under **Privacy Act 2020** principles: employee consent, data minimisation, and cross-border data transfer compliance for any cloud-hosted logging.
- This research respects **Te Tiriti o Waitangi** and Māori data sovereignty principles in its approach to data governance.
- ML-based alert prioritisation is kept auditable to avoid suppressing legitimate security events.
- Adversary emulation was run only against lab VMs I own, using a dedicated low-privilege test account.

---

## 🔭 Future Work

- Extend coverage to Active Directory–dependent LOLBins (`ntdsutil.exe`, `vssadmin.exe`, `PsExec.exe`) using a domain controller lab.
- Tune the LSTM detection threshold to improve recall without materially increasing false positives.
- Explore ensemble scoring that combines Sigma rule output with ML anomaly scores rather than treating them as independent layers.
- Multi-host telemetry to evaluate lateral movement detection.
- Compare the lab's per-technique results against vendor ATT&CK mappings, following the consistency analysis in Virkud et al.

---

## 📚 References

- A. Virkud, M. A. Inam, A. Riddle, J. Liu, G. Wang and A. Bates, "How does Endpoint Detection use the MITRE ATT&CK Framework?", *USENIX Security Symposium*, 2024.
- EDR-Telemetry project: https://www.edr-telemetry.com/windows
- MITRE ATT&CK: https://attack.mitre.org
- HELK (Hunting ELK) by Roberto Rodriguez: https://github.com/Cyb3rWard0g/HELK
- Atomic Red Team by Red Canary: https://github.com/redcanaryco/atomic-red-team

---

## 👩‍💻 Author

**Sudharshiya Ganesan**
Master of Information Technology — Whitecliffe, New Zealand
Supervised by Dr. Simon Yusuf Enoch
