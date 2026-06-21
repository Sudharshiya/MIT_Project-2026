# IOA-Based Detection Framework for Windows Living-Off-the-Land (LOTL) Techniques using Sysmon

> **IT9115 — Project Thesis**
> Sudharshiya Ganesan | Student ID: 20232004
> Master of Information Technology, Whitecliffe, New Zealand
> Supervised by: Dr. Simon Yusuf Enoch

---

## 📌 Overview

Living-off-the-Land (LOTL) attacks abuse legitimate Windows binaries (`powershell.exe`, `wmic.exe`, `rundll32.exe`, `certutil.exe`, etc.) to carry out malicious activity while blending into normal administrative behaviour. Because no new files are dropped, traditional **Indicator of Compromise (IOC)**-based detection — file hashes, static signatures — fails to catch these techniques.

This project designs, implements, and evaluates an **open-source, Indicator of Attack (IOA)-centric detection framework** that identifies LOTL techniques through behavioural telemetry rather than static signatures.

---

## 🎯 Problem Statement

- Adversaries increasingly rely on LOTL binaries (LOLBins) to evade EDR detection.
- Commercial EDR products implement only 48–55% of MITRE ATT&CK techniques.
- Default Windows logging provides limited visibility for behavioural (IOA) detection.
- Real-world incidents (e.g. the 2025 Qilin ransomware attack on Malaysia Airports) demonstrate the cost of inconsistent baselines and untuned EDR.

**Research question:** Can a dual-telemetry, open-source pipeline combining Sysmon, ETW, Sigma-style rules, and machine learning achieve high-fidelity LOTL detection without commercial tooling?

---

## 🧠 Architecture

```
Adversary Emulation Layer (Kali Linux / Atomic Red Team)
            │
            ▼
Telemetry Collection Layer (Sysmon + SilkETW — dual source)
            │
            ▼
Ingestion & Pre-processing Layer (Logstash → Elasticsearch)
            │
            ▼
Detection Layer
   ├── ElastAlert rules (IOA-centric, MITRE ATT&CK enriched)
   └── ML Anomaly Layer (LSTM Autoencoder + Isolation Forest)
            │
            ▼
Analysis & Validation Layer (Kibana dashboards, confusion matrix, ROC, MTTD)
```

**Core platform:** HELK (Hunting ELK) — chosen over standalone ELK for built-in Sigma/ATT&CK enrichment and Jupyter integration.

---

## 🛠️ Tools & Technologies

| Layer | Tool |
|---|---|
| Adversary emulation | Kali Linux, Atomic Red Team |
| Endpoint telemetry | Sysmon (custom config), SilkETW/SilkService |
| SIEM platform | HELK (Hunting ELK) |
| Detection rules | Sigma-style detection logic, deployed as ElastAlert rules |
| Anomaly detection | Isolation Forest, LSTM Autoencoder (PyTorch) |
| Evaluation | scikit-learn (confusion matrix, ROC-AUC, F1) |
| Visualisation | Kibana, Matplotlib |
| Scripting | Python 3 (pandas, numpy, torch, sklearn) |

---

## 📊 Detection Coverage

- **12 MITRE ATT&CK techniques** simulated across **5 tactics**, based on 11 Atomic Red Team test cases.
- **18,943 endpoint events** evaluated in the controlled lab dataset.
- **20 of 44 CISA-referenced LOLBins** applicable to a single-host lab were tested — all successfully detected.
- 3 high-priority LOLBins (`ntdsutil.exe`, `vssadmin.exe`, `PsExec.exe`) require Active Directory infrastructure and are documented as future work.

### Techniques Covered

| Technique ID | Name | Tactic |
|---|---|---|
| T1059.001 | PowerShell (Encoded Command) | Execution |
| T1047 | Windows Management Instrumentation | Execution |
| T1218.011 | Rundll32 | Defense Evasion |
| T1218.010 | Regsvr32 (Squiblydoo) | Defense Evasion |
| T1547.001 | Registry Run Keys | Persistence |
| T1053.005 | Scheduled Task | Persistence |
| T1003.001 | LSASS Memory Access | Credential Access |
| T1003.003 | NTDS Credential Dumping | Credential Access |
| T1490 | Inhibit System Recovery (VSS) | Impact |
| T1105 | Ingress Tool Transfer (Certutil) | Command & Control |
| T1059.005 | Visual Basic Script | Execution |
| T1218.005 | Mshta | Defense Evasion |
| T1197 | BITS Jobs | Persistence |

---

## 📈 Results Summary

| Detector | TPR | Precision | F1 | ROC-AUC |
|---|---|---|---|---|
| **Sigma/ElastAlert Rules** | 100% | 100% | 1.00 | 1.000* |
| **LSTM Autoencoder** | 50% | 93% | 0.65 | 0.709 |
| **Isolation Forest** | 15% | 82% | 0.26 | 0.568 |

\* AUC of 1.0 reflects the deterministic binary nature of rule-based detection in a controlled lab environment, not generalised real-world performance.

**Key finding:** Isolation Forest's low recall (15%) empirically demonstrates that LOTL techniques are specifically designed to evade generic statistical anomaly detection — reinforcing the case for IOA-centric, behaviour-aware Sigma rules as the primary detection layer, with ML as a complementary signal rather than a replacement.

- **False Positive Rate:** 0% across all 12 simulated techniques in the controlled lab environment.
- **Mean Time To Detect (MTTD):** Sub-second to low-second detection latency for rule-based alerts.

---

## 📁 Repository Structure
.
├── README.md
├── Sudha_project.pdf                    # Full thesis report (IT9115)
├── Lab_architecture.png                 # 3-VM HELK lab architecture diagram
├── LOTL_taxonomy.png                    # LOLBins / LOLScripts / LOLLibs taxonomy
├── Attackbasedontactics.png             # Techniques grouped by ATT&CK tactic
├── Mitreattack_coverage_compare.png     # Per-technique severity/tactic card grid
├── Confusion_matrix.png                 # Sigma detection confusion matrix
├── Model comparison.png                 # Sigma vs LSTM vs Isolation Forest — TPR/Precision/F1
├── ROCcurve.png                         # ROC curves for all three detectors
└── lotl_metrics_terminal.png            # Terminal output of the evaluation pipeline run


> 📩 **Sigma rules and ElastAlert rule files are not committed to this public repository.** Detection rule logic is shared on request to avoid publishing tuned detection thresholds and lab-specific evasion-relevant detail in a public index. Please reach out via the contact details on my GitHub profile.

---

## ⚖️ Legal, Ethical & Cultural Considerations

- All experiments were conducted in an isolated lab environment with no personal or production data.
- Telemetry sources (Sysmon, SilkETW) can capture command-line data containing usernames, file paths, and URLs — handled here under **Privacy Act 2020** principles: employee consent, data minimisation, and cross-border data transfer compliance for any cloud-hosted logging.
- This research respects **Te Tiriti o Waitangi** and Māori data sovereignty principles in its approach to data governance.
- ML-based alert prioritisation is kept auditable to avoid suppressing legitimate security events.

---

## 🔭 Future Work

- Extend coverage to Active Directory–dependent LOLBins (`ntdsutil.exe`, `vssadmin.exe`, `PsExec.exe`) using a domain controller lab.
- Tune the LSTM detection threshold to improve recall without materially increasing false positives.
- Explore ensemble scoring that combines Sigma rule output with ML anomaly scores rather than treating them as independent layers.
- Multi-host telemetry to evaluate lateral movement detection.

---

## 👩‍💻 Author

**Sudharshiya Ganesan**
Master of Information Technology — Whitecliffe, New Zealand
Supervised by Dr. Simon Yusuf Enoch
