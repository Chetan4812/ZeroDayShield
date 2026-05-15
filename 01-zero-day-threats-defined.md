# Zero-Day Threats: A Complete Technical Definition

> **For AI Engineers** — This document establishes the foundational vocabulary and threat taxonomy required before building any LLM-based zero-day detection or patching system.

---

## What Is a Zero-Day Threat?

A **zero-day vulnerability** (also written 0-day) is a security flaw in software, hardware, or firmware that is **unknown to the vendor responsible for fixing it**. The term "zero-day" refers to the number of days the developer has had to address the issue — zero, because the vendor has not yet been made aware of it and no patch exists at the time of discovery or exploitation.

A **zero-day exploit** is the attack vector — the specific piece of code or technique — that weaponizes this undiscovered vulnerability to compromise a system.

A **zero-day attack** is the full incident: an adversary discovers or acquires the exploit and deploys it against a target before any defensive countermeasure exists.

The lifecycle of a zero-day threat has five distinct stages:

1. **Introduction** — A software developer unknowingly writes code containing a security flaw.
2. **Discovery** — A threat actor (or sometimes a researcher) finds the vulnerability.
3. **Weaponization** — The threat actor builds an exploit for the flaw.
4. **Active exploitation** — Attacks are launched; victims have no patch to apply.
5. **Disclosure & patching** — The vendor learns of the issue, develops a fix, and releases it; the vulnerability is no longer "zero-day."

---

## Zero-Day vs. Other Threat Types

A zero-day is often confused with related but distinct security terms. The table below clarifies the key differences:

| Threat Type | Vendor Aware? | Patch Available? | Signature Available? | Window of Danger |
|---|---|---|---|---|
| **Zero-Day** | No | No | No | Days to months (or years) |
| **N-Day (Known CVE)** | Yes | Yes or pending | Often yes | Until patch is applied |
| **Unpatched Known Vuln** | Yes | Yes | Yes | Until admin applies patch |
| **Logic Bug / Misconfiguration** | Maybe | Custom fix | Rare | Until fixed |
| **Social Engineering** | N/A | N/A | N/A | Ongoing |

The defining characteristic of a zero-day is the **asymmetry of knowledge**: the attacker knows about the flaw while the defender does not. This makes behavioral and anomaly-based detection the only viable defense during the exploitation window, because signature-based tools have nothing to match against.

---

## The Anatomy of a Zero-Day Attack Chain

Understanding the internal mechanics is essential for designing a detection or patching LLM.

```
┌──────────────────────────────────────────────────────────────────┐
│  THREAT ACTOR                                                    │
│                                                                  │
│  Reconnaissance → Vulnerability Discovery → Exploit Development │
│       ↓                                                          │
│  Weaponized Payload (zero-day exploit)                          │
│       ↓                                                          │
│  Delivery (phishing, watering hole, supply chain, etc.)         │
│       ↓                                                          │
│  Execution on Target → Lateral Movement → Exfiltration/Damage   │
└──────────────────────────────────────────────────────────────────┘
```

At no point in this chain does a conventional antivirus or IDS signature fire, because the vulnerability and its exploit are not yet in any threat database.

---

## Types of Zero-Day Vulnerabilities

Zero-days occur across all layers of the technology stack:

- **Memory corruption**: Buffer overflows, use-after-free, heap spraying — the most common in native code (C/C++).
- **Logic flaws**: Authentication bypasses, race conditions, or improper state management.
- **Input validation failures**: SQL injection, command injection, path traversal in unvalidated parameters.
- **Cryptographic weaknesses**: Incorrect implementations, weak key derivation, or protocol flaws.
- **Supply chain vulnerabilities**: Compromise embedded in third-party libraries or build toolchains.
- **Hardware-level flaws**: Microarchitectural attacks (e.g., Spectre/Meltdown class) that affect CPUs.

Each type generates a different pattern in system logs, network traffic, and memory telemetry — and each requires a different kind of patch response.

---

## Real-World Zero-Day Examples

| CVE / Name | Year | Target | Impact |
|---|---|---|---|
| EternalBlue (CVE-2017-0144) | 2017 | Windows SMB | Enabled WannaCry ransomware globally |
| Log4Shell (CVE-2021-44228) | 2021 | Apache Log4j | Remote code execution in millions of Java apps |
| MOVEit Transfer (CVE-2023-34362) | 2023 | File transfer software | Mass data theft from hundreds of organizations |
| Citrix Bleed (CVE-2023-4966) | 2023 | Citrix NetScaler | Session token theft at scale |
| FortiGate (CVE-2024-21762) | 2024 | Fortinet SSL-VPN | Remote code execution by state actors |

In 2025, Google's Threat Intelligence Group tracked **90 zero-day vulnerabilities** actively exploited in the wild — reflecting a continuing upward trend in attack sophistication and frequency.

---

## The "Zero-Day Window" Problem

The most dangerous phase is the time between when a vulnerability is first exploited by an adversary and when a patch is deployed by defenders. This window has historically ranged from days to months, with some high-value vulnerabilities being silently exploited for years before public discovery. Key contributors to a long window include:

- Complex codebases where the flaw is difficult to locate.
- Limited threat intelligence sharing between organizations.
- Slow vendor response or patch testing cycles.
- Gaps between patch release and patch deployment across enterprise systems.

This is precisely the window where an AI-assisted patching agent creates the most business value — by compressing analysis-to-remediation time from weeks to hours.

---

## Key Terminology Reference for AI Engineers

| Term | Definition |
|---|---|
| **CVE** | Common Vulnerabilities and Exposures — a standardized identifier (e.g., CVE-2023-34362) for known vulnerabilities |
| **CWE** | Common Weakness Enumeration — a taxonomy of software weakness types (e.g., CWE-79: XSS) |
| **CVSS Score** | Common Vulnerability Scoring System — numeric severity score (0–10) |
| **MITRE ATT&CK** | A knowledge base of adversary tactics, techniques, and procedures (TTPs) |
| **IOC** | Indicator of Compromise — observable artifact (IP, hash, URL) associated with a known attack |
| **TTP** | Tactic, Technique, and Procedure — attacker's behavioral pattern |
| **EDR/XDR** | Endpoint/Extended Detection & Response — behavior-based detection tools |
| **CVSS Vector** | A string encoding severity dimensions: AV, AC, PR, UI, S, C, I, A |
| **Patch** | A code-level fix addressing the root cause of a vulnerability |
| **Virtual Patch** | A runtime rule (WAF, IPS) that blocks exploitation without modifying source code |

---

## Why This Matters for an LLM-Based System

An LLM fine-tuned for zero-day threat patching must internalize this taxonomy deeply:

- It needs to parse raw threat logs, anomaly alerts, and CVE descriptions.
- It must map observed behaviors to MITRE ATT&CK TTPs.
- It must infer likely vulnerability classes (CWE) even without a CVE identifier.
- It must reason about patch strategies — code-level fix, virtual patch, or configuration change — given the vulnerability type and affected layer.

The following documents (02 and 03) address the business problem, solution architecture, and implementation.
