# Product Requirements Document (PRD)
## Project Aegis — Defensive Production Edition

### 1. Executive Summary
Project Aegis is a multi-agent AI workflow for **defensive CVE verification** on explicitly authorized assets. It accepts a CVE ID and a target URL, retrieves authoritative CVE metadata, performs non-intrusive live checks, and returns remediation guidance.

### 2. Scope and Safety Model
- No exploit generation, payload crafting, or exploit automation.
- No simulation/mocks in runtime path.
- Real-world checks only against allowlisted ethical targets.
- No Docker requirement.

### 3. Agents
1. Collector (online): fetches CVE metadata from NVD.
2. Researcher (offline reasoning): converts CVE context into defensive verification guidance.
3. Validator (online, non-intrusive): performs TLS and security-header baseline checks.
4. Judge (offline): declares pass/fail and remediation summary.

### 4. Functional Requirements
- Input: CVE ID + target URL.
- Policy Gate: target must be in allowlist.
- Output: structured verdict with concrete findings.

### 5. Non-Functional Requirements
- Production-safe defaults.
- Deterministic validation steps.
- Operator-friendly dark-themed terminal UX.
