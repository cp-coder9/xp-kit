# Project Aegis (Defensive, Production) - Tasks

## Phase 1: Foundation
- [x] Initialize Python project and package structure.
- [x] Configure production dependencies (HTTP client, validation, CLI policy).
- [x] Define a global typed state model for agent handoff.

## Phase 2: Agent Implementation
- [x] Collector: pull CVE metadata from NVD 2.0 API.
- [x] Researcher: generate defensive verification guidance from CVE details.
- [x] Validator: execute non-intrusive real-world checks (TLS + HTTP security header baseline).
- [x] Judge: decide pass/fail and provide remediation summary.

## Phase 3: Orchestration
- [x] Implement orchestrator state progression (collector → researcher → validator → judge).
- [x] Enforce ethical targeting policy via explicit hostname allowlist.
- [x] Build dark-themed CLI surface for operators.

## Phase 4: Frontend Console (Next.js)
- [x] Create Next.js App Router project in `frontend/`.
- [x] Build dark-themed operator dashboard with CVE/Target/Allowlist inputs.
- [x] Implement `/api/run` server route for real-time CVE + target checks.
- [x] Return structured results and pass/fail verdict to the UI.
- [x] Add a dedicated `/preview` route with realistic UI mock plus `npm run preview` for production-like visual verification.

## Phase 5: Hardening & Operations
- [ ] Add retry/backoff and API quota handling for NVD requests.
- [ ] Add structured logging and SIEM-forwardable JSON outputs.
- [ ] Extend validator checks (TLS versions, cert expiry threshold, exposed admin paths, CSP quality).
- [ ] Integrate ticketing output (Jira/ServiceNow) for remediation workflows.
