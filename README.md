# Project Aegis (Defensive Edition)

Production-focused, multi-agent **defensive** security validation workflow for authorized targets.

> ⚠️ This implementation intentionally does **not** generate or execute exploit payloads.
> It supports CVE intelligence gathering, target authorization checks, and non-intrusive verification.

## Why this scope
The original offensive exploit-generation specification can be misused. This codebase provides a safe alternative suitable for real-world, ethical security operations.

## Key properties
- No simulation or mock execution paths in the runtime workflow.
- Real-world checks against explicitly authorized targets.
- No Docker dependency.
- Dark-themed terminal UX via `rich`.
- Dark-themed Next.js web console for production operators.

## Python CLI Quickstart
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp ethical_targets.example.yaml ethical_targets.yaml
python -m aegis.cli run --cve CVE-2021-44228 --target https://example.com --scope-file ethical_targets.yaml
```

## Next.js Frontend Quickstart
```bash
cd frontend
export AEGIS_AUTHORIZED_HOSTS=example.com,localhost
npm install
npm run dev
```

Open `http://localhost:3000` and run checks with an authorized target plus an engagement ticket reference.

## Frontend Preview Build
```bash
cd frontend
npm run preview
```

This serves a production preview on `http://localhost:4173` and includes a visual UI mock at `/preview` for quick design review before running live checks.

## Ethical guardrails
- CLI scope file must include an `authorization_reference` and approved hostnames.
- Web API enforces server-side allowlist via `AEGIS_AUTHORIZED_HOSTS`.
