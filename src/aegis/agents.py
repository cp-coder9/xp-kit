from __future__ import annotations

import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from .models import CVEMetadata, TargetCheckResult


class Collector:
    """Fetches CVE details from NVD."""

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def run(self, cve_id: str) -> CVEMetadata:
        response = httpx.get(self.NVD_API, params={"cveId": cve_id}, timeout=30)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            raise ValueError(f"No vulnerability record found for {cve_id}")

        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        en = next((d for d in descriptions if d.get("lang") == "en"), {})
        refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        return CVEMetadata(
            cve_id=cve.get("id", cve_id),
            published=_parse_dt(cve.get("published")),
            last_modified=_parse_dt(cve.get("lastModified")),
            description=en.get("value", ""),
            references=refs,
        )


class Researcher:
    """Produces defensive verification guidance from CVE metadata."""

    def run(self, cve: CVEMetadata) -> str:
        return (
            f"Validate whether exposed component versions related to {cve.cve_id} are still deployed. "
            "Confirm patch status, monitor logs for exploitation indicators, and enforce layered mitigations "
            "(WAF rules, input validation, least privilege, and rapid patching)."
        )


class Validator:
    """Performs real, non-intrusive target checks."""

    REQUIRED_HEADERS = [
        "content-security-policy",
        "x-content-type-options",
        "strict-transport-security",
    ]

    def run(self, target_url: str) -> TargetCheckResult:
        findings: list[str] = []
        parsed = urlparse(target_url)

        https_ok = False
        if parsed.scheme == "https":
            https_ok = _check_tls_valid(parsed.hostname or "")
            if not https_ok:
                findings.append("TLS certificate check failed or certificate appears invalid.")
        else:
            findings.append("Target is not HTTPS.")

        headers: dict[str, str] = {}
        status_code = None
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            resp = client.get(target_url)
            status_code = resp.status_code
            headers = {k.lower(): v for k, v in resp.headers.items()}

        for header in self.REQUIRED_HEADERS:
            if header not in headers:
                findings.append(f"Missing security header: {header}")

        return TargetCheckResult(
            url=target_url,
            https_ok=https_ok,
            security_headers=headers,
            status_code=status_code,
            findings=findings,
        )


class Judge:
    """Determines whether defensive baseline checks pass."""

    def run(self, target_result: TargetCheckResult) -> tuple[bool, str]:
        if target_result.findings:
            return False, "Needs remediation: " + "; ".join(target_result.findings)
        return True, "Baseline defensive checks passed."


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)


def _check_tls_valid(host: str) -> bool:
    if not host:
        return False
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(__import__("socket").create_connection((host, 443), timeout=8), server_hostname=host) as sock:
        cert = sock.getpeercert()
    return bool(cert)
