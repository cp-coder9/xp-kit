import { z } from "zod";
import tls from "node:tls";

const requestSchema = z.object({
  cveId: z.string().regex(/^CVE-\d{4}-\d{4,}$/i),
  targetUrl: z.string().url(),
  authorizationTicket: z.string().min(3)
});

export type AegisRequest = z.infer<typeof requestSchema>;

export function validateRequest(payload: unknown): AegisRequest {
  return requestSchema.parse(payload);
}

export function parseAuthorizedHostsFromEnv(): string[] {
  const configured = process.env.AEGIS_AUTHORIZED_HOSTS ?? "";
  const hosts = configured
    .split(",")
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);

  if (hosts.length === 0) {
    throw new Error("Server policy missing: set AEGIS_AUTHORIZED_HOSTS env variable.");
  }

  return hosts;
}

export function ensureAuthorized(targetUrl: string, allowlist: string[]) {
  const host = new URL(targetUrl).hostname.toLowerCase();
  if (!allowlist.includes(host)) {
    throw new Error(`Target host '${host}' is not authorized.`);
  }
}

export async function fetchCve(cveId: string) {
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("cveId", cveId);

  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`NVD request failed with ${response.status}`);
  }

  const data = (await response.json()) as {
    vulnerabilities?: Array<{ cve?: { id?: string; descriptions?: Array<{ lang?: string; value?: string }> } }>;
  };

  const cve = data.vulnerabilities?.[0]?.cve;
  if (!cve?.id) {
    throw new Error(`No CVE record found for ${cveId}`);
  }

  const description = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";
  return { id: cve.id, description };
}

export async function runTargetChecks(targetUrl: string) {
  const url = new URL(targetUrl);
  const findings: string[] = [];

  let tlsOk = false;
  if (url.protocol === "https:") {
    tlsOk = await checkTls(url.hostname);
    if (!tlsOk) {
      findings.push("TLS certificate validation failed.");
    }
  } else {
    findings.push("Target URL is not HTTPS.");
  }

  const response = await fetch(targetUrl, { redirect: "follow", cache: "no-store" });
  const requiredHeaders = ["content-security-policy", "x-content-type-options", "strict-transport-security"];

  for (const header of requiredHeaders) {
    if (!response.headers.get(header)) {
      findings.push(`Missing security header: ${header}`);
    }
  }

  return {
    statusCode: response.status,
    tlsOk,
    findings
  };
}

function checkTls(hostname: string): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = tls.connect(443, hostname, { servername: hostname, rejectUnauthorized: true }, () => {
      resolve(socket.authorized);
      socket.end();
    });

    socket.setTimeout(8000, () => {
      socket.destroy();
      resolve(false);
    });

    socket.on("error", () => resolve(false));
  });
}
