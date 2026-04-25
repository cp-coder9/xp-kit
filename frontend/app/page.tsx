"use client";

import { FormEvent, useState } from "react";

type ApiResponse = {
  cve?: { id: string; description: string };
  target?: { statusCode: number; tlsOk: boolean; findings: string[] };
  verdict?: string;
  authorizationTicket?: string;
  error?: string;
};

export default function HomePage() {
  const [cveId, setCveId] = useState("CVE-2021-44228");
  const [targetUrl, setTargetUrl] = useState("https://example.com");
  const [authorizationTicket, setAuthorizationTicket] = useState("ENG-2026-001");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ApiResponse | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setResult(null);

    const response = await fetch("/api/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cveId, targetUrl, authorizationTicket })
    });

    const data = (await response.json()) as ApiResponse;
    setResult(data);
    setLoading(false);
  }

  return (
    <main className="container">
      <h1>Aegis Defensive Console</h1>
      <p>Authorized, real-world CVE verification with non-intrusive checks.</p>
      <p>
        Server-side allowlist enforcement is enabled through <code>AEGIS_AUTHORIZED_HOSTS</code>. Provide your engagement
        authorization ticket below.
      </p>

      <section className="panel">
        <form onSubmit={onSubmit}>
          <div className="grid">
            <div>
              <label htmlFor="cve">CVE ID</label>
              <input id="cve" value={cveId} onChange={(e) => setCveId(e.target.value)} required />
            </div>
            <div>
              <label htmlFor="target">Target URL</label>
              <input id="target" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} required />
            </div>
          </div>

          <div style={{ marginTop: "1rem" }}>
            <label htmlFor="ticket">Authorization Ticket / Scope Reference</label>
            <input id="ticket" value={authorizationTicket} onChange={(e) => setAuthorizationTicket(e.target.value)} required />
          </div>

          <button disabled={loading} type="submit">
            {loading ? "Running checks..." : "Run Production Check"}
          </button>
        </form>
      </section>

      {result && (
        <section className="panel" style={{ marginTop: "1rem" }}>
          <h2>Result</h2>
          <pre className="result">{JSON.stringify(result, null, 2)}</pre>
        </section>
      )}
    </main>
  );
}
