import Link from "next/link";

const sampleResult = {
  cve: {
    id: "CVE-2021-44228",
    description: "Apache Log4j2 remote code execution vulnerability."
  },
  target: {
    statusCode: 200,
    tlsOk: true,
    findings: []
  },
  verdict: "Baseline defensive checks passed."
};

export default function PreviewPage() {
  return (
    <main className="container">
      <h1>Aegis UI Preview</h1>
      <p>Visual preview for layout and dark theme validation before production deployment.</p>

      <section className="panel">
        <div className="grid">
          <div>
            <label>CVE ID</label>
            <input value="CVE-2021-44228" readOnly />
          </div>
          <div>
            <label>Target URL</label>
            <input value="https://example.com" readOnly />
          </div>
        </div>

        <div style={{ marginTop: "1rem" }}>
          <label>Authorized Hosts (one hostname per line)</label>
          <textarea value={"example.com\nlocalhost"} readOnly />
        </div>

        <button disabled type="button">
          Run Production Check
        </button>
      </section>

      <section className="panel" style={{ marginTop: "1rem" }}>
        <h2>Result Preview</h2>
        <pre className="result">{JSON.stringify(sampleResult, null, 2)}</pre>
      </section>

      <section className="panel" style={{ marginTop: "1rem" }}>
        <h2>Next Steps</h2>
        <ul>
          <li>Use this route to validate UI spacing and contrast quickly.</li>
          <li>Use the live console for real checks against authorized targets.</li>
        </ul>
        <p style={{ marginTop: "1rem" }}>
          <Link href="/">Open Live Console</Link>
        </p>
      </section>
    </main>
  );
}
