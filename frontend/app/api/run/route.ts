import { NextRequest, NextResponse } from "next/server";
import { ensureAuthorized, fetchCve, runTargetChecks, validateRequest } from "@/lib/aegis";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const payload = validateRequest(body);

    ensureAuthorized(payload.targetUrl, payload.allowlist);
    const cve = await fetchCve(payload.cveId);
    const target = await runTargetChecks(payload.targetUrl);

    const verdict = target.findings.length === 0 ? "Baseline defensive checks passed." : `FAIL: ${target.findings.join("; ")}`;

    return NextResponse.json({ cve, target, verdict });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
