import { NextRequest, NextResponse } from "next/server";
import { ensureAuthorized, fetchCve, parseAuthorizedHostsFromEnv, runTargetChecks, validateRequest } from "@/lib/aegis";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const payload = validateRequest(body);

    const allowlist = parseAuthorizedHostsFromEnv();
    ensureAuthorized(payload.targetUrl, allowlist);
    const cve = await fetchCve(payload.cveId);
    const target = await runTargetChecks(payload.targetUrl);

    const verdict = target.findings.length === 0 ? "Baseline defensive checks passed." : `FAIL: ${target.findings.join("; ")}`;

    return NextResponse.json({ cve, target, verdict, authorizationTicket: payload.authorizationTicket });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
