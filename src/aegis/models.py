from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class CVEMetadata(BaseModel):
    cve_id: str
    published: datetime | None = None
    last_modified: datetime | None = None
    description: str = ""
    references: list[HttpUrl] = Field(default_factory=list)


class TargetCheckResult(BaseModel):
    url: HttpUrl
    https_ok: bool
    security_headers: dict[str, str]
    status_code: int | None
    findings: list[str] = Field(default_factory=list)


class RunState(BaseModel):
    stage: Literal["collector", "researcher", "validator", "judge", "done"] = "collector"
    cve: CVEMetadata | None = None
    target_result: TargetCheckResult | None = None
    verdict: str | None = None
