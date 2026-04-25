from __future__ import annotations

from .agents import Collector, Judge, Researcher, Validator
from .models import RunState
from .policy import assert_target_authorized, load_authorization_reference, load_authorized_targets


class AegisOrchestrator:
    def __init__(self) -> None:
        self.collector = Collector()
        self.researcher = Researcher()
        self.validator = Validator()
        self.judge = Judge()

    def run(self, cve_id: str, target_url: str, scope_file: str) -> RunState:
        state = RunState(stage="collector")

        allowed = load_authorized_targets(scope_file)
        _ = load_authorization_reference(scope_file)
        assert_target_authorized(target_url, allowed)

        state.cve = self.collector.run(cve_id)
        state.stage = "researcher"
        _ = self.researcher.run(state.cve)

        state.stage = "validator"
        state.target_result = self.validator.run(target_url)

        state.stage = "judge"
        success, verdict = self.judge.run(state.target_result)
        state.verdict = verdict if success else f"FAIL: {verdict}"

        state.stage = "done"
        return state
