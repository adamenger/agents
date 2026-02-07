from __future__ import annotations

import sys
from abc import ABC, abstractmethod

from .models import DomainEvaluation, RunStats, ThreatLevel
from .yaml_config import get_output_strings


class OutputHandler(ABC):
    @abstractmethod
    def emit_summary(self, evaluations: list[DomainEvaluation], stats: RunStats) -> None: ...

    @abstractmethod
    def emit_alert(self, evaluation: DomainEvaluation) -> None: ...


class StdoutHandler(OutputHandler):
    def emit_summary(self, evaluations: list[DomainEvaluation], stats: RunStats) -> None:
        strings = get_output_strings()
        print(strings["summary_header"])
        print(strings["stats_template"].format(**stats.model_dump()))

        threats = [e for e in evaluations if e.threat_level != ThreatLevel.BENIGN]
        if not threats:
            print(strings["no_threats_message"])
        else:
            print(f"Non-benign domains ({len(threats)}):")
            for ev in sorted(threats, key=lambda e: -e.confidence):
                print(
                    f"  [{ev.threat_level.upper():10s}] (conf: {ev.confidence:3d}) "
                    f"{ev.domain} -- {ev.reasoning}"
                )
                if ev.indicators:
                    print(f"             indicators: {', '.join(ev.indicators)}")

        print(strings["summary_footer"])

    def emit_alert(self, evaluation: DomainEvaluation) -> None:
        strings = get_output_strings()
        print(
            f"{strings['alert_prefix']} {evaluation.threat_level.upper()} "
            f"domain: {evaluation.domain} (confidence: {evaluation.confidence}) "
            f"-- {evaluation.reasoning}",
            file=sys.stderr,
        )
