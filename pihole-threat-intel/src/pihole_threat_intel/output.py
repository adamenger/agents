from __future__ import annotations

import smtplib
import sys
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader

from .models import DomainEvaluation, RunStats, ThreatLevel
from .yaml_config import get_output_strings

log = structlog.get_logger()


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


class EmailHandler(OutputHandler):
    def __init__(self, smtp_host: str, smtp_port: int, sender: str, recipients: list[str]) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients
        template_dir = Path(__file__).parent / "templates"
        self.env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)

    def _render(self, evaluations: list[DomainEvaluation], stats: RunStats) -> str:
        template = self.env.get_template("report.html")
        threats = sorted(
            [e for e in evaluations if e.threat_level != ThreatLevel.BENIGN],
            key=lambda e: -e.confidence,
        )
        benign = [e for e in evaluations if e.threat_level == ThreatLevel.BENIGN]
        return template.render(
            stats=stats,
            threats=threats,
            benign=benign,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        )

    def _send(self, subject: str, html_body: str) -> None:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.sendmail(self.sender, self.recipients, msg.as_string())
        log.info("email_sent", recipients=self.recipients)

    def emit_summary(self, evaluations: list[DomainEvaluation], stats: RunStats) -> None:
        subject = f"PiHole Threat Intel — {stats.malicious_count} malicious, {stats.suspicious_count} suspicious"
        html = self._render(evaluations, stats)
        self._send(subject, html)

    def emit_alert(self, evaluation: DomainEvaluation) -> None:
        # Individual alerts handled in summary email
        pass
