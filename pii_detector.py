"""
pii_detector.py

The PII Parsing and Analysis Layer described in Sections 3.5.1 and 3.4.2
(the "PII ANALYZER / Microsoft Presidio" block in the sequence diagram).

Implements the two-tier hybrid detection strategy from Objective 1:

  Tier 1 - Deterministic Regular Expressions (Ghiasvand & Ciorba, 2017)
           Fast, structured-field extraction: IPv4 addresses, MAC
           addresses, email addresses, and port numbers appearing in
           key=value / key: value telemetry fields.

  Tier 2 - NLP / Named Entity Recognition (Mainetti & Elia, 2025)
           For free-text payloads (alert messages, HTTP headers, error
           strings) where sensitive identifiers are not in a fixed
           format. This module attempts to use Microsoft's Presidio
           AnalyzerEngine (spaCy-backed NER) if a spaCy model is
           available, and otherwise falls back to a lightweight,
           heuristic NER recognizer that targets the same entity types
           (usernames, hostnames, person names) using contextual
           regex patterns.

Both tiers return a common `PIIMatch` record so results can be merged,
de-duplicated, and handed to the anonymization engine for field-aware
redaction (Section 3.5.1: "... mapped directly to active privacy
classification arrays ... before any downstream data transformation").
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


# ----------------------------------------------------------------------
# Common result type
# ----------------------------------------------------------------------
@dataclass
class PIIMatch:
    start: int
    end: int
    entity_type: str   # "IP_ADDRESS", "MAC_ADDRESS", "EMAIL", "PORT",
                        # "USERNAME", "HOSTNAME", "PERSON", "TIMESTAMP"
    text: str
    score: float = 1.0
    source: str = "regex"  # "regex" or "ner"

    def __repr__(self) -> str:  # pragma: no cover - debugging convenience
        return (f"PIIMatch({self.entity_type}, "
                f"'{self.text}', [{self.start}:{self.end}], "
                f"source={self.source}, score={self.score})")


# ----------------------------------------------------------------------
# Tier 1: Deterministic Regex recognizers (Section 3.5.1)
# ----------------------------------------------------------------------
class RegexPIIDetector:
    """
    Pattern-matches structured PII fields that follow strict,
    predictable formatting rules -- IPv4 addresses, MAC addresses,
    email addresses, and port numbers appearing in key=value pairs
    typical of Syslog / NetFlow telemetry (Sarhan et al., 2021).
    """

    IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
    )

    MAC = re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
    )

    EMAIL = re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    )

    # Matches "port=443", "dst_port: 51422", "sport 22", etc.
    PORT_CONTEXT = re.compile(
        r"\b(?:src_?port|dst_?port|s_?port|d_?port|port)\s*[=:]?\s*"
        r"(\d{1,5})\b",
        re.IGNORECASE,
    )

    # ISO-8601-ish timestamps, e.g. 2026-06-15T10:23:45(.123)(Z)
    TIMESTAMP = re.compile(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"
    )

    def analyze(self, text: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []

        for m in self.MAC.finditer(text):
            matches.append(PIIMatch(m.start(), m.end(), "MAC_ADDRESS", m.group(), source="regex"))

        for m in self.IPV4.finditer(text):
            matches.append(PIIMatch(m.start(), m.end(), "IP_ADDRESS", m.group(), source="regex"))

        for m in self.EMAIL.finditer(text):
            matches.append(PIIMatch(m.start(), m.end(), "EMAIL", m.group(), source="regex"))

        for m in self.TIMESTAMP.finditer(text):
            matches.append(PIIMatch(m.start(), m.end(), "TIMESTAMP", m.group(), source="regex"))

        for m in self.PORT_CONTEXT.finditer(text):
            # Only the numeric group is the sensitive value; capture
            # its exact span within the overall match.
            num = m.group(1)
            num_start = m.start(1)
            num_end = m.end(1)
            matches.append(PIIMatch(num_start, num_end, "PORT", num, source="regex"))

        return matches


# ----------------------------------------------------------------------
# Tier 2: NLP / NER recognizers (Section 3.5.1, 3.5.3)
# ----------------------------------------------------------------------
class BaseNERRecognizer:
    """Common interface for Tier-2 free-text entity recognition."""

    name = "base"

    def analyze(self, text: str) -> list[PIIMatch]:  # pragma: no cover - interface
        raise NotImplementedError


class PresidioNERRecognizer(BaseNERRecognizer):
    """
    Wraps Microsoft's Presidio AnalyzerEngine (presidio-analyzer +
    spaCy), as specified in Section 3.5.3 / the dependency matrix
    (presidio-analyzer v2.2.35).

    Requires a spaCy language model (e.g. en_core_web_lg) to be
    installed locally. If the model/engine cannot be loaded -- e.g. in
    an offline environment -- construction raises RuntimeError, and
    `build_ner_recognizer()` falls back to HeuristicNERRecognizer.
    """

    name = "presidio"

    # Map Presidio's default entity labels onto this project's taxonomy.
    ENTITY_MAP = {
        "PERSON": "PERSON",
        "EMAIL_ADDRESS": "EMAIL",
        "IP_ADDRESS": "IP_ADDRESS",
        "LOCATION": "LOCATION",
        "URL": "URL",
        "DATE_TIME": "TIMESTAMP",
    }

    def __init__(self, language: str = "en"):
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("presidio_analyzer not installed") from exc

        try:
            # This will raise (or, if no spaCy model is registered,
            # call sys.exit() internally -> SystemExit) for `language`.
            self.engine = AnalyzerEngine()
        except SystemExit as exc:
            raise RuntimeError("presidio_analyzer has no usable spaCy model") from exc

        self.language = language

    def analyze(self, text: str) -> list[PIIMatch]:
        results = self.engine.analyze(text=text, language=self.language)
        matches = []
        for r in results:
            entity_type = self.ENTITY_MAP.get(r.entity_type, r.entity_type)
            matches.append(PIIMatch(
                r.start, r.end, entity_type, text[r.start:r.end],
                score=r.score, source="ner",
            ))
        return matches


class HeuristicNERRecognizer(BaseNERRecognizer):
    """
    Lightweight, dependency-free fallback for Tier 2 when no spaCy
    model is available (e.g. offline development/sandbox use).

    Targets the same entity categories Presidio would surface for this
    domain -- usernames, hostnames, and person names embedded in
    free-text alert/log messages -- using contextual regex patterns
    rather than statistical NER.

    NOTE: this is a *fallback*, not a replacement. On a machine with
    internet access, install spaCy + a language model
    (`python -m spacy download en_core_web_lg`) and
    `build_ner_recognizer()` will automatically prefer
    PresidioNERRecognizer instead.
    """

    name = "heuristic"

    # "user=jdoe", "username: alice.smith", "for user bob123"
    USERNAME = re.compile(
        r"\b(?:user(?:name)?|uid|acct(?:ount)?)\s*[=:]?\s+"
        r"(?:for\s+)?([A-Za-z][A-Za-z0-9._\-]{2,})\b",
        re.IGNORECASE,
    )

    # "host=web01", "hostname: db-prod-2"
    HOSTNAME = re.compile(
        r"\b(?:host(?:name)?)\s*[=:]\s*([A-Za-z0-9][A-Za-z0-9._\-]{1,})\b",
        re.IGNORECASE,
    )

    # Two consecutive capitalized words, e.g. "John Doe" -- a coarse
    # proxy for PERSON entities in free text.
    PERSON_NAME = re.compile(
        r"\b([A-Z][a-z]+(?:\s[A-Z][a-z]+)+)\b"
    )

    def analyze(self, text: str) -> list[PIIMatch]:
        matches: list[PIIMatch] = []

        for m in self.USERNAME.finditer(text):
            matches.append(PIIMatch(
                m.start(1), m.end(1), "USERNAME", m.group(1),
                score=0.6, source="ner",
            ))

        for m in self.HOSTNAME.finditer(text):
            matches.append(PIIMatch(
                m.start(1), m.end(1), "HOSTNAME", m.group(1),
                score=0.6, source="ner",
            ))

        for m in self.PERSON_NAME.finditer(text):
            matches.append(PIIMatch(
                m.start(1), m.end(1), "PERSON", m.group(1),
                score=0.5, source="ner",
            ))

        return matches


def build_ner_recognizer() -> BaseNERRecognizer:
    """
    Factory: prefer Presidio (real NER via spaCy) if it can be
    initialized, otherwise fall back to the heuristic recognizer.
    """
    try:
        return PresidioNERRecognizer()
    except Exception:
        return HeuristicNERRecognizer()
    except SystemExit:  # pragma: no cover - presidio/spacy may sys.exit() directly
        return HeuristicNERRecognizer()


# ----------------------------------------------------------------------
# Hybrid detector: combines both tiers and de-duplicates overlaps
# ----------------------------------------------------------------------
class PIIDetector:
    """
    Combines the deterministic regex tier and the NLP/NER tier into a
    single pass over a free-text field, returning a clean, non-
    overlapping list of PIIMatch spans ready for redaction.

    Regex matches take precedence over NER matches on overlapping
    spans, since they represent exact, high-confidence structural
    identifiers (IPs, MACs, ports) -- consistent with Section 3.5.1's
    description of regex as the first, deterministic tier.
    """

    def __init__(self, ner: Optional[BaseNERRecognizer] = None):
        self.regex_detector = RegexPIIDetector()
        self.ner_detector = ner or build_ner_recognizer()

    def analyze(self, text: str) -> list[PIIMatch]:
        regex_matches = self.regex_detector.analyze(text)
        ner_matches = self.ner_detector.analyze(text)

        all_matches = sorted(
            regex_matches + ner_matches,
            key=lambda m: (m.start, -(m.end - m.start), m.source != "regex"),
        )

        merged: list[PIIMatch] = []
        for match in all_matches:
            if any(self._overlaps(match, kept) for kept in merged):
                continue
            merged.append(match)

        return sorted(merged, key=lambda m: m.start)

    @staticmethod
    def _overlaps(a: PIIMatch, b: PIIMatch) -> bool:
        return a.start < b.end and b.start < a.end


if __name__ == "__main__":
    detector = PIIDetector()
    print(f"Active NER backend: {detector.ner_detector.name}")
    print()

    sample_lines = [
        "Jun 15 10:23:45 fw01 sshd[1922]: Failed password for user jdoe "
        "from 192.168.1.50 port 51422 ssh2",
        "ALERT: suspicious login by Alice Johnson "
        "(alice.johnson@example.com) from host=db-prod-2, "
        "mac=00:1A:2B:3C:4D:5E at 2026-06-15T10:23:45Z",
    ]

    for line in sample_lines:
        print("RAW:", line)
        for match in detector.analyze(line):
            print("   ", match)
        print()