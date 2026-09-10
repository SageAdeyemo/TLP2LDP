"""
text_redactor.py

Bridges the PII Parsing and Analysis Layer (pii_detector.py) and the
Algorithmic Anonymization Layer (anonymizer.py) for *unstructured*
text fields -- free-text alert messages, Syslog message bodies, HTTP
headers, etc. (Section 3.5.1 / 3.5.3).

Given a raw text string, this module:

  1. Runs the hybrid PIIDetector to locate sensitive spans.
  2. Routes each detected entity type to the appropriate field-aware
     anonymization strategy (Laplace noise for ports/timestamps,
     salted hashing for IPs/MACs/usernames/hostnames/persons/emails).
  3. Reconstructs the string with anonymized values substituted in
     place, preserving everything else (structure, surrounding
     context, log format) untouched -- satisfying the "field-aware"
     requirement that anonymization must not destroy contextual
     integrity (Bargale et al., 2025).
"""

from __future__ import annotations

from datetime import datetime, timezone

from anonymizer import FieldAnonymizer
from pii_detector import PIIDetector, PIIMatch


def _anonymize_timestamp_str(value: str, fa: FieldAnonymizer,
                              epsilon: float, stream_key: str) -> str:
    """
    Parse an ISO-8601 timestamp string, apply adaptive Laplace noise
    via FieldAnonymizer.anonymize_timestamp, and re-render it in the
    same ISO-8601 format (preserving a trailing 'Z' if present).
    """
    had_z = value.endswith("Z")
    iso_value = value[:-1] if had_z else value

    try:
        dt = datetime.fromisoformat(iso_value)
    except ValueError:
        # Unparseable -- fall back to categorical hashing rather than
        # silently leaking the raw timestamp.
        return fa.anonymize_categorical(value, length=12)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    epoch = dt.timestamp()
    noisy_epoch = fa.anonymize_timestamp(epoch, epsilon, stream_key=f"{stream_key}:ts")
    noisy_dt = datetime.fromtimestamp(noisy_epoch, tz=timezone.utc)

    rendered = noisy_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    return rendered + "Z" if had_z else rendered


def _anonymize_entity(match: PIIMatch, fa: FieldAnonymizer,
                       epsilon: float, stream_key: str) -> str:
    """Dispatch a single PIIMatch to the correct anonymization routine."""
    entity = match.entity_type
    value = match.text

    if entity == "IP_ADDRESS":
        return fa.anonymize_ip(value)

    if entity == "MAC_ADDRESS":
        return fa.anonymize_mac(value)

    if entity == "PORT":
        anonymized = fa.anonymize_numeric(int(value), epsilon, lower=0, upper=65535)
        return str(anonymized)

    if entity == "TIMESTAMP":
        return _anonymize_timestamp_str(value, fa, epsilon, stream_key)

    # USERNAME, HOSTNAME, PERSON, EMAIL, and any unrecognized entity
    # types fall back to consistent salted-hash pseudonymization.
    return fa.anonymize_categorical(value, length=16)


def redact_text(text: str, fa: FieldAnonymizer, epsilon: float,
                 detector: PIIDetector | None = None,
                 stream_key: str = "default") -> dict:
    """
    Detect and anonymize all PII spans in a free-text field.

    Args:
        text: the raw free-text payload (e.g. a Syslog message body).
        fa: a FieldAnonymizer instance (carries salt + timestamp state).
        epsilon: the privacy budget resolved from the record's TLP tag.
        detector: optional shared PIIDetector instance (created if omitted).
        stream_key: identifies the logical stream, for timestamp ordering.

    Returns:
        {
            "redacted_text": str,
            "entities_found": [ {entity_type, original, anonymized}, ... ],
        }
    """
    detector = detector or PIIDetector()
    matches = detector.analyze(text)

    # Replace from right to left so earlier offsets remain valid even
    # though anonymized values may differ in length from the originals.
    redacted = text
    entities_found = []
    for match in sorted(matches, key=lambda m: m.start, reverse=True):
        replacement = _anonymize_entity(match, fa, epsilon, stream_key)
        redacted = redacted[:match.start] + replacement + redacted[match.end:]
        entities_found.append({
            "entity_type": match.entity_type,
            "original": match.text,
            "anonymized": replacement,
            "source": match.source,
        })

    # Report entities in original left-to-right order
    entities_found.reverse()
    return {"redacted_text": redacted, "entities_found": entities_found}


if __name__ == "__main__":
    fa = FieldAnonymizer()
    detector = PIIDetector()

    sample_logs = {
        "TLP:RED": "Jun 15 10:23:45 fw01 sshd[1922]: Failed password for "
                   "user jdoe from 192.168.1.50 port 51422 ssh2",
        "TLP:CLEAR": "ALERT: suspicious login by Alice Johnson "
                      "(alice.johnson@example.com) from host=db-prod-2, "
                      "mac=00:1A:2B:3C:4D:5E at 2026-06-15T10:23:45Z",
    }

    for tlp, message in sample_logs.items():
        from tlp_resolver import resolve_policy
        policy = resolve_policy(tlp)
        result = redact_text(message, fa, policy["epsilon"],
                              detector=detector, stream_key=tlp)

        print(f"-- {tlp} (epsilon={policy['epsilon']}) --")
        print("RAW     :", message)
        print("REDACTED:", result["redacted_text"])
        for ent in result["entities_found"]:
            print(f"   {ent['entity_type']:<12} '{ent['original']}' -> '{ent['anonymized']}'")
        print()