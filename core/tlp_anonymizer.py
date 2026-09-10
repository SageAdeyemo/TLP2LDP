"""
tlp_anonymizer.py

The "TLPAnonymizerMiddleware" core (Section 3.2.2 / 3.4.2), minus the
Kafka transport and Presidio/NER layers which are added in later steps.

Given a raw log envelope (a dict containing a TLP tag plus telemetry
fields) and a field schema describing each field's type, this module:

  1. Extracts and resolves the TLP tag -> privacy policy (epsilon).
  2. Routes each field to the correct field-aware anonymization
     strategy (numeric / ip / categorical / timestamp).
  3. Returns the anonymized record plus the privacy metadata applied,
     mirroring the "RETURN_ANONYMIZED_DATA" / "PUBLISH_SECURE_LOG"
     steps in the sequence diagram.

Field schema format
--------------------
A field schema is a dict mapping field name -> field type, where
field type is one of:

    "ip"          -> salted per-octet hashing (subnet-preserving)
    "categorical" -> salted SHA-256 hashing (usernames, MACs, hosts)
    "timestamp"   -> adaptive Laplace noise w/ monotonicity guard
    "numeric"     -> Laplace mechanism (ports, byte/packet counts, ...)
    "passthrough" -> field is copied unchanged (e.g. the TLP tag itself)

Numeric fields may instead be given as a tuple:
    ("numeric", lower_bound, upper_bound)
to clip the noisy output into a valid domain (e.g. ports 0-65535).
"""

from typing import Any, Optional

from anonymizer import FieldAnonymizer, SYSTEM_SALT
from pii_detector import PIIDetector
from text_redactor import redact_text
from tlp_resolver import resolve_policy


# A sensible default schema covering the PII taxonomy described in
# Phase 1 / Objective 1 (Bargale et al., 2025): IP addresses, MAC
# addresses, port numbers, timestamps, user/session identifiers, and
# free-text payload bodies.
DEFAULT_FIELD_SCHEMA: dict[str, Any] = {
    "tlp": "passthrough",
    "src_ip": "ip",
    "dst_ip": "ip",
    "src_mac": "categorical",
    "dst_mac": "categorical",
    "user_id": "categorical",
    "session_id": "categorical",
    "hostname": "categorical",
    "action": "passthrough",
    "src_port": ("numeric", 0, 65535),
    "dst_port": ("numeric", 0, 65535),
    "bytes": ("numeric", 0, None),
    "packets": ("numeric", 0, None),
    "duration": ("numeric", 0, None),
    "timestamp": "timestamp",
    "message": "text",
    "payload": "text",
    "raw": "text",
}


class TLPAnonymizerMiddleware:
    """
    Stateful middleware instance. Holds a FieldAnonymizer (for salt +
    timestamp ordering state) and a field schema describing how to
    treat each incoming field.
    """

    def __init__(self, field_schema=None, salt=SYSTEM_SALT,
                 unknown_field_strategy="passthrough"):
        self.field_schema = field_schema or DEFAULT_FIELD_SCHEMA
        self.unknown_field_strategy = unknown_field_strategy
        self.fa = FieldAnonymizer(salt=salt)
        self.pii_detector = PIIDetector()

    def anonymize(self, log_entry: dict[str, Any],
                   stream_key: str = "default") -> dict[str, Any]:
        """
        Anonymize a single log entry.

        Args:
            log_entry: raw log dict, must contain a "tlp" key
                       (e.g. "TLP:RED") plus telemetry fields.
            stream_key: identifies the logical stream for timestamp
                       ordering guarantees (e.g. per-host or per-flow).

        Returns:
            dict with:
              - "anonymized": the perturbed/hashed record
              - "policy": the resolved {tlp, epsilon, sensitivity, noise_level}
        """
        policy = resolve_policy(log_entry.get("tlp"))
        epsilon = policy["epsilon"]

        anonymized: dict[str, Any] = {}
        pii_report: dict[str, list] = {}

        for field, raw_value in log_entry.items():
            field_type = self.field_schema.get(field)
            
            if field_type is None:
                if isinstance(raw_value, (int, float)) and not isinstance(raw_value, bool):
                    field_type = "numeric_float"
                else:
                    field_type = self.unknown_field_strategy

            if raw_value is None:
                anonymized[field] = None
                continue

            if field_type == "passthrough":
                anonymized[field] = raw_value

            elif field_type == "ip":
                anonymized[field] = self.fa.anonymize_ip(str(raw_value))

            elif field_type == "categorical":
                anonymized[field] = self.fa.anonymize_categorical(str(raw_value))

            elif field_type == "timestamp":
                anonymized[field] = self.fa.anonymize_timestamp(
                    float(raw_value), epsilon, stream_key=stream_key
                )

            elif field_type == "text":
                result = redact_text(
                    str(raw_value), self.fa, epsilon,
                    detector=self.pii_detector, stream_key=stream_key,
                )
                anonymized[field] = result["redacted_text"]
                if result["entities_found"]:
                    pii_report[field] = result["entities_found"]

            elif isinstance(field_type, tuple) and field_type[0] == "numeric":
                _, lower, upper = field_type
                anonymized[field] = self.fa.anonymize_numeric(
                    raw_value, epsilon, lower=lower, upper=upper
                )

            elif field_type == "numeric":
                anonymized[field] = self.fa.anonymize_numeric(raw_value, epsilon)

            else:
                # Unknown field type -> safest default is categorical hashing
                anonymized[field] = self.fa.anonymize_categorical(str(raw_value))

        result = {"anonymized": anonymized, "policy": policy}
        if pii_report:
            result["pii_detected"] = pii_report
        return result


if __name__ == "__main__":
    middleware = TLPAnonymizerMiddleware()

    # Same example payload as the sequence diagram in Section 3.2.2
    sample_log = {
        "tlp": "TLP:RED",
        "src_ip": "192.168.1.50",
        "user_id": "jdoe",
        "action": "login",
    }

    result = middleware.anonymize(sample_log, stream_key="host-A")
    print("Input :", sample_log)
    print("Policy:", result["policy"])
    print("Output:", result["anonymized"])

    print()

    # A richer NetFlow-style record, run at two different TLP levels
    netflow_template = {
        "src_ip": "10.0.0.7",
        "dst_ip": "203.0.113.42",
        "src_port": 51422,
        "dst_port": 443,
        "bytes": 15234,
        "packets": 12,
        "duration": 0.842,
        "timestamp": 1718000000.123,
        "user_id": "alice.smith",
    }

    for tlp_tag in ["TLP:RED", "TLP:CLEAR"]:
        log = {"tlp": tlp_tag, **netflow_template}
        result = middleware.anonymize(log, stream_key=f"flow-{tlp_tag}")
        print(f"-- {tlp_tag} (epsilon={result['policy']['epsilon']}) --")
        print(result["anonymized"])
        print()

    # Unstructured Syslog message containing embedded PII
    syslog_log = {
        "tlp": "TLP:AMBER",
        "src_ip": "172.16.0.23",
        "message": "Jun 15 10:23:45 fw01 sshd[1922]: Failed password "
                    "for user jdoe from 192.168.1.50 port 51422 ssh2",
    }
    result = middleware.anonymize(syslog_log, stream_key="syslog-1")
    print(f"-- TLP:AMBER syslog (epsilon={result['policy']['epsilon']}) --")
    print("anonymized:", result["anonymized"])
    print("pii_detected:", result.get("pii_detected"))
