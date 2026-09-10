"""
anonymizer.py

The Algorithmic Anonymization Layer described in Sections 3.3.1, 3.5.2
and 3.5.3 of the project write-up.

Implements three field-aware perturbation strategies:

1. Numeric fields (ports, byte/packet counts, flow durations, IP octets
   used numerically) -> Laplace mechanism, Lap(delta_f / epsilon),
   via IBM diffprivlib.

2. IP addresses -> salted, per-octet SHA-256 hashing. Because the hash
   is deterministic per (salt, octet-value) pair, identical octet
   values always map to the same output -- preserving subnet
   relationships (e.g. all hosts on 192.168.1.0/24 still share the
   same anonymized prefix) while being irreversible without the salt.

3. Categorical / static-string fields (usernames, MAC addresses,
   hostnames) -> salted SHA-256 hashing (full value), giving consistent
   pseudonyms for correlation without exposing the raw identifier.

4. Timestamps -> adaptive Laplace noise with a monotonicity guard, so
   exact times are obfuscated but chronological ordering of events
   within a stream is strictly preserved (per Bargale et al., 2025).

The static system salt is fixed as "BowenCyberSec2026" per Section
3.4.2 of the write-up.
"""

import hashlib
from typing import Any, Optional

from diffprivlib.mechanisms import Laplace

# Static, project-wide salt used for all keyed hashing operations.
SYSTEM_SALT = "BowenCyberSec2026"

# Global sensitivity (delta f) for event-stream / counting-based LDP,
# per the justification in Section 3.3.1 (Delta f = 1).
DEFAULT_SENSITIVITY = 1


class FieldAnonymizer:
    """
    Stateful, field-aware anonymization engine. One instance should be
    reused across a stream (or per-stream-key) so that timestamp
    ordering can be tracked correctly.
    """

    def __init__(self, salt: str = SYSTEM_SALT,
                 sensitivity: int = DEFAULT_SENSITIVITY):
        self.salt = salt
        self.sensitivity = sensitivity
        # Tracks the last emitted (noisy) timestamp per stream key,
        # so monotonicity can be enforced.
        self._last_timestamp: dict[str, float] = {}

    # ------------------------------------------------------------------
    # 1. Numeric fields -- Laplace mechanism
    # ------------------------------------------------------------------
    def anonymize_numeric(self, value: float, epsilon: float,
                           lower: Optional[float] = None,
                           upper: Optional[float] = None,
                           as_int: bool = True) -> float:
        """
        Apply Y ~ Laplace(0, sensitivity/epsilon) noise to a scalar
        numeric field (Section 3.3.1: M(x) = f(x) + Y).

        `lower`/`upper` clip the noisy result back into a valid domain
        (e.g. ports must remain in [0, 65535]) without affecting the
        noise *generation* itself -- only the reported output.
        """
        mech = Laplace(epsilon=epsilon, sensitivity=self.sensitivity)
        noisy = mech.randomise(float(value))

        if lower is not None:
            noisy = max(lower, noisy)
        if upper is not None:
            noisy = min(upper, noisy)

        return int(round(noisy)) if as_int else noisy

    # ------------------------------------------------------------------
    # 2. IP addresses -- salted per-octet hashing (subnet-preserving)
    # ------------------------------------------------------------------
    def anonymize_ip(self, ip_address: str) -> str:
        """
        Apply salt-based SHA-256 hashing at the per-octet level.

        Each octet is hashed independently using the static system
        salt and mapped back into the 0-255 range. Because the
        mapping is deterministic, two addresses sharing the same
        prefix (e.g. same /24 subnet) will continue to share the same
        anonymized prefix -- preserving subnet-level structure for
        threat hunting while making the original octet values
        irreversible without the salt.

        Supports IPv4 dotted-quad notation. Non-IPv4 / malformed input
        is hashed as a single categorical token instead.
        """
        octets = ip_address.strip().split(".")
        if len(octets) != 4 or not all(o.isdigit() for o in octets):
            # Fallback for IPv6 or malformed values: treat as categorical
            return self.anonymize_categorical(ip_address)

        return ".".join(str(self._hash_octet(o)) for o in octets)

    def _hash_octet(self, octet_str: str) -> int:
        digest = hashlib.sha256(f"{self.salt}:{octet_str}".encode()).hexdigest()
        return int(digest, 16) % 256

    # ------------------------------------------------------------------
    # 3. Categorical fields -- salted SHA-256 hashing
    # ------------------------------------------------------------------
    def anonymize_categorical(self, value: str, length: int = 16) -> str:
        """
        Deterministic, salt-keyed SHA-256 hash for static strings
        (usernames, MAC addresses, hostnames). The same input always
        maps to the same output within this system, preserving
        correlation across logs without exposing the raw identifier.
        """
        digest = hashlib.sha256(f"{self.salt}:{value}".encode()).hexdigest()
        return digest[:length]

    def anonymize_mac(self, mac_address: str) -> str:
        """
        Salted SHA-256 hash of a MAC address, reformatted back into
        standard colon-separated hex-pair notation (e.g.
        'a1:b2:c3:d4:e5:f6') so downstream tooling that expects MAC-
        shaped strings continues to parse the field correctly, while
        the value itself is irreversibly pseudonymized and remains
        consistent across logs for correlation.
        """
        digest = hashlib.sha256(f"{self.salt}:{mac_address.lower()}".encode()).hexdigest()
        hex_pairs = [digest[i:i + 2] for i in range(0, 12, 2)]
        return ":".join(hex_pairs)

    # ------------------------------------------------------------------
    # 4. Timestamps -- adaptive noise with monotonicity guard
    # ------------------------------------------------------------------
    def anonymize_timestamp(self, timestamp: float, epsilon: float,
                             stream_key: str = "default",
                             min_gap: float = 1e-6) -> float:
        """
        Inject Laplace noise into a Unix timestamp (seconds) while
        guaranteeing the output remains strictly greater than the
        previously emitted timestamp for the same stream_key.

        This obfuscates the exact instant an event occurred while
        preserving the chronological *sequence* of events -- the
        property Bargale et al. (2025) identify as essential for
        tracing attack paths.
        """
        mech = Laplace(epsilon=epsilon, sensitivity=self.sensitivity)
        noisy = float(timestamp) + mech.randomise(0.0)

        last = self._last_timestamp.get(stream_key)
        if last is not None and noisy <= last:
            noisy = last + min_gap

        self._last_timestamp[stream_key] = noisy
        return noisy

    def reset_stream(self, stream_key: str = "default") -> None:
        """Clear timestamp ordering state for a given stream key."""
        self._last_timestamp.pop(stream_key, None)


if __name__ == "__main__":
    fa = FieldAnonymizer()

    print("-- IP anonymization (subnet preservation check) --")
    ip_a = fa.anonymize_ip("192.168.1.50")
    ip_b = fa.anonymize_ip("192.168.1.51")
    ip_c = fa.anonymize_ip("10.0.0.7")
    print("192.168.1.50 ->", ip_a)
    print("192.168.1.51 ->", ip_b)
    print("10.0.0.7      ->", ip_c)
    print("Shared /24 prefix preserved:",
          ip_a.split(".")[:3] == ip_b.split(".")[:3])

    print("\n-- Numeric field anonymization (port=443) at varying epsilon --")
    for eps, label in [(0.05, "RED"), (0.25, "AMBER"), (1.0, "GREEN"), (10.0, "CLEAR")]:
        print(f"  TLP:{label:<6} eps={eps:<5} -> {fa.anonymize_numeric(443, eps, 0, 65535)}")

    print("\n-- Categorical field anonymization --")
    print("'jdoe'    ->", fa.anonymize_categorical("jdoe"))
    print("'jdoe' again ->", fa.anonymize_categorical("jdoe"))

    print("\n-- Timestamp anonymization (chronological order preserved) --")
    ts_stream = "demo"
    raw_ts = [1000.0, 1000.5, 1001.0, 1001.2, 1001.9]
    noisy_ts = [fa.anonymize_timestamp(t, epsilon=0.05, stream_key=ts_stream) for t in raw_ts]
    for r, n in zip(raw_ts, noisy_ts):
        print(f"  raw={r:<8} -> noisy={n:.6f}")
    print("Order preserved:", noisy_ts == sorted(noisy_ts))