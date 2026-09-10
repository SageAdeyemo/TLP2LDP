"""
tlp_resolver.py

Implements the case-based deterministic switching logic described in
Section 3.3.2 of the project write-up:

    epsilon = g(TLP) = { 0.05  if TLP = RED
                        { 0.25  if TLP = AMBER / AMBER+STRICT
                        { 1.00  if TLP = GREEN
                        { 10.00 if TLP = CLEAR

This module is the "automated bridge" between the qualitative TLP 2.0
governance label and the quantitative Differential Privacy budget (epsilon).
"""

from enum import Enum


class TLPLevel(str, Enum):
    """TLP 2.0 designations (CISA, 2022)."""
    RED = "RED"
    AMBER_STRICT = "AMBER+STRICT"
    AMBER = "AMBER"
    GREEN = "GREEN"
    CLEAR = "CLEAR"


# Core TLP -> epsilon mapping (Section 3.3.2)
# AMBER+STRICT is treated identically to AMBER for budget purposes,
# since both restrict disclosure to a need-to-know basis and the
# distinction is organizational rather than mathematical.
TLP_EPSILON_MAP = {
    TLPLevel.RED: 0.05,
    TLPLevel.AMBER_STRICT: 0.25,
    TLPLevel.AMBER: 0.25,
    TLPLevel.GREEN: 1.00,
    TLPLevel.CLEAR: 10.00,
}

# Default fallback per the process flow diagram (3.4.2):
# "VALID TLP MARKING FOUND? -> NO -> ASSIGN TLP:RED (High Noise Default)"
DEFAULT_TLP = TLPLevel.RED


def _normalize_tlp(tlp_raw: str) -> TLPLevel:
    """
    Normalize a raw TLP string (e.g. 'tlp:amber', 'TLP:AMBER+STRICT',
    'amber', 'Amber Strict') into a TLPLevel enum member.

    Falls back to DEFAULT_TLP if the marking is missing, malformed,
    or unrecognized -- mirroring the "fail-safe" branch in the
    process flow diagram, which defaults to the highest-noise (RED)
    setting rather than risking under-protection.
    """
    if not tlp_raw or not isinstance(tlp_raw, str):
        return DEFAULT_TLP

    # Strip a leading "TLP:" prefix, surrounding whitespace, and
    # normalize separators/casing.
    cleaned = tlp_raw.strip().upper()
    if cleaned.startswith("TLP:"):
        cleaned = cleaned[4:]
    cleaned = cleaned.replace(" ", "").replace("_", "+")

    # Handle common variants of the AMBER+STRICT modifier
    if cleaned in ("AMBER+STRICT", "AMBERSTRICT", "AMBER-STRICT"):
        return TLPLevel.AMBER_STRICT

    try:
        return TLPLevel(cleaned)
    except ValueError:
        return DEFAULT_TLP


def resolve_epsilon(tlp_raw: str) -> float:
    """
    Resolve a raw TLP marking string to its corresponding Differential
    Privacy budget (epsilon).

    Args:
        tlp_raw: The TLP tag as it appears in the log envelope header,
                 e.g. "TLP:RED", "AMBER", "tlp:clear".

    Returns:
        The epsilon value (float) to be used by the Laplace mechanism.

    Example:
        >>> resolve_epsilon("TLP:RED")
        0.05
        >>> resolve_epsilon("green")
        1.0
        >>> resolve_epsilon("not-a-real-tag")
        0.05
    """
    tlp_level = _normalize_tlp(tlp_raw)
    return TLP_EPSILON_MAP[tlp_level]


def resolve_policy(tlp_raw: str) -> dict:
    """
    Resolve a raw TLP marking into the full privacy policy context
    (mirrors the 'RETURN_POLICY' step in the sequence diagram, 3.2.2):
    {tlp, epsilon, sensitivity, noise_level}.

    'sensitivity' (delta f) is held at the unit constant 1, per the
    justification in Section 3.3.1 for event-stream / counting-based
    LDP processing.
    """
    tlp_level = _normalize_tlp(tlp_raw)
    epsilon = TLP_EPSILON_MAP[tlp_level]

    if epsilon <= 0.05:
        noise_level = "HIGH"
    elif epsilon <= 0.25:
        noise_level = "MEDIUM"
    elif epsilon <= 1.0:
        noise_level = "LOW"
    else:
        noise_level = "MINIMAL"

    return {
        "tlp": tlp_level.value,
        "epsilon": epsilon,
        "sensitivity": 1,
        "noise_level": noise_level,
    }


if __name__ == "__main__":
    # Quick self-test against the values in Section 3.3.2
    for tag in ["TLP:RED", "TLP:AMBER", "TLP:AMBER+STRICT",
                "TLP:GREEN", "TLP:CLEAR", "garbage", None]:
        print(f"{tag!r:20} -> {resolve_policy(tag)}")
