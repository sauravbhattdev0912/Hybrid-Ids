"""
signature_engine.py
-------------------
Stage 1 engine: checks known attack rules.

Example rule:
    If port is 3306 and protocol is TCP -> SQL Injection alert
"""

import json
from pathlib import Path
from typing import Any


SIGNATURE_FILE = Path(__file__).resolve().parent.parent / "data" / "signatures.json"
signatures: list[dict] = []


def load_signatures() -> list[dict]:
    """Load rules from data/signatures.json."""
    global signatures
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as file:
        signatures = json.load(file)
    return signatures


def inspect(packet: dict[str, Any]) -> dict | None:
    """
    Check packet against every signature rule.

    Return rule details if matched.
    Return None if no known rule matches.
    """
    if not signatures:
        load_signatures()

    for rule in signatures:
        if packet_matches_rule(packet, rule):
            return {
                "matched": True,
                "rule_id": rule["id"],
                "attack_type": rule["name"],
                "severity": rule.get("severity", "medium"),
                "description": rule.get("description", ""),
                "method": "Signature",
            }

    return None


def packet_matches_rule(packet: dict, rule: dict) -> bool:
    """Return True only when all rule conditions match the packet."""
    conditions = rule.get("conditions", {})

    # Match port
    if conditions.get("port") is not None:
        if int(packet.get("port", 0)) not in conditions["port"]:
            return False

    # Match protocol
    if conditions.get("protocol") is not None:
        packet_protocol = str(packet.get("protocol", "")).upper()
        allowed_protocols = [p.upper() for p in conditions["protocol"]]
        if packet_protocol not in allowed_protocols:
            return False

    # Match TCP flags. At least one flag should match.
    if conditions.get("flags") is not None:
        packet_flags = str(packet.get("flags", "")).upper()
        allowed_flags = [f.upper() for f in conditions["flags"]]
        if not any(flag in packet_flags for flag in allowed_flags):
            return False

    # Optional IP prefix match
    if conditions.get("ip_prefix"):
        if not str(packet.get("ip", "")).startswith(conditions["ip_prefix"]):
            return False

    return True


def list_signatures() -> list[dict]:
    """Return all loaded signature rules."""
    if not signatures:
        load_signatures()
    return signatures
