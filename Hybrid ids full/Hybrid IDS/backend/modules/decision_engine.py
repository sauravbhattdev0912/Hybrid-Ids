"""
decision_engine.py
------------------
This is the simplest explanation of the whole IDS logic.

Packet comes in:
1. Check known attack rules using Signature Engine.
2. If no rule matched, check unknown attack using ML Engine.
3. Save result in database.
"""

from typing import Any

from modules import database, signature_engine
from modules.ml_engine import ml_engine


def analyse(packet: dict[str, Any]) -> dict:
    """Run one packet through the complete Hybrid IDS pipeline."""

    # Stage 1: check known attacks
    signature_result = signature_engine.inspect(packet)
    if signature_result is not None:
        return save_attack(
            packet=packet,
            attack_type=signature_result["attack_type"],
            method="Signature",
            stage="signature",
            confidence=1.0,
            rule_id=signature_result["rule_id"],
            severity=signature_result["severity"],
            details=signature_result,
        )

    # Stage 2: check unknown/anomaly attacks
    ml_result = ml_engine.predict(packet)
    if ml_result["is_attack"]:
        return save_attack(
            packet=packet,
            attack_type=ml_result["attack_type"],
            method="Anomaly",
            stage="ml",
            confidence=ml_result["confidence"],
            rule_id=None,
            severity=confidence_to_severity(ml_result["confidence"]),
            details=ml_result,
        )

    # If both engines say safe, it is benign.
    database.save_log(
        packet=packet,
        attack_type="Benign",
        method=None,
        verdict="benign",
        stage="none",
    )

    return make_result(
        packet=packet,
        verdict="benign",
        stage="none",
        method=None,
        attack_type=None,
        confidence=ml_result.get("confidence", 0.0),
        rule_id=None,
        severity=None,
        details=ml_result,
    )


def save_attack(
    packet: dict,
    attack_type: str,
    method: str,
    stage: str,
    confidence: float,
    rule_id,
    severity,
    details: dict,
) -> dict:
    """Save attack in alerts table and logs table."""
    database.save_alert(packet, attack_type, method, confidence)
    database.save_log(packet, attack_type, method, verdict="attack", stage=stage)

    return make_result(
        packet=packet,
        verdict="attack",
        stage=stage,
        method=method,
        attack_type=attack_type,
        confidence=confidence,
        rule_id=rule_id,
        severity=severity,
        details=details,
    )


def make_result(
    packet: dict,
    verdict: str,
    stage: str,
    method,
    attack_type,
    confidence: float,
    rule_id,
    severity,
    details: dict,
) -> dict:
    """Create one common response format for frontend/API."""
    return {
        "ip": str(packet.get("ip", "unknown")),
        "port": int(packet.get("port", 0)),
        "protocol": str(packet.get("protocol", "TCP")).upper(),
        "verdict": verdict,
        "stage": stage,
        "method": method,
        "attack_type": attack_type,
        "confidence": confidence,
        "rule_id": rule_id,
        "severity": severity,
        "details": details,
    }


def confidence_to_severity(confidence: float) -> str:
    """Convert ML confidence to human-readable severity."""
    if confidence >= 0.90:
        return "critical"
    if confidence >= 0.75:
        return "high"
    if confidence >= 0.55:
        return "medium"
    return "low"
