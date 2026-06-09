"""
packet_capture.py
-----------------
Simple packet simulator for demo.

It creates fake packets and sends them to decision_engine.analyse().
This helps the dashboard show live-looking data without real packet capture.
"""

import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Any

from modules import database, decision_engine


running = False


BENIGN_PACKETS = [
    {"protocol": "TCP", "port": 80, "flags": "ACK,PSH"},
    {"protocol": "TCP", "port": 443, "flags": "ACK,PSH"},
    {"protocol": "UDP", "port": 53, "flags": ""},
    {"protocol": "TCP", "port": 8080, "flags": "ACK"},
    {"protocol": "TCP", "port": 22, "flags": "ACK"},
]


ATTACK_PACKETS = [
    {"protocol": "TCP", "port": 3306, "flags": "SYN"},   # SQL Injection
    {"protocol": "UDP", "port": 53, "flags": ""},       # DNS Amplification
    {"protocol": "TCP", "port": 22, "flags": "SYN"},    # SSH brute force
    {"protocol": "TCP", "port": 445, "flags": "SYN"},   # SMB exploit
    {"protocol": "TCP", "port": 4444, "flags": "ACK"},  # Beaconing
    {"protocol": "TCP", "port": 135, "flags": "SYN"},   # Lateral movement
]


def random_ip() -> str:
    prefix = random.choice(["192.168.", "10.0.", "172.16."])
    return f"{prefix}{random.randint(0, 9)}.{random.randint(1, 254)}"


def make_packet(template: dict[str, Any]) -> dict[str, Any]:
    """Create one packet dictionary from a template."""
    return {
        "ip": random_ip(),
        "port": template["port"],
        "protocol": template["protocol"],
        "packet_size": random.randint(64, 1500),
        "flags": template["flags"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def simulation_loop(rate_hz: float = 2.0, attack_prob: float = 0.15):
    """Generate packets until stop button/API is called."""
    global running

    delay = 1.0 / max(rate_hz, 0.1)
    packet_count = 0
    last_save_time = time.monotonic()

    while running:
        if random.random() < attack_prob:
            template = random.choice(ATTACK_PACKETS)
        else:
            template = random.choice(BENIGN_PACKETS)

        packet = make_packet(template)
        decision_engine.analyse(packet)
        packet_count += 1

        # Save traffic count every 30 seconds for chart.
        if time.monotonic() - last_save_time >= 30:
            database.save_traffic_count(packet_count)
            packet_count = 0
            last_save_time = time.monotonic()

        await asyncio.sleep(delay)


async def start_simulation(rate_hz: float = 2.0, attack_prob: float = 0.15):
    """Start background packet simulation."""
    global running
    if running:
        return
    running = True
    asyncio.create_task(simulation_loop(rate_hz, attack_prob))


async def stop_simulation():
    """Stop background packet simulation."""
    global running
    running = False


def is_running() -> bool:
    return running
