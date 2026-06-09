"""
preprocessor.py
---------------
Converts one packet dictionary into numbers for the ML models.

ML models cannot understand words like "TCP" or "SYN" directly.
So we convert them into a 9-number feature vector.
"""

from typing import Any
import numpy as np


MAX_PORT = 65535
MAX_PACKET_SIZE = 65535
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}

# Feature Selection mask. It is set during model training.
selected_feature_indices: list[int] | None = None


def extract_features(packet: dict[str, Any]) -> np.ndarray:
    """
    Convert packet to 9 simple numeric features:
    0 port number
    1 port number again as destination port placeholder
    2 protocol value
    3 packet size
    4 SYN flag
    5 ACK flag
    6 FIN flag
    7 RST flag
    8 PSH flag
    """
    port = int(packet.get("port", 0))
    protocol = str(packet.get("protocol", "OTHER")).upper()
    packet_size = int(packet.get("packet_size", 512))

    flags = packet.get("flags", "")
    if isinstance(flags, list):
        flags = ",".join(flags)
    flags = str(flags).upper()

    protocol_value = PROTOCOL_MAP.get(protocol, PROTOCOL_MAP["OTHER"]) / len(PROTOCOL_MAP)

    return np.array(
        [
            port / MAX_PORT,
            port / MAX_PORT,
            protocol_value,
            min(packet_size, MAX_PACKET_SIZE) / MAX_PACKET_SIZE,
            float("SYN" in flags),
            float("ACK" in flags),
            float("FIN" in flags),
            float("RST" in flags),
            float("PSH" in flags),
        ],
        dtype=np.float32,
    )


def select_features(X: np.ndarray, y: np.ndarray, k: int = 7) -> None:
    """
    Select the best k features using mutual information.
    This keeps the same NBFS idea, but written simply.
    """
    global selected_feature_indices

    from sklearn.feature_selection import mutual_info_classif

    scores = mutual_info_classif(X, y, random_state=42)
    best_to_worst = np.argsort(scores)[::-1]
    selected_feature_indices = sorted(best_to_worst[:k].tolist())


def apply_selected_features(vector: np.ndarray) -> np.ndarray:
    """Use selected features if feature selection has been done."""
    if selected_feature_indices is None:
        return vector
    return vector[selected_feature_indices]


def preprocess(packet: dict[str, Any]) -> np.ndarray:
    """Complete preprocessing step for one packet."""
    return apply_selected_features(extract_features(packet))


def get_selected_indices() -> list[int] | None:
    return selected_feature_indices


def set_selected_indices(indices: list[int] | None) -> None:
    global selected_feature_indices
    selected_feature_indices = indices
