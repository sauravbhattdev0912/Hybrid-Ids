"""
ml_engine.py
------------
Stage 2 engine: Machine Learning anomaly detection.

Same engines are kept:
1. PKNN  -> Prioritized K-Nearest Neighbors
2. OSVM  -> Optimized Support Vector Machine

Final decision:
    PKNN probability + OSVM probability / 2
"""

import logging
import pickle
from pathlib import Path
from typing import Any

import numpy as np

from modules.preprocessor import (
    extract_features,
    get_selected_indices,
    select_features,
    set_selected_indices,
)


logger = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "models"
PKNN_PATH = MODEL_DIR / "pknn.pkl"
SVM_PATH = MODEL_DIR / "svm.pkl"
META_PATH = MODEL_DIR / "meta.pkl"


ATTACK_LABELS = [
    "Benign",
    "DDoS",
    "Traffic Spike",
    "Brute Force",
    "Beaconing Activity",
    "Unusual Outbound Transfer",
    "Lateral Movement",
    "High Entropy Data Transfer",
    "Slow HTTP Attack",
    "DNS Amplification",
]


class PrioritizedKNN:
    """
    PKNN means KNN with distance based priority.
    Closer neighbors get more importance than far neighbors.
    """

    def __init__(self, n_neighbors: int = 7):
        from sklearn.neighbors import KNeighborsClassifier

        self.model = KNeighborsClassifier(
            n_neighbors=n_neighbors,
            weights="distance",
            metric="euclidean",
        )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        self.classes_ = self.model.classes_
        return self

    def predict(self, X: np.ndarray):
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray):
        return self.model.predict_proba(X)

    # Kept for compatibility with older project explanation.
    def priority_scores(self, X: np.ndarray):
        return self.predict_proba(X)


class MLEngine:
    """Main ML class used by the decision engine."""

    def __init__(self):
        self.pknn: PrioritizedKNN | None = None
        self.svm: Any = None
        self.labels = ATTACK_LABELS
        self.trained = False
        self.selected_features: list[int] | None = None

    def load_or_train(self) -> None:
        """Load saved models. If they are missing, train models."""
        if self.load_models():
            return

        logger.info("No saved models found. Training using same synthetic dataset...")
        X, y = self._generate_synthetic_data()
        self.train(X, y)

    def load_models(self) -> bool:
        """Load PKNN, OSVM, and metadata from disk."""
        if not (PKNN_PATH.exists() and SVM_PATH.exists() and META_PATH.exists()):
            return False

        try:
            with open(PKNN_PATH, "rb") as file:
                self.pknn = pickle.load(file)

            # Older pickle used attribute _model instead of model.
            if hasattr(self.pknn, "_model") and not hasattr(self.pknn, "model"):
                self.pknn.model = self.pknn._model

            with open(SVM_PATH, "rb") as file:
                self.svm = pickle.load(file)

            with open(META_PATH, "rb") as file:
                meta = pickle.load(file)

            self.labels = meta.get("labels", ATTACK_LABELS)
            self.selected_features = meta.get("nbfs")
            set_selected_indices(self.selected_features)

            self.trained = True
            logger.info("Saved ML models loaded successfully.")
            return True

        except Exception as error:
            logger.warning("Could not load saved models: %s", error)
            return False

    def save_models(self) -> None:
        """Save trained models to backend/data/models."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        with open(PKNN_PATH, "wb") as file:
            pickle.dump(self.pknn, file)
        with open(SVM_PATH, "wb") as file:
            pickle.dump(self.svm, file)
        with open(META_PATH, "wb") as file:
            pickle.dump({"labels": self.labels, "nbfs": self.selected_features}, file)

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        """Train PKNN and OSVM models."""
        from sklearn.metrics import accuracy_score, classification_report
        from sklearn.model_selection import train_test_split
        from sklearn.svm import SVC

        # Step 1: feature selection
        select_features(X, y, k=min(7, X.shape[1]))
        self.selected_features = get_selected_indices()
        if self.selected_features:
            X = X[:, self.selected_features]

        # Step 2: split dataset
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )

        # Step 3: train PKNN
        self.pknn = PrioritizedKNN(n_neighbors=7)
        self.pknn.fit(X_train, y_train)

        # Step 4: train OSVM
        self.svm = SVC(
            kernel="rbf",
            C=10,
            gamma="scale",
            probability=True,
            random_state=42,
        )
        self.svm.fit(X_train, y_train)

        # Step 5: evaluate combined/fused model
        pknn_accuracy = accuracy_score(y_test, self.pknn.predict(X_test))
        svm_accuracy = accuracy_score(y_test, self.svm.predict(X_test))
        fused_prediction = self.fuse_predictions(X_test)
        fused_accuracy = accuracy_score(y_test, fused_prediction)

        self.trained = True
        self.save_models()

        return {
            "samples": int(len(X)),
            "pknn_accuracy": round(float(pknn_accuracy), 4),
            "svm_accuracy": round(float(svm_accuracy), 4),
            "fused_accuracy": round(float(fused_accuracy), 4),
            "report": classification_report(
                y_test,
                fused_prediction,
                output_dict=True,
                zero_division=0,
            ),
        }

    def predict(self, packet: dict[str, Any]) -> dict:
        """Predict whether packet is benign or attack."""
        if not self.trained or self.pknn is None or self.svm is None:
            return {
                "attack_type": "Unknown",
                "method": "Anomaly",
                "confidence": 0.0,
                "is_attack": False,
            }

        vector = extract_features(packet)
        if self.selected_features:
            vector = vector[self.selected_features]

        X = vector.reshape(1, -1)

        pknn_prob = self.pknn.predict_proba(X)[0]
        svm_prob = self.svm.predict_proba(X)[0]

        final_prob = (pknn_prob + svm_prob) / 2.0
        best_index = int(np.argmax(final_prob))
        confidence = float(final_prob[best_index])

        classes = self.pknn.classes_
        attack_type = str(classes[best_index])
        is_attack = attack_type.lower() != "benign"

        return {
            "attack_type": attack_type,
            "method": "Anomaly",
            "confidence": round(confidence, 4),
            "is_attack": is_attack,
            "pknn_pred": str(classes[int(np.argmax(pknn_prob))]),
            "svm_pred": str(classes[int(np.argmax(svm_prob))]),
        }

    def fuse_predictions(self, X: np.ndarray) -> np.ndarray:
        """Average PKNN and OSVM probabilities."""
        pknn_prob = self.pknn.predict_proba(X)
        svm_prob = self.svm.predict_proba(X)
        final_prob = (pknn_prob + svm_prob) / 2.0
        classes = self.pknn.classes_
        return np.array([classes[i] for i in np.argmax(final_prob, axis=1)])

    def _generate_synthetic_data(
        self,
        n_benign: int = 800,
        n_attack_each: int = 120,
    ) -> tuple[np.ndarray, np.ndarray]:
        """
        Same dataset logic as the original project:
        synthetic CICIDS-style traffic for demo/training.
        """
        rng = np.random.default_rng(42)
        X_rows = []
        y_rows = []

        # Benign traffic
        for _ in range(n_benign):
            X_rows.append([
                rng.uniform(0.1, 0.9),
                rng.uniform(0.1, 0.9),
                rng.choice([0, 0.25]),
                rng.uniform(0.01, 0.3),
                0.0, 1.0, 0.0, 0.0, 1.0,
            ])
            y_rows.append("Benign")

        attack_profiles = {
            "DDoS": {
                "port": lambda: rng.uniform(0.001, 0.01),
                "size": lambda: rng.uniform(0.8, 1.0),
                "flags": [1, 0, 0, 0, 0],
            },
            "Traffic Spike": {
                "port": lambda: rng.uniform(0.0, 0.05),
                "size": lambda: rng.uniform(0.7, 1.0),
                "flags": [1, 0, 0, 0, 0],
            },
            "Brute Force": {
                "port": lambda: rng.choice([22/65535, 21/65535, 3389/65535]),
                "size": lambda: rng.uniform(0.01, 0.05),
                "flags": [1, 0, 0, 0, 0],
            },
            "Beaconing Activity": {
                "port": lambda: 4444/65535,
                "size": lambda: rng.uniform(0.05, 0.15),
                "flags": [0, 1, 0, 0, 1],
            },
            "Unusual Outbound Transfer": {
                "port": lambda: 443/65535,
                "size": lambda: rng.uniform(0.6, 1.0),
                "flags": [0, 1, 0, 0, 1],
            },
            "Lateral Movement": {
                "port": lambda: 135/65535,
                "size": lambda: rng.uniform(0.1, 0.4),
                "flags": [1, 0, 0, 0, 0],
            },
            "High Entropy Data Transfer": {
                "port": lambda: 443/65535,
                "size": lambda: rng.uniform(0.8, 1.0),
                "flags": [0, 1, 0, 0, 1],
            },
            "Slow HTTP Attack": {
                "port": lambda: 80/65535,
                "size": lambda: rng.uniform(0.001, 0.02),
                "flags": [0, 1, 0, 0, 0],
            },
            "DNS Amplification": {
                "port": lambda: 53/65535,
                "size": lambda: rng.uniform(0.5, 1.0),
                "flags": [0, 0, 0, 0, 0],
            },
        }

        for label, profile in attack_profiles.items():
            for _ in range(n_attack_each):
                port = profile["port"]()
                size = profile["size"]()
                flags = profile["flags"]
                protocol = rng.choice([0, 0.25])
                noise = rng.normal(0, 0.01, 9)
                vector = np.clip(
                    np.array([port, port, protocol, size, *flags], dtype=float) + noise,
                    0.0,
                    1.0,
                )
                X_rows.append(vector.tolist())
                y_rows.append(label)

        X = np.array(X_rows, dtype=np.float32)
        y = np.array(y_rows)

        # Shuffle dataset
        order = rng.permutation(len(X))
        return X[order], y[order]


ml_engine = MLEngine()
