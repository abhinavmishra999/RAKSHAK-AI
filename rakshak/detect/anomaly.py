"""Unsupervised anomaly detection with Isolation Forest (scikit-learn).

The model learns what *normal* traffic windows look like. The "Learn my normal
traffic" button retrains it on windows observed while only normal users were active.
Until then, it is not used for alerts (status reports "not trained").
"""
import pickle
from pathlib import Path

import numpy as np
from sklearn.ensemble import IsolationForest

FEATURES = ["rate", "timing_cv", "err_404_ratio", "unique_paths", "unique_uas", "failed_logins"]


def vector(f):
    return [float(f[k]) for k in FEATURES]


class AnomalyModel:
    def __init__(self, path: Path, load_persisted: bool = True):
        self.path = path
        self.load_persisted = load_persisted
        self.model = None
        self.trained_on = 0
        self.samples = []
        # loading a pickle executes code: only do it when the operator explicitly trusted the file
        if load_persisted and path.exists():
            with open(path, "rb") as fh:
                saved = pickle.load(fh)
            self.model, self.trained_on = saved["model"], saved["n"]

    def collect(self, f):
        if f and f["malicious"] == 0 and f["count"] >= 3:
            self.samples.append(vector(f))
            self.samples = self.samples[-5000:]

    def train(self):
        if len(self.samples) < 30:
            return {"ok": False, "reason": f"Need at least 30 normal samples, have {len(self.samples)}. "
                                            "Run the 'Normal users' test first."}
        X = np.array(self.samples)
        self.model = IsolationForest(n_estimators=150, contamination=0.01, random_state=42).fit(X)
        self.trained_on = len(X)
        with open(self.path, "wb") as fh:
            pickle.dump({"model": self.model, "n": self.trained_on}, fh)
        return {"ok": True, "samples": self.trained_on}

    def is_anomalous(self, f):
        if self.model is None or not f or f["count"] < 10:
            return False, 0.0
        s = float(self.model.decision_function([vector(f)])[0])
        return s < -0.05, round(s, 3)

    def status(self):
        return {"trained": self.model is not None, "trained_on": self.trained_on,
                "pending_samples": len(self.samples),
                "persistence": ("loading saved model files is disabled (set RAKSHAK_TRUST_MODEL=1 "
                                "to load them; training in-process always works)"
                                if not self.load_persisted else "saved model loaded (trusted)")}
