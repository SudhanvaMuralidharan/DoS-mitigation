"""Hybrid detector: fast statistical alarm + Random Forest attack classifier."""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support

from .simulator import FEATURES, LABELS, SCENARIOS, features, truth, window


def dataset(rng, n):
    X, y, s = [], [], []
    for sc in SCENARIOS:
        for _ in range(n):
            X.append(features(window(sc, rng))); y.append(truth(sc)); s.append(sc)
    return np.array(X), np.array(y), np.array(s)


class Detector:
    def __init__(self, seed=0, n=250):
        X, y, s = dataset(np.random.default_rng(seed), n)
        self.model = RandomForestClassifier(n_estimators=80, random_state=seed).fit(X, y)
        base = X[s == "normal", 0]
        self.pps_limit = float(base.mean() + 4 * base.std())

    def alarm(self, f):
        """Quick statistical check: rate spike, one dominant source, or SYN-heavy traffic."""
        return bool(f[0] > self.pps_limit or f[3] > .3 or f[5] > .6)

    def predict(self, f):
        p = self.model.predict_proba([f])[0]
        cls = list(self.model.classes_)
        return cls[int(np.argmax(p))], float(1 - p[cls.index("normal")])

    def evaluate(self, seed=123, n=100):
        X, y, s = dataset(np.random.default_rng(seed), n)
        pred = self.model.predict(X)
        pr, rc, f1, _ = precision_recall_fscore_support(y, pred, labels=LABELS, zero_division=0)
        legit = y == "normal"
        flash = s == "flash_crowd"
        return dict(
            accuracy=float((pred == y).mean()),
            false_positive_rate=float((pred[legit] != "normal").mean()),
            flash_crowd_false_positive_rate=float((pred[flash] != "normal").mean()),
            per_class={l: dict(precision=float(pr[i]), recall=float(rc[i]), f1=float(f1[i])) for i, l in enumerate(LABELS)},
            confusion=dict(labels=LABELS, matrix=confusion_matrix(y, pred, labels=LABELS).tolist()),
            windows=int(len(y)), note="Synthetic held-out windows (different seed); not real-world accuracy.")
