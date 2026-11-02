"""Ties simulator, detector and mitigator into one step-per-window pipeline."""
import threading

import numpy as np

from .detector import Detector
from .mitigation import Mitigator
from .simulator import features, truth, window

OFFENDER_PPS = 15   # per-source packets/s above which a source counts as offending
P_BLOCK = 0.7       # attack probability needed to act immediately
ALARM_K = 2         # consecutive alarm windows that also trigger action (if model is at least unsure)


class Engine:
    def __init__(self, seed=0, **mit):
        self.seed, self.mit_args = seed, mit
        self.lock = threading.Lock()
        self.detector = Detector(seed)
        self.reset()

    def reset(self):
        self.rng = np.random.default_rng(self.seed + 1)
        self.mit = Mitigator(**self.mit_args)
        self.t, self.streak, self.history = 0, 0, []

    def step(self, scenario):
        return self.process(window(scenario, self.rng), scenario)

    def process(self, w, scenario="live"):
        with self.lock:
            self.t += 1
            t = self.t
            self.mit.expire(t)
            f = features(w)
            passed, dropped = self.mit.filter(w["counts"])   # rules from earlier windows act on this one
            alarm = self.detector.alarm(f)
            label, p_attack = self.detector.predict(f)
            self.streak = self.streak + 1 if alarm else 0
            act = p_attack >= P_BLOCK or (self.streak >= ALARM_K and p_attack >= .3)
            offenders = [ip for ip, c in w["counts"].items() if c > OFFENDER_PPS] if act else []
            decision = "mitigate" if act else "alert" if (label != "normal" or alarm) else "none"
            if act and offenders: self.mit.apply(t, offenders)
            elif act: self.mit.log(t, f"{label}: no dominant source, global filter advised")
            if decision != "none": self.mit.log(t, f"{decision}: {label} (p={p_attack:.2f}, alarm={alarm})")
            row = dict(t=t, scenario=scenario, truth=truth(scenario) if scenario != "live" else "unknown", label=label, attack_prob=round(p_attack, 3),
                       alarm=alarm, decision=decision, pps=int(f[0]), passed=int(passed), dropped=int(dropped),
                       offenders=len(offenders), features=dict(zip(
                           ["pps", "unique_src", "src_entropy", "top_share", "median_pps", "syn_ratio", "mean_size"],
                           [round(x, 3) for x in f])))
            self.history = (self.history + [row])[-200:]
            return row

    def state(self):
        with self.lock:
            return dict(t=self.t, history=self.history[-60:], mitigations=self.mit.table(self.t),
                        allow_list=sorted(self.mit.allow_list), events=self.mit.events[-30:][::-1])
