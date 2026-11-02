"""Synthetic traffic generator: one call = one 1-second window of per-source packet counts.
Nothing here touches a real network; it only produces numbers for the detector."""
import numpy as np

SCENARIOS = ["normal", "flash_crowd", "syn_flood", "udp_flood", "http_flood"]
ATTACKS = ["syn_flood", "udp_flood", "http_flood"]
LABELS = ["normal"] + ATTACKS
FEATURES = ["pps", "unique_src", "src_entropy", "top_share", "median_pps", "syn_ratio", "mean_size"]


def truth(scenario):
    return scenario if scenario in ATTACKS else "normal"


def _ip(prefix, i):
    return f"{prefix}.{i // 250}.{i % 250 + 1}"


def _legit(rng, n, lam):
    ids = rng.choice(1000, size=n, replace=False)
    return {_ip("10.0", int(i)): int(rng.poisson(lam)) + 1 for i in ids}


def _bots(rng, n, lo, hi, pool):  # fixed pool => the same bots reappear, so escalation can happen
    ids = rng.choice(pool, size=n, replace=False)
    return {_ip("172.16", int(i)): int(rng.integers(lo, hi)) for i in ids}


def window(scenario, rng):
    if scenario == "normal":
        c, syn, size = _legit(rng, int(rng.integers(30, 120)), 3), rng.uniform(.05, .25), rng.normal(550, 80)
    elif scenario == "flash_crowd":  # many legitimate users at once: must NOT be blocked
        c, syn, size = _legit(rng, int(rng.integers(300, 700)), 4), rng.uniform(.1, .3), rng.normal(520, 80)
    else:
        c = _legit(rng, int(rng.integers(20, 80)), 3)
        if scenario == "syn_flood":
            if rng.random() < .5:  # spoofed sources: thousands of one-packet senders
                ids = rng.choice(60000, size=int(rng.integers(1500, 4000)), replace=False)
                c.update({_ip("198.51", int(i)): int(rng.integers(1, 3)) for i in ids})
            else:
                c.update(_bots(rng, int(rng.integers(5, 15)), 300, 800, 40))
            syn, size = rng.uniform(.85, .99), rng.normal(60, 8)
        elif scenario == "udp_flood":
            c.update(_bots(rng, int(rng.integers(3, 10)), 500, 1500, 40))
            syn, size = rng.uniform(0, .03), rng.normal(1100, 150)
        else:  # http_flood
            c.update(_bots(rng, int(rng.integers(150, 400)), 20, 45, 600))
            syn, size = rng.uniform(.15, .3), rng.normal(420, 60)
    return dict(counts=c, syn_ratio=float(syn), mean_size=float(max(40, size)))


def features(w):
    v = np.array(list(w["counts"].values()), float)
    tot = v.sum()
    p = v / tot
    return [float(tot), float(len(v)), float(-(p * np.log2(p)).sum()), float(v.max() / tot),
            float(np.median(v)), w["syn_ratio"], w["mean_size"]]
