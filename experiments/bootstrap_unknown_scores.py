import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

# AIDAS Stage 5 - bootstrap uncertainty for the saved validation scores (no retraining).
# Metric: share of the withheld category flagged when about 5% of Normal flows are flagged.

CATEGORIES = ["Reconnaissance", "Fuzzers", "Exploits"]
TARGET = 0.05
N_BOOT = 500
rng = np.random.default_rng(42)


def flagged_at_matched(normal, withheld):
    y = np.r_[np.zeros(len(normal)), np.ones(len(withheld))]
    fpr, tpr, thr = roc_curve(y, np.r_[normal, withheld])
    t = thr[fpr <= TARGET][-1]
    return (withheld >= t).mean() * 100


def interval(values):
    lo, hi = np.percentile(values, [2.5, 97.5])
    return f"[{lo:5.1f}, {hi:5.1f}]"


print("Withheld category flagged (%) at a cutoff flagging about 5% of Normal; 95% bootstrap intervals")
print(f"{N_BOOT} resamples of the validation flows (paired for A and B)")
print()

for category in CATEGORIES:
    df = pd.read_csv("reports/unknown_" + category + "_scores.csv")
    normal = df[df["role"] == "normal"]
    withheld = df[df["role"] == "withheld"]
    na, nb = normal["a_score"].to_numpy(), normal["b_score"].to_numpy()
    wa, wb = withheld["a_score"].to_numpy(), withheld["b_score"].to_numpy()

    est_a = flagged_at_matched(na, wa)
    est_b = flagged_at_matched(nb, wb)

    boots_a, boots_b = [], []
    for _ in range(N_BOOT):
        i = rng.integers(0, len(na), len(na))
        j = rng.integers(0, len(wa), len(wa))
        boots_a.append(flagged_at_matched(na[i], wa[j]))
        boots_b.append(flagged_at_matched(nb[i], wb[j]))
    boots_a = np.array(boots_a)
    boots_b = np.array(boots_b)
    diff = boots_b - boots_a

    print(
        f"{category:15s} | A {est_a:5.1f}% {interval(boots_a)}"
        f" | B {est_b:5.1f}% {interval(boots_b)}"
        f" | B minus A {est_b - est_a:5.1f} {interval(diff)}"
    )