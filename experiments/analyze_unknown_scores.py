import numpy as np
import pandas as pd
from sklearn.metrics import roc_curve

# AIDAS Stage 5 - which true categories get flagged at the Normal-matched cutoff?
# Reads the per-flow score files saved by unknown_rf_confidence_v3.py (no retraining).

CATEGORIES = ["Reconnaissance", "Fuzzers", "Exploits"]
TARGET = 0.05  # cutoff chosen so that about 5% of Normal flows are flagged


def matched_cutoff(normal, withheld, target):
    y = np.r_[np.zeros(len(normal)), np.ones(len(withheld))]
    fpr, tpr, thr = roc_curve(y, np.r_[normal, withheld])
    return thr[fpr <= target][-1]


for category in CATEGORIES:
    df = pd.read_csv("reports/unknown_" + category + "_scores.csv")
    normal = df[df["role"] == "normal"]
    withheld = df[df["role"] == "withheld"]

    t_a = matched_cutoff(normal["a_score"].to_numpy(), withheld["a_score"].to_numpy(), TARGET)
    t_b = matched_cutoff(normal["b_score"].to_numpy(), withheld["b_score"].to_numpy(), TARGET)
    df["A_flagged"] = df["a_score"] >= t_a
    df["B_flagged"] = df["b_score"] >= t_b

    table = df.groupby("attack_cat").agg(
        rows=("attack_cat", "size"),
        A_flagged_pct=("A_flagged", lambda s: round(s.mean() * 100, 1)),
        B_flagged_pct=("B_flagged", lambda s: round(s.mean() * 100, 1)),
    )
    table["note"] = np.where(table.index == category, "<-- withheld", "")

    print()
    print("Withheld:", category, "| cutoffs set so about 5% of Normal flows are flagged")
    print(table.sort_values("B_flagged_pct", ascending=False).to_string())