import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score, roc_curve

sys.path.insert(0, "preprocessing")
from feature_pipeline import build_preprocessor, DROP_COLS, CATEGORICAL_COLS  # type: ignore

# AIDAS Stage 5 - Option B (v3): saves per-flow scores and counts how many KNOWN attacks
# are flagged at Normal-matched cutoffs, for both Option A and Option B.
# Usage: python experiments/unknown_rf_confidence_v3.py <withheld_category>

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"
FA_TARGETS = [0.01, 0.05]  # false-alarm rates on Normal flows

if len(sys.argv) != 2:
    sys.exit("Usage: python experiments/unknown_rf_confidence_v3.py <withheld_category>")
withheld = sys.argv[1]

train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)

if withheld == "Normal" or withheld not in train["attack_cat"].unique():
    sys.exit("'" + withheld + "' is not a valid attack category.")

# 1. Remove the withheld category from training
train_known = train[train["attack_cat"] != withheld]
val_known = val[val["attack_cat"] != withheld]
val_withheld = val[val["attack_cat"] == withheld]

# 2. Fresh preprocessor, fitted on the retained training rows only
X_train = train_known.drop(columns=DROP_COLS)
numeric_cols = [c for c in X_train.columns if c not in CATEGORICAL_COLS]
pre = build_preprocessor(numeric_cols)
X_train_ready = pre.fit_transform(X_train)
y_train = train_known["attack_cat"]

# 3. Train the Random Forest on the retained categories
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train_ready, y_train)


# 4. Option B score = 1 - highest class probability (higher = more unfamiliar)
def b_score(frame):
    X = pre.transform(frame.drop(columns=DROP_COLS))
    proba = model.predict_proba(X)
    return model.classes_[proba.argmax(axis=1)], 1.0 - proba.max(axis=1)


pred_known, score_known = b_score(val_known)
pred_withheld, score_withheld = b_score(val_withheld)

# 5. Option A score = Isolation Forest anomaly score (saved baseline model, unchanged)
pre_all = joblib.load("models/preprocessor.joblib")
iso = joblib.load("models/isolation_forest.joblib")


def a_score(frame):
    return -iso.decision_function(pre_all.transform(frame.drop(columns=DROP_COLS)))


a_known = a_score(val_known)
a_withheld = a_score(val_withheld)

is_normal = (val_known["attack_cat"] == "Normal").to_numpy()
is_attack = ~is_normal  # known attacks = every retained attack category

# Sanity checks (should match the v2 run)
accuracy = (pred_known == val_known["attack_cat"]).mean()
y_nw = np.r_[np.zeros(is_normal.sum()), np.ones(len(score_withheld))]
auc_b = roc_auc_score(y_nw, np.r_[score_known[is_normal], score_withheld])
print("Withheld category         :", withheld)
print("Training rows (retained)  :", len(train_known))
print("Known validation rows     :", len(val_known))
print("Withheld validation rows  :", len(val_withheld))
print("Known attack rows         :", int(is_attack.sum()))
print("Accuracy on known validation rows:", round(accuracy, 4))
print("B: ROC-AUC, withheld vs Normal only:", round(auc_b, 3))


# 6. Normal-matched cutoffs: the cutoff is set from the Normal flows only
def matched(normal, withheld_scores, known_attack, target):
    y = np.r_[np.zeros(len(normal)), np.ones(len(withheld_scores))]
    fpr, tpr, thr = roc_curve(y, np.r_[normal, withheld_scores])
    keep = fpr <= target
    t = thr[keep][-1]
    return (
        t,
        (normal >= t).mean() * 100,
        (withheld_scores >= t).mean() * 100,
        (known_attack >= t).mean() * 100,
    )


rows = []
print()
print("Cutoff set so that about 1% or 5% of Normal flows are flagged")
print("target | method               | Normal flagged | withheld flagged | known attacks flagged")
for target in FA_TARGETS:
    for method, normal, wh, ka in [
        ("A (Isolation Forest)", a_known[is_normal], a_withheld, a_known[is_attack]),
        ("B (RF confidence)", score_known[is_normal], score_withheld, score_known[is_attack]),
    ]:
        t, n, w, k = matched(normal, wh, ka, target)
        print(f"{target * 100:5.0f}% | {method:20s} | {n:13.1f}% | {w:15.1f}% | {k:20.1f}%")
        rows.append(
            {
                "category": withheld,
                "target_pct": target * 100,
                "method": method,
                "cutoff": t,
                "normal_flagged_pct": n,
                "withheld_flagged_pct": w,
                "known_attacks_flagged_pct": k,
            }
        )

# 7. Save the matched table and the per-flow scores
pd.DataFrame(rows).round(4).to_csv("reports/unknown_" + withheld + "_matched.csv", index=False)

scores_df = pd.concat(
    [
        pd.DataFrame(
            {
                "attack_cat": val_known["attack_cat"].to_numpy(),
                "b_label": pred_known,
                "b_score": score_known,
                "a_score": a_known,
            }
        ),
        pd.DataFrame(
            {
                "attack_cat": val_withheld["attack_cat"].to_numpy(),
                "b_label": pred_withheld,
                "b_score": score_withheld,
                "a_score": a_withheld,
            }
        ),
    ],
    ignore_index=True,
)
scores_df["role"] = np.where(
    scores_df["attack_cat"] == withheld,
    "withheld",
    np.where(scores_df["attack_cat"] == "Normal", "normal", "known_attack"),
)
scores_df.to_csv("reports/unknown_" + withheld + "_scores.csv", index=False)

print()
print("Saved: reports/unknown_" + withheld + "_matched.csv and reports/unknown_" + withheld + "_scores.csv")