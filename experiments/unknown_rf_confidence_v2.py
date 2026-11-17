import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve

sys.path.insert(0, "preprocessing")
from feature_pipeline import build_preprocessor, DROP_COLS, CATEGORICAL_COLS  # type: ignore

# AIDAS Stage 5 - Option B (v2): Random Forest confidence as the "unknown" signal,
# with label analysis, a like-for-like comparison against Option A, and saved results.
# Usage: python experiments/unknown_rf_confidence_v2.py <withheld_category>

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"
BUDGETS = [0.01, 0.05, 0.10]  # share of KNOWN validation flows allowed to be flagged
FA_TARGETS = [0.01, 0.05]  # false-alarm rates on Normal flows for the A vs B comparison

if len(sys.argv) != 2:
    sys.exit("Usage: python experiments/unknown_rf_confidence_v2.py <withheld_category>")
withheld = sys.argv[1]

train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)

if withheld == "Normal" or withheld not in train["attack_cat"].unique():
    sys.exit("'" + withheld + "' is not a valid attack category.")

results = []  # rows of (category, measure, value) saved at the end


def record(measure, value):
    results.append((withheld, measure, round(float(value), 4)))


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
b_normal = score_known[(val_known["attack_cat"] == "Normal").to_numpy()]

accuracy = (pred_known == val_known["attack_cat"]).mean()
print("Withheld category         :", withheld)
print("Training rows (retained)  :", len(train_known))
print("Known validation rows     :", len(val_known))
print("Withheld validation rows  :", len(val_withheld))
print("Accuracy on known validation rows:", round(accuracy, 4))
record("known_accuracy", accuracy)

# 5. Cutoff-free separation for Option B
y_known = np.r_[np.zeros(len(score_known)), np.ones(len(score_withheld))]
auc_known = roc_auc_score(y_known, np.r_[score_known, score_withheld])
y_nw = np.r_[np.zeros(len(b_normal)), np.ones(len(score_withheld))]
auc_b = roc_auc_score(y_nw, np.r_[b_normal, score_withheld])
print()
print("B: ROC-AUC, withheld vs all known flows:", round(auc_known, 3))
print("B: ROC-AUC, withheld vs Normal only    :", round(auc_b, 3))
record("B_auc_vs_all_known", auc_known)
record("B_auc_vs_normal", auc_b)

# 6. Flag budgets: cutoffs come from KNOWN validation flows only
print()
print("B: cutoff set from known flows")
print("budget | withheld flagged | Normal flagged | known flagged")
for budget in BUDGETS:
    cutoff = np.quantile(score_known, 1 - budget)
    w = (score_withheld > cutoff).mean() * 100
    n = (b_normal > cutoff).mean() * 100
    k = (score_known > cutoff).mean() * 100
    print(f"{budget * 100:5.0f}% | {w:15.1f}% | {n:13.1f}% | {k:11.1f}%")
    record(f"B_withheld_flagged_pct_at_{int(budget * 100)}pct_budget", w)
    record(f"B_normal_flagged_pct_at_{int(budget * 100)}pct_budget", n)

# 7. Where do the withheld flows go? (false-negative analysis)
cutoff5 = np.quantile(score_known, 0.95)
not_flagged = score_withheld <= cutoff5
labels = (
    pd.DataFrame(
        {
            "all_withheld_pct": pd.Series(pred_withheld).value_counts(normalize=True) * 100,
            "not_flagged_at_5pct_budget_pct": pd.Series(pred_withheld[not_flagged]).value_counts(normalize=True) * 100,
        }
    )
    .fillna(0)
    .round(1)
    .sort_values("all_withheld_pct", ascending=False)
)
print()
print("Known label the model assigns to the withheld flows (percent)")
print(labels.to_string())

# 8. Like-for-like A vs B at a fixed false-alarm rate on Normal flows
pre_all = joblib.load("models/preprocessor.joblib")
iso = joblib.load("models/isolation_forest.joblib")


def a_score(frame):
    return -iso.decision_function(pre_all.transform(frame.drop(columns=DROP_COLS)))


a_normal = a_score(val[val["attack_cat"] == "Normal"])
a_withheld = a_score(val_withheld)


def operating_point(y_true, y_score, target):
    fpr, tpr, _ = roc_curve(y_true, y_score)
    keep = fpr <= target
    return fpr[keep][-1], tpr[keep][-1]


print()
print("A (Isolation Forest) vs B (RF confidence) at a fixed false-alarm rate on Normal")
print("target | A: Normal flagged | A: withheld flagged | B: Normal flagged | B: withheld flagged")
for t in FA_TARGETS:
    a_fa, a_tp = operating_point(y_nw, np.r_[a_normal, a_withheld], t)
    b_fa, b_tp = operating_point(y_nw, np.r_[b_normal, score_withheld], t)
    print(f"{t * 100:5.0f}% | {a_fa * 100:16.1f}% | {a_tp * 100:18.1f}% | {b_fa * 100:16.1f}% | {b_tp * 100:17.1f}%")
    record(f"A_withheld_flagged_pct_at_{int(t * 100)}pct_normal_fa", a_tp * 100)
    record(f"B_withheld_flagged_pct_at_{int(t * 100)}pct_normal_fa", b_tp * 100)

auc_a = roc_auc_score(y_nw, np.r_[a_normal, a_withheld])
pr_a = average_precision_score(y_nw, np.r_[a_normal, a_withheld])
pr_b = average_precision_score(y_nw, np.r_[b_normal, score_withheld])
print()
print("Withheld vs Normal only:  ROC-AUC A =", round(auc_a, 3), "| B =", round(auc_b, 3))
print("Withheld vs Normal only:  PR-AUC  A =", round(pr_a, 3), "| B =", round(pr_b, 3))
record("A_auc_vs_normal", auc_a)
record("A_pr_auc_vs_normal", pr_a)
record("B_pr_auc_vs_normal", pr_b)

# 9. Save the results
pd.DataFrame(results, columns=["category", "measure", "value"]).to_csv(
    "reports/unknown_" + withheld + "_summary.csv", index=False
)
labels.to_csv("reports/unknown_" + withheld + "_labels.csv")
print()
print("Saved: reports/unknown_" + withheld + "_summary.csv and reports/unknown_" + withheld + "_labels.csv")