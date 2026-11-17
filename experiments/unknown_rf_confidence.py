import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score

sys.path.insert(0, "preprocessing")
from feature_pipeline import build_preprocessor, DROP_COLS, CATEGORICAL_COLS

# AIDAS Stage 5 - Option B: Random Forest confidence as the "unknown" signal
# Usage: python experiments/unknown_rf_confidence.py <withheld_category>

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"
BUDGETS = [0.01, 0.05, 0.10]  # share of known validation flows allowed to be flagged

if len(sys.argv) != 2:
    sys.exit("Usage: python experiments/unknown_rf_confidence.py <withheld_category>")
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


# 4. Unknown score = 1 - highest class probability (higher = more unfamiliar)
def score(frame):
    X = pre.transform(frame.drop(columns=DROP_COLS))
    proba = model.predict_proba(X)
    return model.classes_[proba.argmax(axis=1)], 1.0 - proba.max(axis=1)


pred_known, score_known = score(val_known)
_, score_withheld = score(val_withheld)
score_normal = score_known[(val_known["attack_cat"] == "Normal").to_numpy()]

print("Withheld category         :", withheld)
print("Training rows (retained)  :", len(train_known))
print("Known validation rows     :", len(val_known))
print("Withheld validation rows  :", len(val_withheld))
print("Accuracy on known validation rows:", round((pred_known == val_known["attack_cat"]).mean(), 4))

# Cutoff-free separation (ROC-AUC)
y_all = np.r_[np.zeros(len(score_known)), np.ones(len(score_withheld))]
auc_known = roc_auc_score(y_all, np.r_[score_known, score_withheld])
y_norm = np.r_[np.zeros(len(score_normal)), np.ones(len(score_withheld))]
auc_normal = roc_auc_score(y_norm, np.r_[score_normal, score_withheld])
print()
print("ROC-AUC, withheld vs all known flows:", round(auc_known, 3))
print("ROC-AUC, withheld vs Normal only    :", round(auc_normal, 3))

# Flag budgets: cutoffs come from KNOWN validation flows only
print()
print("budget | withheld flagged | Normal flagged | known flagged")
for budget in BUDGETS:
    cutoff = np.quantile(score_known, 1 - budget)
    w = (score_withheld > cutoff).mean() * 100
    n = (score_normal > cutoff).mean() * 100
    k = (score_known > cutoff).mean() * 100
    print(f"{budget * 100:5.0f}% | {w:15.1f}% | {n:13.1f}% | {k:11.1f}%")