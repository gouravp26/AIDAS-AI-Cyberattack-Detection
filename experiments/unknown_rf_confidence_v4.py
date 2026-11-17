import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, "preprocessing")
from feature_pipeline import build_preprocessor, DROP_COLS, CATEGORICAL_COLS  # type: ignore

# AIDAS Stage 5 - Option B (v4): evaluation on the official test set.
# Cutoffs are fixed from the VALIDATION Normal flows only; nothing is tuned on the test set.
# Usage: python experiments/unknown_rf_confidence_v4.py <withheld_category>

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"
TRAIN_FULL_PATH = "data/processed/train_deduplicated.csv"
TEST_PATH = "data/raw/UNSW_NB15_testing-set.csv"
FA_TARGETS = [0.01, 0.05]  # share of Normal flows allowed to be flagged

if len(sys.argv) != 2:
    sys.exit("Usage: python experiments/unknown_rf_confidence_v4.py <withheld_category>")
withheld = sys.argv[1]

train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)
test = pd.read_csv(TEST_PATH)

if withheld == "Normal" or withheld not in train["attack_cat"].unique():
    sys.exit("'" + withheld + "' is not a valid attack category.")

# 1. Remove the withheld category from training
train_known = train[train["attack_cat"] != withheld]

# 2. Fresh preprocessor, fitted on the retained training rows only
X_train = train_known.drop(columns=DROP_COLS)
numeric_cols = [c for c in X_train.columns if c not in CATEGORICAL_COLS]
pre = build_preprocessor(numeric_cols)
X_train_ready = pre.fit_transform(X_train)

# 3. Train the Random Forest on the retained categories
model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
model.fit(X_train_ready, train_known["attack_cat"])

# Option A uses the saved baseline models, unchanged
pre_all = joblib.load("models/preprocessor.joblib")
iso = joblib.load("models/isolation_forest.joblib")


def b_score(frame):
    # Option B score = 1 - highest class probability (higher = more unfamiliar)
    proba = model.predict_proba(pre.transform(frame.drop(columns=DROP_COLS)))
    return 1.0 - proba.max(axis=1)


def a_score(frame):
    # Option A score = Isolation Forest anomaly score (higher = more unusual)
    return -iso.decision_function(pre_all.transform(frame.drop(columns=DROP_COLS)))


b_val, a_val = b_score(val), a_score(val)
b_test, a_test = b_score(test), a_score(test)

# 4. Cutoffs come from the validation Normal flows only
val_cats = val["attack_cat"].to_numpy()
test_cats = test["attack_cat"].to_numpy()
val_normal = val_cats == "Normal"
cutoffs = {}
for target in FA_TARGETS:
    cutoffs[("A", target)] = np.quantile(a_val[val_normal], 1 - target)
    cutoffs[("B", target)] = np.quantile(b_val[val_normal], 1 - target)

# 5. Which test rows also appear in the training data? (inputs only)
feature_cols = [c for c in test.columns if c not in DROP_COLS]
train_full = pd.read_csv(TRAIN_FULL_PATH)[feature_cols].drop_duplicates()
merged = test[feature_cols].merge(train_full, how="left", indicator=True)
in_training = (merged["_merge"] == "both").to_numpy()
print("Withheld category:", withheld)
print("Test rows whose inputs also appear in the training data:", int(in_training.sum()), "of", len(test))

rows = []


def report(dataset, cats, a_sc, b_sc, keep):
    cats, a_sc, b_sc = cats[keep], a_sc[keep], b_sc[keep]
    is_n = cats == "Normal"
    is_w = cats == withheld
    is_k = ~is_n & ~is_w
    for target in FA_TARGETS:
        for method, sc in [("A", a_sc), ("B", b_sc)]:
            flagged = sc > cutoffs[(method, target)]
            rows.append(
                {
                    "category": withheld,
                    "dataset": dataset,
                    "target_pct": target * 100,
                    "method": method,
                    "normal_n": int(is_n.sum()),
                    "withheld_n": int(is_w.sum()),
                    "known_attack_n": int(is_k.sum()),
                    "normal_flagged_pct": flagged[is_n].mean() * 100,
                    "withheld_flagged_pct": flagged[is_w].mean() * 100,
                    "known_attacks_flagged_pct": flagged[is_k].mean() * 100,
                }
            )


everything_val = np.ones(len(val_cats), dtype=bool)
everything_test = np.ones(len(test_cats), dtype=bool)
report("validation", val_cats, a_val, b_val, everything_val)
report("test_full", test_cats, a_test, b_test, everything_test)
report("test_no_overlap", test_cats, a_test, b_test, ~in_training)

out = pd.DataFrame(rows)

print()
print("Group sizes (flows)")
sizes = out[["dataset", "normal_n", "withheld_n", "known_attack_n"]].drop_duplicates()
print(sizes.to_string(index=False))

print()
print("Percent flagged; cutoffs fixed from validation Normal flows")
columns = [
    "dataset",
    "target_pct",
    "method",
    "normal_flagged_pct",
    "withheld_flagged_pct",
    "known_attacks_flagged_pct",
]
print(out[columns].round(1).to_string(index=False))

out.round(3).to_csv("reports/unknown_" + withheld + "_test.csv", index=False)
print()
print("Saved: reports/unknown_" + withheld + "_test.csv")