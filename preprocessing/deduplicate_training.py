import pandas as pd

# AIDAS Stage 3 - remove exact duplicate rows from the training data

RAW_PATH = "data/raw/UNSW_NB15_training-set.csv"
OUTPUT_PATH = "data/processed/train_deduplicated.csv"

df = pd.read_csv(RAW_PATH)

# A duplicate = identical values in every column except id
compare_cols = [c for c in df.columns if c != "id"]
clean = df.drop_duplicates(subset=compare_cols, keep="first")

print("Rows before:", len(df))
print("Rows after :", len(clean))
print("Removed    :", len(df) - len(clean))

# Conflict check: same inputs, different answers (report only)
feature_cols = [c for c in df.columns if c not in ("id", "attack_cat", "label")]
cat_counts = clean.groupby(feature_cols)["attack_cat"].transform("nunique")
label_counts = clean.groupby(feature_cols)["label"].transform("nunique")

print()
print("Rows whose inputs also appear with a different attack_cat:", (cat_counts > 1).sum())
print("Rows whose inputs also appear with a different label     :", (label_counts > 1).sum())

clean.to_csv(OUTPUT_PATH, index=False)
print()
print("Saved to:", OUTPUT_PATH)