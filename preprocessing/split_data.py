import pandas as pd
from sklearn.model_selection import train_test_split

# AIDAS Stage 3 - split the deduplicated training data into train and validation parts

INPUT_PATH = "data/processed/train_deduplicated.csv"
TRAIN_OUT = "data/processed/train_part.csv"
VAL_OUT = "data/processed/validation_part.csv"

df = pd.read_csv(INPUT_PATH)

train_part, val_part = train_test_split(
    df,
    test_size=0.2,
    random_state=42,
    stratify=df["attack_cat"],
)

train_part.to_csv(TRAIN_OUT, index=False)
val_part.to_csv(VAL_OUT, index=False)

print("Train part rows     :", len(train_part))
print("Validation part rows:", len(val_part))

print()
print("Share of each category (percent): train vs validation")
shares = pd.DataFrame({
    "train_%": (train_part["attack_cat"].value_counts(normalize=True) * 100).round(2),
    "validation_%": (val_part["attack_cat"].value_counts(normalize=True) * 100).round(2),
})
print(shares.to_string())

# Leakage check: validation rows whose inputs also appear in the training part
feature_cols = [c for c in df.columns if c not in ("id", "attack_cat", "label")]
check = val_part[feature_cols].merge(
    train_part[feature_cols].drop_duplicates(), how="left", indicator=True
)
print()
print("Validation rows with identical inputs in the training part:", (check["_merge"] == "both").sum())
print("Saved to:", TRAIN_OUT, "and", VAL_OUT)