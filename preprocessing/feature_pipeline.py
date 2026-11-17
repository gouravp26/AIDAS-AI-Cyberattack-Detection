import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler

# AIDAS Stage 3 - feature preprocessing pipeline

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"
SAVE_PATH = "models/preprocessor.joblib"

DROP_COLS = ["id", "attack_cat", "label"]
CATEGORICAL_COLS = ["proto", "service", "state"]


def build_preprocessor(numeric_cols):
    return ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="infrequent_if_exist",
                    min_frequency=100,
                    sparse_output=False,
                ),
                CATEGORICAL_COLS,
            ),
            ("numeric", StandardScaler(), numeric_cols),
        ]
    )


if __name__ == "__main__":
    train = pd.read_csv(TRAIN_PATH)
    val = pd.read_csv(VAL_PATH)

    X_train = train.drop(columns=DROP_COLS)
    X_val = val.drop(columns=DROP_COLS)

    numeric_cols = [c for c in X_train.columns if c not in CATEGORICAL_COLS]

    preprocessor = build_preprocessor(numeric_cols)
    X_train_ready = preprocessor.fit_transform(X_train)  # learns from the training part only
    X_val_ready = preprocessor.transform(X_val)  # only applies what was learned

    print("Numeric columns         :", len(numeric_cols))
    print("Training matrix shape   :", X_train_ready.shape)
    print("Validation matrix shape :", X_val_ready.shape)
    print("Any NaN in training matrix:", bool(pd.DataFrame(X_train_ready).isnull().any().any()))

    joblib.dump(preprocessor, SAVE_PATH)
    print("Saved preprocessor to:", SAVE_PATH)