import json
from pathlib import Path

import joblib
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

BASE = Path(__file__).resolve().parent.parent

DATASET = BASE / "data/raw/UNSW_NB15_testing-set.csv"
MODEL_DIR = BASE / "models"
OUTPUT_DIR = BASE / "dashboard" / "static"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(DATASET)

preprocessor = joblib.load(
    MODEL_DIR / "preprocessor.joblib"
)

feature_names = list(preprocessor.feature_names_in_)

X = preprocessor.transform(df[feature_names])
y = df["attack_cat"]

model_files = {
    "Logistic Regression": "logistic_regression.joblib",
    "Decision Tree": "decision_tree.joblib",
    "Random Forest": "random_forest.joblib",
}

results = {}

for model_name, filename in model_files.items():

    print(f"\nEvaluating {model_name}...")

    model = joblib.load(MODEL_DIR / filename)

    predictions = model.predict(X)

    labels = [str(label) for label in model.classes_]

    actual_binary = (df["label"] == 1).astype(int)
    predicted_binary = (
        pd.Series(predictions) != "Normal"
    ).astype(int)

    tn = int(
        ((actual_binary == 0) & (predicted_binary == 0)).sum()
    )
    fp = int(
        ((actual_binary == 0) & (predicted_binary == 1)).sum()
    )
    fn = int(
        ((actual_binary == 1) & (predicted_binary == 0)).sum()
    )
    tp = int(
        ((actual_binary == 1) & (predicted_binary == 1)).sum()
    )

    results[model_name] = {
        "multiclass_accuracy": float(
            accuracy_score(y, predictions)
        ),
        "macro_f1": float(
            f1_score(y, predictions, average="macro")
        ),
        "weighted_f1": float(
            f1_score(y, predictions, average="weighted")
        ),
        "binary_accuracy": float(
            accuracy_score(actual_binary, predicted_binary)
        ),
        "false_positive_rate": float(
            fp / (fp + tn) if (fp + tn) else 0
        ),
        "false_negative_rate": float(
            fn / (fn + tp) if (fn + tp) else 0
        ),
        "binary_confusion": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
        "class_labels": labels,
        "confusion_matrix": confusion_matrix(
            y, predictions, labels=model.classes_
        ).tolist(),
        "classification_report": classification_report(
            y,
            predictions,
            output_dict=True,
            zero_division=0,
        ),
    }

    print(
        "Multiclass accuracy:",
        round(results[model_name]["multiclass_accuracy"], 4)
    )

    print(
        "Macro-F1:",
        round(results[model_name]["macro_f1"], 4)
    )

    print(
        "False-positive rate:",
        round(results[model_name]["false_positive_rate"], 4)
    )

output = OUTPUT_DIR / "model_evaluation.json"

with open(output, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=2)

print("\nSaved:", output)
print("STAGE 7.4: EVALUATION EXPORT COMPLETE")
