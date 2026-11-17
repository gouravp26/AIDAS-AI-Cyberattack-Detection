import pandas as pd
import joblib

from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

# File paths
TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"

PREPROCESSOR_PATH = "models/preprocessor.joblib"
MODEL_PATH = "models/isolation_forest.joblib"

DROP_COLS = ["id", "attack_cat", "label"]


# Load datasets
train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)

# Select only normal traffic for training
normal_train = train[train["label"] == 0].copy()

print("Total training rows:", len(train))
print("Normal training rows:", len(normal_train))
print("Validation rows:", len(val))


# Separate features
X_train = normal_train.drop(columns=DROP_COLS)
X_val = val.drop(columns=DROP_COLS)

# Actual binary labels for validation
y_val = val["label"]


# Load existing preprocessing pipeline
preprocessor = joblib.load(PREPROCESSOR_PATH)

X_train_ready = preprocessor.transform(X_train)
X_val_ready = preprocessor.transform(X_val)

print("\nTraining matrix:", X_train_ready.shape)
print("Validation matrix:", X_val_ready.shape)


# Create Isolation Forest
model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42,
    n_jobs=-1
)

# Train using normal traffic only
print("\nTraining Isolation Forest...")

model.fit(X_train_ready)


# Predict validation data
# Isolation Forest: 1 = normal, -1 = anomaly
raw_predictions = model.predict(X_val_ready)

# Convert predictions to our binary label format
# 0 = normal, 1 = attack/anomaly
y_pred = (raw_predictions == -1).astype(int)


# Evaluation
print("\n========== ISOLATION FOREST RESULTS ==========")

print("Accuracy:", accuracy_score(y_val, y_pred))

print(
    "Macro F1-score:",
    f1_score(y_val, y_pred, average="macro")
)

print("\nClassification Report:")

print(
    classification_report(
        y_val,
        y_pred,
        labels=[0, 1],
        target_names=["Normal", "Attack/Anomaly"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")

print(confusion_matrix(y_val, y_pred, labels=[0, 1]))


# Save model
joblib.dump(model, MODEL_PATH)

print("\nModel saved to:", MODEL_PATH)