import pandas as pd
import joblib

from sklearn.tree import DecisionTreeClassifier

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score
)

# AIDAS Stage 4 - Decision Tree

TRAIN_PATH = "data/processed/train_part.csv"
VAL_PATH = "data/processed/validation_part.csv"

PREPROCESSOR_PATH = "models/preprocessor.joblib"
MODEL_PATH = "models/decision_tree.joblib"

DROP_COLS = ["id", "attack_cat", "label"]


# Load datasets
train = pd.read_csv(TRAIN_PATH)
val = pd.read_csv(VAL_PATH)


# Separate features and target
X_train = train.drop(columns=DROP_COLS)
y_train = train["attack_cat"]

X_val = val.drop(columns=DROP_COLS)
y_val = val["attack_cat"]


# Load fitted preprocessor
preprocessor = joblib.load(PREPROCESSOR_PATH)


# Transform features
X_train_ready = preprocessor.transform(X_train)
X_val_ready = preprocessor.transform(X_val)


print("Training matrix:", X_train_ready.shape)
print("Validation matrix:", X_val_ready.shape)


# Create Decision Tree model
model = DecisionTreeClassifier(
    criterion="gini",
    random_state=42
)


# Train model
print("\nTraining Decision Tree...")

model.fit(X_train_ready, y_train)


# Generate predictions
y_pred = model.predict(X_val_ready)


# Evaluate model
print("\n========== RESULTS ==========")

print("Accuracy:", accuracy_score(y_val, y_pred))

print("Macro F1-score:", f1_score(
    y_val,
    y_pred,
    average="macro"
))

print("\nClassification Report:")

print(classification_report(
    y_val,
    y_pred,
    zero_division=0
))

print("\nConfusion Matrix:")

print(confusion_matrix(
    y_val,
    y_pred,
    labels=model.classes_
))


# Save model
joblib.dump(model, MODEL_PATH)

print("\nModel saved to:", MODEL_PATH)