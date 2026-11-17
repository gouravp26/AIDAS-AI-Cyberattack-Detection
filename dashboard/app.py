from pathlib import Path
from dashboard.live_monitor import monitor

import json
import joblib
import numpy as np
import pandas as pd
from flask import Flask, jsonify, render_template, request

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "models"

app = Flask(__name__)

preprocessor = joblib.load(MODEL_DIR / "preprocessor.joblib")

models = {
    "logistic_regression": joblib.load(
        MODEL_DIR / "logistic_regression.joblib"
    ),
    "decision_tree": joblib.load(
        MODEL_DIR / "decision_tree.joblib"
    ),
    "random_forest": joblib.load(
        MODEL_DIR / "random_forest.joblib"
    ),
    "isolation_forest": joblib.load(
        MODEL_DIR / "isolation_forest.joblib"
    ),
}

EXPECTED_FEATURES = list(preprocessor.feature_names_in_)

DATASET_PATH = (
    BASE_DIR / "data" / "raw" / "UNSW_NB15_testing-set.csv"
)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def status():
    return jsonify({
        "status": "running",
        "project": "AIDAS",
        "models_loaded": list(models.keys()),
        "expected_features": len(EXPECTED_FEATURES),
        "live_ml_validated": False,
    })


@app.route("/api/sample")
def sample():
    if not DATASET_PATH.exists():
        return jsonify({
            "error": "Testing dataset not found"
        }), 404

    df = pd.read_csv(DATASET_PATH, nrows=100)

    if df.empty:
        return jsonify({
            "error": "Testing dataset is empty"
        }), 400

    row = df.iloc[0]

    return jsonify({
        "features": {
            name: (
                None if pd.isna(row[name])
                else row[name].item()
                if hasattr(row[name], "item")
                else row[name]
            )
            for name in EXPECTED_FEATURES
        },
        "actual_attack_category": str(
            row.get("attack_cat", "Unknown")
        ),
        "actual_label": int(row.get("label", -1)),
    })


@app.route("/api/predict", methods=["POST"])
def predict():
    try:
        payload = request.get_json(silent=True)

        if not isinstance(payload, dict):
            return jsonify({
                "error": "Expected a JSON object"
            }), 400

        features = payload.get("features")
        model_name = payload.get("model", "random_forest")

        if model_name not in models:
            return jsonify({
                "error": "Unknown model"
            }), 400

        if model_name == "isolation_forest":
            return jsonify({
                "error": (
                    "Isolation Forest requires a separate "
                    "anomaly-detection endpoint."
                )
            }), 400

        if not isinstance(features, dict):
            return jsonify({
                "error": "Features must be a JSON object"
            }), 400

        missing = [
            name for name in EXPECTED_FEATURES
            if name not in features
        ]

        if missing:
            return jsonify({
                "error": "Missing required features",
                "missing": missing,
            }), 400

        row = pd.DataFrame(
            [{name: features[name] for name in EXPECTED_FEATURES}],
            columns=EXPECTED_FEATURES,
        )

        # Use the exact saved training preprocessor.
        transformed = preprocessor.transform(row)

        model = models[model_name]
        prediction = model.predict(transformed)[0]

        result = {
            "model": model_name,
            "prediction": str(prediction),
            "source": "compatible_dataset_features",
            "live_prediction": False,
        }

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(transformed)[0]

            result["class_probabilities"] = {
                str(label): float(prob)
                for label, prob in zip(
                    model.classes_,
                    probabilities,
                )
            }

        return jsonify(result)

    except (ValueError, TypeError, KeyError) as exc:
        return jsonify({
            "error": str(exc)
        }), 400

@app.route("/api/evaluation")
def evaluation():
    evaluation_path = (
        BASE_DIR / "dashboard" / "static" / "model_evaluation.json"
    )

    if not evaluation_path.exists():
        return jsonify({
            "error": "Model evaluation results not found"
        }), 404

    with open(evaluation_path, encoding="utf-8") as file:
        results = json.load(file)

    return jsonify(results)
@app.route("/api/anomaly", methods=["POST"])
def anomaly_analysis():
    try:
        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            return jsonify({
                "error": "A JSON object is required"
            }), 400

        features = data.get("features")

        if not isinstance(features, dict):
            return jsonify({
                "error": "Features must be a JSON object"
            }), 400

        expected = list(preprocessor.feature_names_in_)

        missing = [
            feature for feature in expected
            if feature not in features
        ]

        if missing:
            return jsonify({
                "error": "Missing required features",
                "missing_features": missing
            }), 400

        import pandas as pd
        import joblib

        from pathlib import Path

        row = pd.DataFrame(
            [{feature: features[feature] for feature in expected}]
        )

        transformed = preprocessor.transform(row)

        model_path = (
            Path(__file__).resolve().parent.parent
            / "models"
            / "isolation_forest.joblib"
        )

        model = joblib.load(model_path)

        if transformed.shape[1] != model.n_features_in_:
            return jsonify({
                "error": "Feature dimension mismatch"
            }), 500

        prediction = int(model.predict(transformed)[0])

        score = float(
            model.decision_function(transformed)[0]
        )

        return jsonify({
            "model": "Isolation Forest",
            "prediction": prediction,
            "status": (
                "Anomaly" if prediction == -1
                else "Inlier"
            ),
            "anomaly_score": score,
            "interpretation": (
                "Statistical anomaly detected; "
                "this does not confirm a cyberattack."
                if prediction == -1
                else
                "Sample is within the model's "
                "learned decision boundary."
            ),
            "live_ml_validated": False
        })

    except (ValueError, TypeError, KeyError) as error:
        return jsonify({
            "error": str(error)
        }), 400
@app.route("/api/live/status")
def live_status():
    return jsonify(monitor.get_status())


@app.route("/api/live/start", methods=["POST"])
def live_start():
    data = request.get_json(silent=True) or {}

    interface_index = data.get("interface_index", 22)

    result = monitor.start(interface_index)

    return jsonify(result), (
        200 if result["success"] else 400
    )


@app.route("/api/live/stop", methods=["POST"])
def live_stop():
    result = monitor.stop()

    return jsonify(result), (
        200 if result["success"] else 400
    )


@app.route("/api/live/flows")
def live_flows():
    return jsonify({
        "flows": monitor.get_flows(),
        "status": monitor.get_status(),
        "live_ml_validated": False
    })
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
