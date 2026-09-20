import joblib
from pathlib import Path


MODEL_PATH = (
    Path(__file__).resolve().parent.parent
    / "models"
    / "xgboost_url_model.joblib"
)


def load_model():
    """
    Load the trained XGBoost model.
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def predict(features, model):
    """
    Make a phishing prediction.

    Parameters:
        features: Feature vector in the exact order
                   expected by the model.
        model: Loaded ML model.

    Returns:
        Prediction and probability.
    """

    prediction = model.predict([features])[0]

    probabilities = model.predict_proba([features])[0]

    phishing_probability = probabilities[1]

    if prediction == 1:
        label = "Phishing"
    else:
        label = "Legitimate"

    return {
        "prediction": label,
        "phishing_probability": float(
            phishing_probability
        )
    }