"""
ml_model.py
Natural Language Processing and Machine Learning Engine for Phishing Detection.
Implements TF-IDF vectorization, Naive Bayes / Logistic Regression classification,
and feature importance extraction.
"""

import os
import joblib
from typing import Dict, Any, List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from phish_analyzer.dataset import EXPANDED_TRAINING_CORPUS

DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "trained_model.joblib")

class PhishingMLClassifier:
    """
    NLP and Machine Learning Classifier for email text.
    Provides probability scores, predicted classes, and top contributing features.
    Automatically loads serialized models from models/trained_model.joblib if available.
    """

    def __init__(self, model_type: str = "logistic_regression", model_path: str = DEFAULT_MODEL_PATH):
        self.model_type = model_type
        self.model_path = model_path
        self.is_trained = False
        self.is_large_model = False
        self.optimal_threshold = 0.50
        self.metadata: Dict[str, Any] = {}

        # 1. Attempt to load pre-trained large model artifact
        if os.path.isfile(self.model_path):
            try:
                data = joblib.load(self.model_path)
                self.vectorizer = data["vectorizer"]
                self.model = data["model"]
                self.model_type = data.get("model_type", model_type)
                self.optimal_threshold = float(data.get("optimal_threshold", 0.50))
                self.metadata = data.get("metrics", {})
                self.metadata["dataset"] = data.get("trained_dataset", "Unknown")
                self.metadata["optimal_threshold"] = self.optimal_threshold
                self.metadata["created_at"] = data.get("created_at", "")
                self.is_trained = True
                self.is_large_model = True
                return
            except Exception as e:
                print(f"[*] Warning: Could not load serialized model ({e}), falling back to default.")

        # 2. Fallback to lightweight default training
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            max_features=500,
            token_pattern=r"(?u)\b[a-zA-Z0-9_\-\.\$]{2,}\b"
        )
        if model_type == "naive_bayes":
            self.model = MultinomialNB()
        else:
            self.model = LogisticRegression(C=1.0, max_iter=200, random_state=42)
        
        self._train_default_model()

    def _train_default_model(self):
        """Trains the model on the expanded synthetic corpus."""
        texts = [item["text"] for item in EXPANDED_TRAINING_CORPUS]
        labels = [1 if item["label"] == "Phishing" else 0 for item in EXPANDED_TRAINING_CORPUS]

        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)
        self.is_trained = True
        self.is_large_model = False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Predicts whether a text is Phishing (1) or Legitimate (0).
        Returns class, probability, and top contributing keywords.
        """
        if not self.is_trained:
            self._train_default_model()

        X_input = self.vectorizer.transform([text])
        proba = self.model.predict_proba(X_input)[0]  # [prob_legit, prob_phish]
        phish_prob = float(proba[1])
        prediction = "Phishing" if phish_prob >= self.optimal_threshold else "Legitimate"

        # Feature explanation (which tokens contributed most)
        feature_names = self.vectorizer.get_feature_names_out()
        tokens_in_text = self.vectorizer.inverse_transform(X_input)[0]

        contributing_keywords: List[Tuple[str, float]] = []
        if hasattr(self.model, "coef_"):
            coefficients = self.model.coef_[0]
            token_weights = []
            for token in tokens_in_text:
                if token in self.vectorizer.vocabulary_:
                    idx = self.vectorizer.vocabulary_[token]
                    weight = coefficients[idx]
                    token_weights.append((token, float(weight)))
            # Sort by absolute weight
            token_weights.sort(key=lambda x: abs(x[1]), reverse=True)
            contributing_keywords = token_weights[:5]

        return {
            "prediction": prediction,
            "phishing_probability": round(phish_prob, 4),
            "legitimate_probability": round(float(proba[0]), 4),
            "confidence": round(max(phish_prob, float(proba[0])), 4),
            "contributing_features": contributing_keywords
        }
