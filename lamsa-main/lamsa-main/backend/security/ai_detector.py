"""
FinGuard AI Behavioral Anomaly Detection Module
Uses Scikit-Learn Isolation Forest to detect anomalous client behavioral patterns.
"""
import time
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import IsolationForest
import threading

class AIBehavioralDetector:
    """
    AI Behavioral Anomaly Detector powered by Isolation Forest.
    Evaluates client request patterns against a baseline model of normal fintech traffic.
    """
    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        self._lock = threading.Lock()
        self.is_trained = False
        
        # Historical metrics for ratio calculation
        self.total_evaluations = 0
        self.anomaly_count = 0
        
        # Train light model on startup
        self.train_baseline_model()

    def train_baseline_model(self):
        """Train the Isolation Forest model on synthetic baseline 'normal' user behavior."""
        np.random.seed(42)
        n_samples = 600

        # Normal User Traffic Profile:
        # 1. request_rate_last_60s: 1 to 6 req/min
        req_rates = np.random.uniform(1.0, 6.0, n_samples)
        # 2. payload_length: 20 to 450 bytes
        payload_lens = np.random.uniform(20.0, 450.0, n_samples)
        # 3. token_age: 100 to 3600 seconds
        token_ages = np.random.uniform(100.0, 3600.0, n_samples)
        # 4. endpoint_risk_factor: 1.0 to 1.5
        risk_factors = np.random.uniform(1.0, 1.5, n_samples)
        # 5. time_of_day (hour): 8.0 to 18.0 (business hours)
        times_of_day = np.random.uniform(8.0, 18.0, n_samples)

        X_normal = np.column_stack([
            req_rates, payload_lens, token_ages, risk_factors, times_of_day
        ])

        with self._lock:
            self.model.fit(X_normal)
            self.is_trained = True
            print("[AI] Lamsa AI Isolation Forest Model trained on normal baseline traffic.")

    def evaluate_behavior(
        self,
        request_rate_60s: float,
        payload_length: float,
        token_age_seconds: float,
        endpoint_risk_factor: float,
        hour_of_day: float
    ) -> Dict[str, Any]:
        """
        Evaluates a single request vector against the Isolation Forest anomaly detector.
        Features vector: [request_rate_last_60s, payload_length, token_age, endpoint_risk_factor, time_of_day]
        """
        if not self.is_trained:
            return {"is_anomaly": False, "score": 0.0, "threat_boost": 0, "reasons": []}

        features = np.array([[
            float(request_rate_60s),
            float(payload_length),
            float(token_age_seconds),
            float(endpoint_risk_factor),
            float(hour_of_day)
        ]])

        with self._lock:
            prediction = self.model.predict(features)[0]  # 1: Normal, -1: Anomaly
            decision_score = float(self.model.decision_function(features)[0]) # Lower = more anomalous
            
            self.total_evaluations += 1

            # Anomaly criteria: prediction is -1 OR decision_score < -0.3
            is_anomaly = (prediction == -1) or (decision_score < -0.3)
            
            if is_anomaly:
                self.anomaly_count += 1

        reasons = []
        if is_anomaly:
            if request_rate_60s > 10:
                reasons.append(f"Abnormally high request rate: {request_rate_60s:.1f} req/min")
            if payload_length > 1500:
                reasons.append(f"Anomalous payload size: {payload_length:.0f} bytes")
            if token_age_seconds < 5:
                reasons.append(f"Suspiciously new/fresh token age: {token_age_seconds:.1f}s")
            if hour_of_day < 6 or hour_of_day > 22:
                reasons.append(f"Off-hours activity profile: Hour {hour_of_day:.1f}")
            if not reasons:
                reasons.append(f"Behavioral feature outlier (Isolation Forest score: {decision_score:.3f})")

        threat_boost = 50 if is_anomaly else 0

        return {
            "is_anomaly": is_anomaly,
            "decision_score": round(decision_score, 4),
            "threat_boost": threat_boost,
            "reasons": reasons
        }

    def get_metrics(self) -> Dict[str, Any]:
        with self._lock:
            total = self.total_evaluations
            anom = self.anomaly_count
            ratio = round((anom / total * 100), 1) if total > 0 else 0.0
            return {
                "total_evaluations": total,
                "anomaly_count": anom,
                "normal_count": max(0, total - anom),
                "anomaly_ratio_percent": ratio,
                "model_status": "ONLINE" if self.is_trained else "INITIALIZING"
            }

# Global AI Detector instance
ai_detector_instance = AIBehavioralDetector()
