"""
NetGuard-Agent: Anomaly Detection Engine
القلب الحقيقي للمشروع - يكتشف الأنماط الخطيرة في بيانات الشبكة
"""

import uuid
import numpy as np
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import logging

logger = logging.getLogger(__name__)


# =============================================
# Feature Engineering
# =============================================

def extract_features(flows: List[Dict]) -> pd.DataFrame:
    """
    Convert raw network flows to ML features.
    يحول بيانات الشبكة الخام إلى features قابلة للتحليل
    """
    records = []

    for f in flows:
        # Traffic ratio: كمية البيانات المرسلة مقارنة بالمستقبلة
        total = f["bytes_sent"] + f["bytes_received"] + 1
        ratio = f["bytes_sent"] / total

        # Port risk: البورتات المعروفة = خطر أقل
        dst_port = f["destination_port"]
        well_known_ports = {80, 443, 22, 25, 53, 3306, 5432}
        port_risk = 0 if dst_port in well_known_ports else (1 if dst_port < 1024 else 2)

        # Protocol encoding
        protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2, "OTHER": 3}
        proto_enc = protocol_map.get(f["protocol"].upper(), 3)

        # Volume
        log_bytes = np.log1p(total)

        records.append({
            "bytes_sent": f["bytes_sent"],
            "bytes_received": f["bytes_received"],
            "traffic_ratio": ratio,
            "port_risk": port_risk,
            "protocol_enc": proto_enc,
            "log_bytes": log_bytes,
            "dst_port": dst_port,
            "src_port": f["source_port"],
        })

    return pd.DataFrame(records)


# =============================================
# Threat Rules (Rule-based layer)
# =============================================

THREAT_RULES = [
    {
        "name": "Port Scanning",
        "severity": "high",
        "check": lambda f: f["source_port"] > 60000 and f["destination_port"] < 1024,
        "description": "Source using ephemeral port targeting privileged destination port — classic scan pattern",
        "action": "Block source IP and investigate",
    },
    {
        "name": "Data Exfiltration",
        "severity": "critical",
        "check": lambda f: f["bytes_sent"] > 10_000_000 and f["bytes_received"] < 1000,
        "description": "Massive outbound data with minimal response — possible data exfiltration",
        "action": "Immediately block connection and alert security team",
    },
    {
        "name": "Suspicious Protocol on Common Port",
        "severity": "medium",
        "check": lambda f: f["destination_port"] == 443 and f["protocol"].upper() == "UDP",
        "description": "UDP traffic on port 443 — HTTPS should be TCP",
        "action": "Inspect traffic with DPI",
    },
    {
        "name": "High Volume UDP Flood",
        "severity": "high",
        "check": lambda f: f["protocol"].upper() == "UDP" and f["bytes_sent"] > 5_000_000,
        "description": "Very high UDP traffic — possible DDoS or amplification attack",
        "action": "Rate limit source and alert NOC",
    },
    {
        "name": "Internal Reconnaissance",
        "severity": "medium",
        "check": lambda f: (
            f["source_ip"].startswith("192.168.") and
            not f["destination_ip"].startswith("192.168.") and
            f["destination_port"] in [21, 23, 3389, 5900]
        ),
        "description": "Internal host connecting to suspicious remote ports (FTP/Telnet/RDP/VNC)",
        "action": "Investigate internal host for compromise",
    },
]


def apply_rules(flow: Dict) -> List[Dict]:
    """Apply rule-based detection on a single flow"""
    triggered = []
    for rule in THREAT_RULES:
        try:
            if rule["check"](flow):
                triggered.append({
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "description": rule["description"],
                    "recommended_action": rule["action"],
                })
        except Exception:
            pass
    return triggered


# =============================================
# Anomaly Detector (ML layer)
# =============================================

class AnomalyDetector:
    """
    Isolation Forest-based anomaly detector.
    Uses unsupervised learning — no labels needed.
    مكتشف الشذوذ بالذكاء الاصطناعي — لا يحتاج بيانات مصنفة
    """

    def __init__(self, contamination: float = 0.05):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False
        self._fit_on_synthetic()

    def _fit_on_synthetic(self):
        """
        Pre-train on synthetic 'normal' traffic so the model can
        detect anomalies even on the first real request.
        نتدرب على بيانات اصطناعية لتجنب مشكلة cold start
        """
        np.random.seed(42)
        n = 2000

        normal = pd.DataFrame({
            "bytes_sent": np.random.randint(100, 50_000, n),
            "bytes_received": np.random.randint(500, 100_000, n),
            "traffic_ratio": np.random.uniform(0.1, 0.7, n),
            "port_risk": np.random.choice([0, 1], n, p=[0.8, 0.2]),
            "protocol_enc": np.random.choice([0, 1], n, p=[0.7, 0.3]),
            "log_bytes": np.random.uniform(6, 12, n),
            "dst_port": np.random.choice([80, 443, 53, 22, 3000, 8080], n),
            "src_port": np.random.randint(1024, 65535, n),
        })

        X = self.scaler.fit_transform(normal)
        self.model.fit(X)
        self.is_fitted = True
        logger.info("✅ AnomalyDetector pre-trained on synthetic normal traffic")

    def predict(self, flows: List[Dict]) -> List[Dict]:
        """
        Analyze a list of network flows.
        Returns per-flow results with anomaly scores.
        """
        if not flows:
            return []

        df = extract_features(flows)
        X = self.scaler.transform(df)

        raw_scores = self.model.decision_function(X)   # higher = more normal
        predictions = self.model.predict(X)            # -1 = anomaly, 1 = normal

        # Normalize score to [0, 1] where 1 = most anomalous
        min_s, max_s = raw_scores.min(), raw_scores.max()
        span = max_s - min_s if max_s != min_s else 1
        normalized = 1 - (raw_scores - min_s) / span

        results = []
        for i, (flow, pred, score) in enumerate(zip(flows, predictions, normalized)):
            is_anomaly = pred == -1
            rule_hits = apply_rules(flow)

            # Merge severity: rules override ML when they fire
            if rule_hits:
                severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                top_rule = max(rule_hits, key=lambda r: severity_map.get(r["severity"], 0))
                severity = top_rule["severity"]
            elif is_anomaly:
                severity = "high" if score > 0.8 else "medium" if score > 0.6 else "low"
            else:
                severity = "none"

            results.append({
                "flow_index": i,
                "source_ip": flow["source_ip"],
                "destination_ip": flow["destination_ip"],
                "is_anomaly": is_anomaly or bool(rule_hits),
                "anomaly_score": round(float(score), 4),
                "severity": severity,
                "rule_detections": rule_hits,
                "ml_flagged": is_anomaly,
            })

        return results


# =============================================
# Singleton — one model instance for the app
# =============================================

_detector: Optional[AnomalyDetector] = None


def get_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        logger.info("🔄 Initializing AnomalyDetector...")
        _detector = AnomalyDetector()
    return _detector


# =============================================
# Alert Builder
# =============================================

def build_alerts(flow_results: List[Dict], flows: List[Dict]) -> List[Dict]:
    """Build structured security alerts from detection results"""
    alerts = []

    for result in flow_results:
        if not result["is_anomaly"]:
            continue

        alert_id = str(uuid.uuid4())[:8]
        flow = flows[result["flow_index"]]

        # Compose title
        if result["rule_detections"]:
            top = result["rule_detections"][0]
            title = top["rule_name"]
            description = top["description"]
            action = top["recommended_action"]
        else:
            title = "ML Anomaly Detected"
            description = (
                f"Unusual traffic pattern from {result['source_ip']} "
                f"to {result['destination_ip']}:{flow['destination_port']} "
                f"(score: {result['anomaly_score']})"
            )
            action = "Review traffic logs and verify legitimacy"

        alerts.append({
            "alert_id": alert_id,
            "title": title,
            "severity": result["severity"],
            "source_ip": result["source_ip"],
            "destination_ip": result["destination_ip"],
            "description": description,
            "recommended_action": action,
            "anomaly_score": result["anomaly_score"],
            "rule_detections": result["rule_detections"],
            "ml_flagged": result["ml_flagged"],
            "timestamp": datetime.utcnow().isoformat(),
        })

    return alerts
