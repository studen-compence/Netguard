"""
NetGuard-Agent: Alert Storage Service
تخزين الـ alerts للـ dashboard والتحليل
"""

import logging
from collections import deque
from typing import List, Dict, Optional
from datetime import datetime, timedelta
import json
import os

logger = logging.getLogger(__name__)


class AlertStore:
    """
    In-memory alert storage with optional file persistence.
    Stores last N alerts for dashboard and analysis.
    """

    def __init__(self, max_alerts: int = 1000, persist_file: Optional[str] = None):
        """
        Initialize alert store.
        
        Args:
            max_alerts: Maximum alerts to keep in memory
            persist_file: Optional file path for persistence
        """
        self.max_alerts = max_alerts
        self.persist_file = persist_file
        self.alerts: deque = deque(maxlen=max_alerts)
        self.stats = {
            "total_processed": 0,
            "total_anomalies": 0,
            "severity_count": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "none": 0,
            }
        }

        # Load from file if exists
        if self.persist_file and os.path.exists(persist_file):
            self._load_from_file()

    def add_alert(self, alert: Dict) -> None:
        """Add an alert to storage"""
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.utcnow().isoformat()

        self.alerts.append(alert)
        severity = alert.get("severity", "none")
        self.stats["severity_count"][severity] += 1
        self.stats["total_processed"] += 1
        
        if alert.get("is_anomaly") or alert.get("anomaly_score", 0) > 0:
            self.stats["total_anomalies"] += 1

        logger.info(f"📌 Alert stored: {alert.get('title', 'Unknown')} ({severity})")

        # Persist if configured
        if self.persist_file:
            self._save_to_file()

    def add_alerts(self, alerts: List[Dict]) -> None:
        """Add multiple alerts"""
        for alert in alerts:
            self.add_alert(alert)

    def get_recent(self, limit: int = 50) -> List[Dict]:
        """Get recent alerts, newest first"""
        return list(reversed(list(self.alerts)))[:limit]

    def get_by_severity(self, severity: str, limit: int = 50) -> List[Dict]:
        """Get alerts filtered by severity"""
        filtered = [a for a in self.alerts if a.get("severity") == severity]
        return list(reversed(filtered))[:limit]

    def get_by_source_ip(self, ip: str, limit: int = 50) -> List[Dict]:
        """Get alerts from a specific source IP"""
        filtered = [a for a in self.alerts if a.get("source_ip") == ip]
        return list(reversed(filtered))[:limit]

    def get_stats(self) -> Dict:
        """Get aggregated statistics"""
        return {
            "total_alerts": len(self.alerts),
            "total_processed": self.stats["total_processed"],
            "anomalies_detected": self.stats["total_anomalies"],
            "severity_distribution": self.stats["severity_count"],
            "recent_alerts": self.get_recent(10),
        }

    def clear(self) -> None:
        """Clear all alerts"""
        self.alerts.clear()
        logger.info("🗑️  Alert store cleared")

    def _save_to_file(self) -> None:
        """Persist alerts to file"""
        if not self.persist_file:
            return
        try:
            data = {
                "timestamp": datetime.utcnow().isoformat(),
                "stats": self.stats,
                "alerts": list(self.alerts),
            }
            with open(self.persist_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"❌ Failed to save alerts: {e}")

    def _load_from_file(self) -> None:
        """Load alerts from file"""
        if not self.persist_file or not os.path.exists(self.persist_file):
            return
        try:
            with open(self.persist_file, "r") as f:
                data = json.load(f)
                for alert in data.get("alerts", []):
                    self.alerts.append(alert)
                self.stats = data.get("stats", self.stats)
            logger.info(f"✅ Loaded {len(self.alerts)} alerts from {self.persist_file}")
        except Exception as e:
            logger.error(f"❌ Failed to load alerts: {e}")


# =============================================
# Singleton
# =============================================

_store: Optional[AlertStore] = None


def get_alert_store(persist: bool = True) -> AlertStore:
    """Get or create alert store singleton"""
    global _store
    if _store is None:
        persist_file = "data/alerts.json" if persist else None
        if persist_file:
            os.makedirs(os.path.dirname(persist_file), exist_ok=True)
        _store = AlertStore(max_alerts=1000, persist_file=persist_file)
    return _store
