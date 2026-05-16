"""
NetGuard-Agent: API Schemas
نماذج البيانات المستخدمة في API
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, field_validator
import re


# =============================================
# Input Schemas
# =============================================

class NetworkFlow(BaseModel):
    """A single network flow record"""
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: int = Field(..., ge=0, le=65535)
    destination_port: int = Field(..., ge=0, le=65535)
    protocol: str = Field(..., description="TCP, UDP, ICMP, etc.")
    bytes_sent: int = Field(..., ge=0, description="Bytes sent")
    bytes_received: int = Field(..., ge=0, description="Bytes received")
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow)

    @field_validator("protocol")
    @classmethod
    def protocol_upper(cls, v):
        return v.upper()

    model_config = {
        "json_schema_extra": {
            "example": {
                "source_ip": "192.168.1.100",
                "destination_ip": "8.8.8.8",
                "source_port": 54321,
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_sent": 1024,
                "bytes_received": 2048,
            }
        }
    }


class AnalyzeRequest(BaseModel):
    """Request body for /analyze endpoint"""
    flows: List[NetworkFlow] = Field(..., min_length=1, max_length=1000)
    threshold: float = Field(default=0.5, ge=0.0, le=1.0,
                              description="Anomaly score threshold (0-1). Lower = more sensitive")

    model_config = {
        "json_schema_extra": {
            "example": {
                "flows": [
                    {
                        "source_ip": "10.0.0.5",
                        "destination_ip": "185.220.101.45",
                        "source_port": 62341,
                        "destination_port": 22,
                        "protocol": "TCP",
                        "bytes_sent": 15_000_000,
                        "bytes_received": 200,
                    }
                ],
                "threshold": 0.5
            }
        }
    }


class IPCheckRequest(BaseModel):
    """Request to check a single IP"""
    ip_address: str
    include_recommendations: bool = True


# =============================================
# Output Schemas
# =============================================

class RuleDetection(BaseModel):
    """A single rule that was triggered"""
    rule_name: str
    severity: str
    description: str
    recommended_action: str


class FlowResult(BaseModel):
    """Per-flow analysis result"""
    flow_index: int
    source_ip: str
    destination_ip: str
    is_anomaly: bool
    anomaly_score: float = Field(..., description="0 = normal, 1 = highly anomalous")
    severity: str  # none | low | medium | high | critical
    rule_detections: List[RuleDetection]
    ml_flagged: bool


class SecurityAlert(BaseModel):
    """A security alert generated from a detected anomaly"""
    alert_id: str
    title: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    recommended_action: str
    anomaly_score: float
    rule_detections: List[Dict[str, Any]]
    ml_flagged: bool
    timestamp: str


class AnalyzeResponse(BaseModel):
    """Full response from /analyze endpoint"""
    analysis_id: str
    status: str = "completed"
    flows_analyzed: int
    anomalies_found: int
    alerts_generated: int
    alerts: List[SecurityAlert]
    flow_results: List[FlowResult]
    analysis_time_ms: float
    timestamp: str


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    detector_ready: bool


class StatsResponse(BaseModel):
    """Summary stats about the detector"""
    detector_ready: bool
    rules_loaded: int
    model_type: str
    supported_protocols: List[str]
    severity_levels: List[str]


class AlertExplanationResponse(BaseModel):
    """LLM-generated explanation of an alert"""
    explanation: str = Field(..., description="Executive summary")
    technical_reasoning: str = Field(..., description="Technical details")
    risk_analysis: str = Field(..., description="Why this is dangerous")
    recommended_actions: List[str] = Field(..., description="What to do about it")
    urgency_level: str = Field(..., description="immediate | high | medium | low")
    confidence: float = Field(..., ge=0.0, le=1.0)
    provider: str = Field(..., description="anthropic | openai | fallback")


class ExplainAlertRequest(BaseModel):
    """Request to explain an alert"""
    alert: dict = Field(..., description="Alert object to explain")


class MetricsResponse(BaseModel):
    """System metrics for dashboard"""
    total_alerts: int
    total_processed: int
    anomalies_detected: int
    severity_distribution: Dict[str, int]
    recent_alerts: List[SecurityAlert]
