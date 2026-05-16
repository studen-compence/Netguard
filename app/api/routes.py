"""
NetGuard-Agent: API Routes
الـ endpoints الحقيقية اللي تشتغل فعلاً
"""

import time
import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, HTTPException, status

from app.schemas.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    FlowResult,
    SecurityAlert,
    RuleDetection,
    HealthResponse,
    StatsResponse,
    IPCheckRequest,
    AlertExplanationResponse,
    ExplainAlertRequest,
    MetricsResponse,
)
from app.core.detector import get_detector, build_alerts, THREAT_RULES
from app.services.llm_explainer import get_explainer
from app.services.alert_store import get_alert_store

router = APIRouter()


# =============================================
# Health
# =============================================

@router.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Health check — verifies the detector is loaded and ready"""
    detector = get_detector()
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
        detector_ready=detector.is_fitted,
    )


@router.get("/stats", response_model=StatsResponse, tags=["System"])
async def stats():
    """Returns information about the detection engine"""
    detector = get_detector()
    return StatsResponse(
        detector_ready=detector.is_fitted,
        rules_loaded=len(THREAT_RULES),
        model_type="IsolationForest + Rule-Based Hybrid",
        supported_protocols=["TCP", "UDP", "ICMP"],
        severity_levels=["none", "low", "medium", "high", "critical"],
    )


# =============================================
# Core: Analyze endpoint
# =============================================

@router.post("/analyze", response_model=AnalyzeResponse, tags=["Detection"])
async def analyze_flows(request: AnalyzeRequest):
    """
    **Main detection endpoint.**

    Accepts a list of network flows and returns:
    - Per-flow anomaly scores
    - Rule-based detections (port scanning, exfiltration, etc.)
    - ML-based anomaly detection (IsolationForest)
    - Structured security alerts

    The hybrid approach means:
    - Rules catch known attack patterns instantly
    - ML catches unknown/novel anomalies
    """
    start = time.perf_counter()

    detector = get_detector()
    store = get_alert_store()

    # Convert Pydantic models to plain dicts for the detector
    flows_raw = [f.model_dump() for f in request.flows]

    # Run detection
    flow_results_raw = detector.predict(flows_raw)

    # Filter by user threshold
    for r in flow_results_raw:
        if r["anomaly_score"] < request.threshold and not r["rule_detections"]:
            r["is_anomaly"] = False
            r["severity"] = "none"

    # Build alerts
    alerts_raw = build_alerts(flow_results_raw, flows_raw)

    # Store alerts
    store.add_alerts(alerts_raw)

    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

    # Convert to response schemas
    flow_results = [
        FlowResult(
            flow_index=r["flow_index"],
            source_ip=r["source_ip"],
            destination_ip=r["destination_ip"],
            is_anomaly=r["is_anomaly"],
            anomaly_score=r["anomaly_score"],
            severity=r["severity"],
            rule_detections=[RuleDetection(**rd) for rd in r["rule_detections"]],
            ml_flagged=r["ml_flagged"],
        )
        for r in flow_results_raw
    ]

    alerts = [SecurityAlert(**a) for a in alerts_raw]

    return AnalyzeResponse(
        analysis_id=str(uuid.uuid4())[:12],
        flows_analyzed=len(request.flows),
        anomalies_found=sum(1 for r in flow_results if r.is_anomaly),
        alerts_generated=len(alerts),
        alerts=alerts,
        flow_results=flow_results,
        analysis_time_ms=elapsed_ms,
        timestamp=datetime.utcnow().isoformat(),
    )


# =============================================
# NEW: LLM Alert Explanation
# =============================================

@router.post("/explain-alert", response_model=AlertExplanationResponse, tags=["AI Analysis"])
async def explain_alert(request: ExplainAlertRequest):
    """
    **Use LLM to explain a security alert in detail.**

    Provides:
    - Executive summary
    - Technical reasoning
    - Risk analysis
    - Recommended actions
    - Urgency level

    Supports:
    - Anthropic Claude (primary)
    - OpenAI GPT-4 (fallback)
    - Local fallback when no API available

    Example:
    ```json
    {
      "alert": {
        "title": "Data Exfiltration",
        "severity": "critical",
        "source_ip": "192.168.1.55",
        "anomaly_score": 0.99
      }
    }
    ```
    """
    explainer = get_explainer()
    result = explainer.explain(request.alert)
    return AlertExplanationResponse(**result)


# =============================================
# NEW: Dashboard Metrics
# =============================================

@router.get("/metrics", response_model=MetricsResponse, tags=["Dashboard"])
async def get_metrics():
    """
    **Get system metrics for dashboard.**

    Returns:
    - Total alerts generated
    - Total flows processed
    - Anomalies detected
    - Severity distribution
    - Recent alerts (last 10)
    """
    store = get_alert_store()
    stats = store.get_stats()

    return MetricsResponse(
        total_alerts=stats["total_alerts"],
        total_processed=stats["total_processed"],
        anomalies_detected=stats["anomalies_detected"],
        severity_distribution=stats["severity_distribution"],
        recent_alerts=[SecurityAlert(**a) for a in stats["recent_alerts"]],
    )


@router.get("/alerts/recent", tags=["Dashboard"])
async def get_recent_alerts(limit: int = 50):
    """Get recent alerts, newest first."""
    store = get_alert_store()
    alerts = store.get_recent(limit)
    return {
        "count": len(alerts),
        "alerts": alerts,
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/alerts/severity/{severity}", tags=["Dashboard"])
async def get_alerts_by_severity(severity: str, limit: int = 50):
    """Filter alerts by severity level."""
    store = get_alert_store()
    valid_severities = ["critical", "high", "medium", "low", "none"]
    if severity not in valid_severities:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid severity. Must be one of: {valid_severities}"
        )
    alerts = store.get_by_severity(severity, limit)
    return {
        "severity": severity,
        "count": len(alerts),
        "alerts": alerts,
    }


@router.get("/alerts/source/{source_ip}", tags=["Dashboard"])
async def get_alerts_by_source(source_ip: str, limit: int = 50):
    """Get alerts from a specific source IP."""
    store = get_alert_store()
    alerts = store.get_by_source_ip(source_ip, limit)
    return {
        "source_ip": source_ip,
        "count": len(alerts),
        "alerts": alerts,
    }


# =============================================
# Quick IP check
# =============================================

@router.post("/check-ip", tags=["Detection"])
async def check_ip(request: IPCheckRequest):
    """
    Quick check: send a minimal flow from/to an IP to see
    if it matches any known threat rules.
    """
    # Simulate a connection attempt from this IP
    test_flow = {
        "source_ip": request.ip_address,
        "destination_ip": "10.0.0.1",
        "source_port": 63412,
        "destination_port": 80,
        "protocol": "TCP",
        "bytes_sent": 500,
        "bytes_received": 1200,
    }

    from app.core.detector import apply_rules
    rule_hits = apply_rules(test_flow)

    risk_level = "low"
    if any(r["severity"] == "critical" for r in rule_hits):
        risk_level = "critical"
    elif any(r["severity"] == "high" for r in rule_hits):
        risk_level = "high"
    elif any(r["severity"] == "medium" for r in rule_hits):
        risk_level = "medium"

    return {
        "ip_address": request.ip_address,
        "risk_level": risk_level,
        "rule_hits": rule_hits,
        "checked_at": datetime.utcnow().isoformat(),
    }


# =============================================
# Demo: Generate test flows
# =============================================

@router.get("/demo-flows", tags=["Demo"])
async def demo_flows():
    """
    Returns example flows you can paste into /analyze.
    Includes both normal and malicious patterns.
    """
    return {
        "description": "Paste the 'flows' list into POST /analyze to see the detector in action",
        "flows": [
            # Normal traffic
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "142.250.80.46",
                "source_port": 52341,
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_sent": 1500,
                "bytes_received": 45000,
            },
            # Port scan pattern
            {
                "source_ip": "203.0.113.99",
                "destination_ip": "192.168.1.10",
                "source_port": 63412,   # ephemeral
                "destination_port": 22,  # SSH
                "protocol": "TCP",
                "bytes_sent": 60,
                "bytes_received": 0,
            },
            # Data exfiltration pattern
            {
                "source_ip": "192.168.1.55",
                "destination_ip": "185.220.101.45",
                "source_port": 49201,
                "destination_port": 8080,
                "protocol": "TCP",
                "bytes_sent": 25_000_000,   # 25 MB out
                "bytes_received": 150,
            },
            # Suspicious UDP on 443
            {
                "source_ip": "10.0.0.8",
                "destination_ip": "1.1.1.1",
                "source_port": 55000,
                "destination_port": 443,
                "protocol": "UDP",   # should be TCP for HTTPS
                "bytes_sent": 800,
                "bytes_received": 200,
            },
        ]
    }

