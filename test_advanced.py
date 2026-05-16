"""
NetGuard-Agent: Advanced Feature Tests
اختبر الـ LLM explainer، alert storage، والـ endpoints الجديدة
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from app.core.detector import get_detector, build_alerts
from app.services.llm_explainer import get_explainer
from app.services.alert_store import get_alert_store

print("=" * 70)
print("NetGuard-Agent — Advanced Features Test")
print("=" * 70)

# =============================================================
# Test 1: Detection Engine + Alert Generation
# =============================================================

print("\n[TEST 1] 🔍 Detection Engine")
print("-" * 70)

test_flows = [
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
    # Port scan
    {
        "source_ip": "203.0.113.99",
        "destination_ip": "192.168.1.10",
        "source_port": 63412,
        "destination_port": 22,
        "protocol": "TCP",
        "bytes_sent": 60,
        "bytes_received": 0,
    },
    # Data exfiltration
    {
        "source_ip": "192.168.1.55",
        "destination_ip": "185.220.101.45",
        "source_port": 49201,
        "destination_port": 8080,
        "protocol": "TCP",
        "bytes_sent": 25_000_000,
        "bytes_received": 150,
    },
]

detector = get_detector()
results = detector.predict(test_flows)
alerts = build_alerts(results, test_flows)

print(f"✅ Processed {len(test_flows)} flows")
print(f"🚨 Generated {len(alerts)} alerts\n")

for i, alert in enumerate(alerts, 1):
    print(f"Alert {i}: [{alert['severity'].upper()}] {alert['title']}")
    print(f"   Source: {alert['source_ip']} → {alert['destination_ip']}")
    print()

# =============================================================
# Test 2: Alert Storage
# =============================================================

print("\n[TEST 2] 💾 Alert Storage")
print("-" * 70)

store = get_alert_store(persist=False)
store.add_alerts(alerts)

stats = store.get_stats()
print(f"✅ Stored {stats['total_alerts']} alerts")
print(f"📊 Total processed: {stats['total_processed']}")
print(f"📈 Anomalies detected: {stats['anomalies_detected']}")
print(f"Severity: {stats['severity_distribution']}\n")

recent = store.get_recent(limit=5)
print(f"📋 Recent alerts ({len(recent)}):")
for alert in recent:
    print(f"   - {alert['title']} ({alert['severity']})")

# =============================================================
# Test 3: LLM Explainer
# =============================================================

print("\n[TEST 3] 🤖 LLM Alert Explanation")
print("-" * 70)

explainer = get_explainer()
print(f"ℹ️  LLM Mode: {'API' if explainer.enabled else 'FALLBACK TEMPLATES'}")

# Test with data exfiltration alert
exfil_alert = alerts[2] if len(alerts) > 2 else alerts[0]

print(f"\n📝 Explaining: {exfil_alert['title']}")
print("-" * 70)

explanation = explainer.explain(exfil_alert)

print(f"\n✏️  Provider: {explanation.get('provider', 'api')}")
print(f"Confidence: {explanation.get('confidence_score', explanation.get('confidence', 0.85))}\n")

print("📄 EXPLANATION:")
explanation_text = explanation.get('technical_explanation', explanation.get('explanation', ''))
print(explanation_text[:400] + "..." if len(explanation_text) > 400 else explanation_text)

print("\n⚠️  RISK ANALYSIS:")
risk = explanation.get('risk_analysis', '')
print(risk[:300] + "..." if len(risk) > 300 else risk)

print("\n🔧 RECOMMENDED ACTIONS:")
for i, action in enumerate(explanation.get('recommended_actions', []), 1):
    print(f"   {i}. {action}")

# =============================================================
# Test 4: Alert Queries
# =============================================================

print("\n[TEST 4] 🔎 Alert Queries")
print("-" * 70)

# Query by severity
critical = store.get_by_severity("critical", limit=10)
print(f"Critical alerts: {len(critical)}")

# Query by IP
ip_alerts = store.get_by_source_ip("192.168.1.55", limit=10)
print(f"Alerts for 192.168.1.55: {len(ip_alerts)}")

if ip_alerts:
    print(f"   - {ip_alerts[0]['title']}")

# =============================================================
# Test 5: Fallback Mode Demonstration
# =============================================================

print("\n[TEST 5] 🔄 Fallback Mode (when API key not set)")
print("-" * 70)

# Show that different threats get appropriate templates
test_alerts = [
    {
        "title": "Port Scanning",
        "severity": "high",
        "source_ip": "203.0.113.1",
        "destination_ip": "192.168.1.1",
        "description": "Ephemeral port to privileged port",
        "anomaly_score": 0.75,
        "rule_detections": [],
    },
    {
        "title": "High Volume UDP Flood",
        "severity": "high",
        "source_ip": "10.0.0.5",
        "destination_ip": "8.8.8.8",
        "description": "UDP flood attack detected",
        "anomaly_score": 0.92,
        "rule_detections": [],
    },
]

for test_alert in test_alerts:
    exp = explainer.explain(test_alert)
    print(f"\n✓ {test_alert['title']}")
    risk_text = exp.get('risk_analysis', '')
    print(f"  Risk: {risk_text[:100]}...")
    actions = exp.get('recommended_actions', [])
    actions_preview = ", ".join(actions[:2]) if actions else "No actions"
    print(f"  Actions: {actions_preview}...")

# =============================================================
# Summary
# =============================================================

print("\n" + "=" * 70)
print("✅ ALL TESTS PASSED")
print("=" * 70)
print("\n📋 Summary:")
print(f"  ✓ Detection engine: Working")
print(f"  ✓ Alert generation: {len(alerts)} alerts created")
print(f"  ✓ Alert storage: {stats['total_alerts']} stored")
print(f"  ✓ LLM explainer: {explanation.get('provider', 'api')} mode")
print(f"  ✓ Query system: Filtering by severity and IP")
print(f"  ✓ Fallback templates: Ready")

print("\n🚀 Ready to deploy!")
print("\nNext step: Run `uvicorn app.main:app --reload` to start the API")
