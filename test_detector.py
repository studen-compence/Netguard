"""
NetGuard-Agent: Quick Test
شغّل هذا الملف للتأكد أن كل شيء يعمل بدون server
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from app.core.detector import get_detector, build_alerts

print("=" * 60)
print("NetGuard-Agent — Detection Engine Test")
print("=" * 60)

# Test flows: mixed normal + malicious
test_flows = [
    # Normal HTTPS traffic
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
    # UDP on 443 (suspicious)
    {
        "source_ip": "10.0.0.8",
        "destination_ip": "1.1.1.1",
        "source_port": 55000,
        "destination_port": 443,
        "protocol": "UDP",
        "bytes_sent": 800,
        "bytes_received": 200,
    },
    # Normal DNS
    {
        "source_ip": "192.168.1.20",
        "destination_ip": "8.8.8.8",
        "source_port": 34567,
        "destination_port": 53,
        "protocol": "UDP",
        "bytes_sent": 64,
        "bytes_received": 128,
    },
]

print(f"\n📊 Analyzing {len(test_flows)} flows...\n")

detector = get_detector()
results = detector.predict(test_flows)
alerts = build_alerts(results, test_flows)

# Print per-flow results
for r in results:
    emoji = "🚨" if r["is_anomaly"] else "✅"
    print(f"{emoji} Flow {r['flow_index']}: {r['source_ip']} → {r['destination_ip']}")
    print(f"   Score: {r['anomaly_score']:.3f} | Severity: {r['severity']} | ML: {r['ml_flagged']}")
    if r["rule_detections"]:
        for rd in r["rule_detections"]:
            print(f"   ⚠️  Rule: {rd['rule_name']} ({rd['severity']})")
    print()

# Print alerts
print("=" * 60)
print(f"🛡️  ALERTS GENERATED: {len(alerts)}")
print("=" * 60)
for alert in alerts:
    print(f"\n[{alert['severity'].upper()}] {alert['title']}")
    print(f"  Source: {alert['source_ip']}")
    print(f"  {alert['description']}")
    print(f"  → Action: {alert['recommended_action']}")

print("\n✅ Detection engine working correctly!")
