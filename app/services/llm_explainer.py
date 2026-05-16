"""
NetGuard-Agent: LLM Alert Explainer Service
يستخدم Claude أو OpenAI لشرح التهديدات بشكل ذكي
"""

import os
import logging
from typing import Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class LLMExplainer:
    """
    Abstracted LLM service for explaining security alerts.
    Supports both Anthropic (Claude) and OpenAI.
    """

    def __init__(self, provider: str = "anthropic", api_key: Optional[str] = None):
        """
        Initialize LLM explainer.
        
        Args:
            provider: "anthropic" or "openai"
            api_key: Override environment variable
        """
        self.provider = provider.lower()
        self.api_key = api_key or os.getenv(
            "ANTHROPIC_API_KEY" if self.provider == "anthropic" else "OPENAI_API_KEY"
        )

        if not self.api_key:
            logger.warning(f"⚠️  No {self.provider.upper()} API key found. LLM features disabled.")
            self.enabled = False
        else:
            self.enabled = True
            logger.info(f"✅ LLM Explainer initialized with {self.provider.upper()}")

    def _build_prompt(self, alert: Dict) -> str:
        """Build a detailed prompt for the LLM"""
        rule_details = ""
        if alert.get("rule_detections"):
            rule_details = "\n".join([
                f"- {r['rule_name']}: {r['description']}"
                for r in alert["rule_detections"]
            ])

        prompt = f"""You are a cybersecurity expert. Analyze this security alert and provide a professional explanation.

ALERT DETAILS:
- Title: {alert.get('title', 'Unknown')}
- Severity: {alert.get('severity', 'unknown')}
- Source IP: {alert.get('source_ip', 'N/A')}
- Destination IP: {alert.get('destination_ip', 'N/A')}
- Anomaly Score: {alert.get('anomaly_score', 0):.2f} (0-1, higher = more suspicious)
- Description: {alert.get('description', 'No description')}
- ML Flagged: {alert.get('ml_flagged', False)}

DETECTED RULES:
{rule_details if rule_details else "- No rule-based detections (ML anomaly only)"}

REQUIRED OUTPUT FORMAT (JSON):
{{
  "executive_summary": "1-2 sentence summary of the threat",
  "technical_explanation": "Explain what's happening and why it's suspicious",
  "risk_analysis": "Why this is dangerous for the organization",
  "recommended_actions": ["Action 1", "Action 2", "Action 3"],
  "urgency_level": "immediate | high | medium | low",
  "confidence_score": 0.85
}}

Be concise, technical, and actionable."""
        return prompt

    def explain(self, alert: Dict) -> Dict:
        """
        Explain a security alert using LLM.
        
        Args:
            alert: Alert dictionary from detector
            
        Returns:
            Dictionary with explanation, risk analysis, and recommendations
        """
        if not self.enabled:
            return self._fallback_explanation(alert)

        try:
            if self.provider == "anthropic":
                return self._explain_anthropic(alert)
            elif self.provider == "openai":
                return self._explain_openai(alert)
            else:
                return self._fallback_explanation(alert)
        except Exception as e:
            logger.error(f"❌ LLM error: {e}")
            return self._fallback_explanation(alert)

    def _explain_anthropic(self, alert: Dict) -> Dict:
        """Use Anthropic Claude API"""
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        prompt = self._build_prompt(alert)

        message = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1024,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response_text = message.content[0].text

        # Parse JSON from response
        import json
        try:
            # Find JSON in response
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = response_text[start:end]
                result = json.loads(json_str)
            else:
                result = self._parse_text_response(response_text)
        except json.JSONDecodeError:
            result = self._parse_text_response(response_text)

        return {
            "explanation": result.get("executive_summary", ""),
            "technical_reasoning": result.get("technical_explanation", ""),
            "risk_analysis": result.get("risk_analysis", ""),
            "recommended_actions": result.get("recommended_actions", []),
            "urgency_level": result.get("urgency_level", "medium"),
            "confidence": float(result.get("confidence_score", 0.75)),
            "provider": "anthropic",
        }

    def _explain_openai(self, alert: Dict) -> Dict:
        """Use OpenAI GPT API"""
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
        prompt = self._build_prompt(alert)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Always respond with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1024
        )

        response_text = response.choices[0].message.content

        import json
        try:
            start = response_text.find('{')
            end = response_text.rfind('}') + 1
            if start != -1 and end != 0:
                json_str = response_text[start:end]
                result = json.loads(json_str)
            else:
                result = self._parse_text_response(response_text)
        except json.JSONDecodeError:
            result = self._parse_text_response(response_text)

        return {
            "explanation": result.get("executive_summary", ""),
            "technical_reasoning": result.get("technical_explanation", ""),
            "risk_analysis": result.get("risk_analysis", ""),
            "recommended_actions": result.get("recommended_actions", []),
            "urgency_level": result.get("urgency_level", "medium"),
            "confidence": float(result.get("confidence_score", 0.75)),
            "provider": "openai",
        }

    def _parse_text_response(self, text: str) -> Dict:
        """Fallback: parse non-JSON response"""
        return {
            "executive_summary": text[:200],
            "technical_explanation": text,
            "risk_analysis": "Unable to parse structured response",
            "recommended_actions": ["Review alert logs", "Monitor source IP"],
            "urgency_level": "medium",
            "confidence_score": 0.5,
        }

    def _fallback_explanation(self, alert: Dict) -> Dict:
        """Fallback when LLM is unavailable"""
        severity_map = {
            "critical": ("Critical threat detected", "immediate"),
            "high": ("High-priority security issue", "high"),
            "medium": ("Security concern detected", "medium"),
            "low": ("Low-priority alert", "low"),
        }

        title, urgency = severity_map.get(alert.get("severity", "medium"), ("Alert detected", "medium"))

        return {
            "explanation": alert.get("description", "Unknown alert"),
            "technical_reasoning": f"Score: {alert.get('anomaly_score', 0):.2f}. ML flagged: {alert.get('ml_flagged', False)}",
            "risk_analysis": f"{title}. Source: {alert.get('source_ip')}",
            "recommended_actions": ["Review logs", "Investigate source", "Monitor activity"],
            "urgency_level": urgency,
            "confidence": 0.6,
            "provider": "fallback",
        }


# =============================================
# Singleton
# =============================================

_explainer: Optional[LLMExplainer] = None


def get_explainer(provider: str = "anthropic") -> LLMExplainer:
    """Get or create the LLM explainer singleton"""
    global _explainer
    if _explainer is None:
        _explainer = LLMExplainer(provider=provider)
    return _explainer
