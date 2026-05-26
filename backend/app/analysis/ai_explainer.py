"""
Generative AI Explanation Layer
Uses OpenAI or Gemini API to generate human-readable explanations of APK analysis results.
Falls back to template-based explanations if no API key is configured.
"""
import os
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini")  # "openai" or "gemini"
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


def _build_analysis_prompt(apk_data: Dict[str, Any], score_data: Dict[str, Any], fraud_data: Dict[str, Any]) -> str:
    """Build the prompt for AI analysis."""
    permissions = apk_data.get("permissions", [])[:10]
    dangerous = apk_data.get("dangerous_permissions", [])[:10]
    api_calls = apk_data.get("api_calls", [])[:8]
    urls = apk_data.get("urls", [])[:5]
    fraud_types = fraud_data.get("fraud_types", [])
    risk_score = score_data.get("risk_score", 0)
    risk_level = score_data.get("risk_level", "UNKNOWN")
    obfuscation = apk_data.get("obfuscation_indicators", [])[:3]

    prompt = f"""You are a cybersecurity expert analyzing an Android APK for malware and fraud.

APK Analysis Results:
- App: {apk_data.get('app_name', 'Unknown')} ({apk_data.get('package_name', 'Unknown')})
- Risk Score: {risk_score}/100
- Risk Level: {risk_level}
- Dangerous Permissions: {', '.join(dangerous) if dangerous else 'None'}
- Key API Calls: {', '.join(api_calls) if api_calls else 'None'}
- Suspicious URLs: {', '.join(urls) if urls else 'None'}
- Detected Fraud Types: {', '.join(fraud_types) if fraud_types else 'None'}
- Obfuscation: {', '.join(obfuscation) if obfuscation else 'None detected'}

Provide a concise security analysis with:
1. A 2-3 sentence threat summary explaining what this APK likely does
2. Why it's dangerous (be specific about the fraud mechanisms)
3. 3-5 specific actionable recommendations for the security team

Format:
THREAT SUMMARY: [summary]
ANALYSIS: [detailed explanation]
RECOMMENDATIONS:
- [recommendation 1]
- [recommendation 2]
- [recommendation 3]"""

    return prompt


async def _call_openai(prompt: str) -> Optional[str]:
    """Call OpenAI API for explanation."""
    try:
        import openai
        client = openai.AsyncOpenAI(api_key=OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=600,
            temperature=0.3,
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API error: {e}")
        return None


async def _call_gemini(prompt: str) -> Optional[str]:
    """Call Google Gemini API using the new google-genai SDK with model fallback."""
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)

        # Try models in order until one works
        models_to_try = ["gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-flash-8b"]
        last_error = None

        for model_name in models_to_try:
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                logger.info(f"Gemini response via {model_name}")
                return response.text
            except Exception as model_err:
                err_str = str(model_err)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str or "RATE_LIMIT" in err_str:
                    logger.warning(f"Gemini {model_name} quota exceeded, trying next model...")
                    last_error = model_err
                    continue
                else:
                    raise model_err

        logger.error(f"All Gemini models quota-exceeded: {last_error}")
        return None

    except ImportError:
        logger.warning("google-genai not installed, falling back to template")
        return None
    except Exception as e:
        logger.error(f"Gemini API error: {e}")
        return None


def _generate_template_explanation(
    apk_data: Dict[str, Any],
    score_data: Dict[str, Any],
    fraud_data: Dict[str, Any],
) -> str:
    """Template-based explanation when no AI API is available."""
    risk_score = score_data.get("risk_score", 0)
    risk_level = score_data.get("risk_level", "UNKNOWN")
    fraud_types = fraud_data.get("fraud_types", [])
    dangerous = apk_data.get("dangerous_permissions", [])
    app_name = apk_data.get("app_name", "This application")
    package = apk_data.get("package_name", "Unknown")
    obf_detected = apk_data.get("obfuscation_detected", False)

    # Build threat summary
    if risk_level == "BLOCK":
        threat_level_text = "extremely high-risk malware"
        action = "immediately blocked and quarantined"
    elif risk_level == "SUSPICIOUS":
        threat_level_text = "suspicious application with potential malicious capabilities"
        action = "flagged for manual review and user notification"
    else:
        threat_level_text = "low-risk application"
        action = "monitored but allowed with standard permissions review"

    fraud_text = ""
    if fraud_types:
        fraud_text = f" The primary threats identified include: {', '.join(fraud_types[:3])}."
    else:
        fraud_text = " No specific fraud patterns were definitively detected, but suspicious behaviors warrant caution."

    obf_text = ""
    if obf_detected:
        obf_text = " Code obfuscation was detected, suggesting deliberate attempt to evade security analysis."

    # Permission analysis
    perm_text = ""
    if "android.permission.READ_SMS" in dangerous or "android.permission.RECEIVE_SMS" in dangerous:
        perm_text += " The app requests SMS access, which is the primary mechanism for OTP theft in mobile banking fraud."
    if "android.permission.BIND_DEVICE_ADMIN" in dangerous:
        perm_text += " Device Administrator privileges requested could allow the app to lock the device (ransomware behavior)."
    if "android.permission.SYSTEM_ALERT_WINDOW" in dangerous:
        perm_text += " Screen overlay permission enables phishing overlays over legitimate banking apps."

    summary = f"""THREAT SUMMARY: {app_name} ({package}) has been classified as {threat_level_text} with a risk score of {risk_score}/100. This application should be {action}.

ANALYSIS: Our analysis detected {len(dangerous)} dangerous permission requests out of the total permissions declared.{fraud_text}{obf_text}{perm_text} The risk score of {risk_score}/100 was calculated based on permission risk ({score_data.get('permission_score', 0):.1f}), API call patterns ({score_data.get('api_score', 0):.1f}), suspicious URLs ({score_data.get('url_score', 0):.1f}), obfuscation ({score_data.get('obfuscation_score', 0):.1f}), and behavioral indicators ({score_data.get('behavior_score', 0):.1f}).

RECOMMENDATIONS:
- {'Immediately block this application from being installed on any corporate device.' if risk_level == 'BLOCK' else 'Review this application carefully before allowing on corporate devices.'}
- Notify affected users to check for unauthorized SMS access or account transactions.
- Submit the APK hash to VirusTotal and threat intelligence platforms for cross-validation.
- {'Deploy EDR alerts for the package name ' + package + ' across your MDM infrastructure.' if risk_level != 'SAFE' else 'Continue monitoring this application for behavioral changes in future versions.'}
- {'Investigate network traffic to the identified suspicious URLs for signs of active C2 communication.' if apk_data.get('urls') else 'Perform dynamic analysis in a sandboxed environment to capture runtime behavior.'}"""

    return summary


def _parse_ai_response(response: str) -> Dict[str, Any]:
    """Parse AI response into structured format."""
    recommendations = []
    explanation = response
    threat_summary = ""

    lines = response.split("\n")
    in_recommendations = False

    for line in lines:
        line = line.strip()
        if line.startswith("THREAT SUMMARY:"):
            threat_summary = line.replace("THREAT SUMMARY:", "").strip()
        elif line.startswith("RECOMMENDATIONS:"):
            in_recommendations = True
        elif in_recommendations and (line.startswith("- ") or line.startswith("• ")):
            rec = line.lstrip("- •").strip()
            if rec:
                recommendations.append(rec)

    if not threat_summary:
        # Extract first meaningful line
        for line in lines:
            if len(line) > 30:
                threat_summary = line[:200]
                break

    if not recommendations:
        recommendations = [
            "Review all declared permissions for necessity",
            "Perform dynamic analysis in isolated environment",
            "Cross-check with threat intelligence databases",
            "Monitor network traffic from this application",
        ]

    return {
        "explanation": explanation,
        "threat_summary": threat_summary,
        "recommendations": recommendations[:6],
    }


async def generate_explanation(
    apk_data: Dict[str, Any],
    score_data: Dict[str, Any],
    fraud_data: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Main explanation generation function.
    Tries AI APIs first, falls back to template.
    """
    prompt = _build_analysis_prompt(apk_data, score_data, fraud_data)
    ai_response = None

    # Try AI providers
    if AI_PROVIDER == "gemini" and GEMINI_API_KEY:
        ai_response = await _call_gemini(prompt)
    elif AI_PROVIDER == "openai" and OPENAI_API_KEY:
        ai_response = await _call_openai(prompt)

    # Fallback to template
    if not ai_response:
        logger.info("Using template-based explanation (no AI API configured)")
        ai_response = _generate_template_explanation(apk_data, score_data, fraud_data)

    return _parse_ai_response(ai_response)
