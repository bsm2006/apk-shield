"""
Risk Scoring Engine
Weighted multi-factor scoring system for APK malware risk assessment.
Score: 0-100 where 100 = maximum risk
"""
import re
import logging
from typing import Dict, List, Any, Tuple

logger = logging.getLogger(__name__)

# Scoring weights (must sum to 1.0)
SCORING_WEIGHTS = {
    "permissions": 0.30,
    "api_calls": 0.25,
    "urls": 0.20,
    "obfuscation": 0.15,
    "behavior": 0.10,
}

# Permission risk scores (0-100)
PERMISSION_RISK_SCORES = {
    # Critical risk (80-100)
    "android.permission.READ_SMS": 95,
    "android.permission.RECEIVE_SMS": 90,
    "android.permission.SEND_SMS": 90,
    "android.permission.BIND_DEVICE_ADMIN": 95,
    "android.permission.REQUEST_INSTALL_PACKAGES": 85,
    "android.permission.SYSTEM_ALERT_WINDOW": 80,
    "android.permission.READ_CALL_LOG": 85,
    "android.permission.PROCESS_OUTGOING_CALLS": 80,
    "android.permission.DISABLE_KEYGUARD": 85,
    "android.permission.REQUEST_DELETE_PACKAGES": 80,

    # High risk (60-79)
    "android.permission.ACCESS_FINE_LOCATION": 65,
    "android.permission.RECORD_AUDIO": 70,
    "android.permission.READ_CONTACTS": 65,
    "android.permission.WRITE_CONTACTS": 65,
    "android.permission.READ_PHONE_STATE": 70,
    "android.permission.CALL_PHONE": 75,
    "android.permission.GET_ACCOUNTS": 65,
    "android.permission.USE_CREDENTIALS": 70,
    "android.permission.MANAGE_ACCOUNTS": 70,
    "android.permission.AUTHENTICATE_ACCOUNTS": 70,
    "android.permission.RECEIVE_BOOT_COMPLETED": 60,
    "android.permission.FOREGROUND_SERVICE": 60,

    # Medium risk (30-59)
    "android.permission.CAMERA": 45,
    "android.permission.READ_EXTERNAL_STORAGE": 35,
    "android.permission.WRITE_EXTERNAL_STORAGE": 40,
    "android.permission.ACCESS_COARSE_LOCATION": 40,
    "android.permission.WAKE_LOCK": 30,
    "android.permission.CHANGE_NETWORK_STATE": 35,
    "android.permission.CHANGE_WIFI_STATE": 35,

    # Low risk (0-29)
    "android.permission.INTERNET": 15,
    "android.permission.ACCESS_NETWORK_STATE": 10,
    "android.permission.VIBRATE": 5,
    "android.permission.FLASHLIGHT": 5,
    "android.permission.USE_BIOMETRIC": 10,
    "android.permission.USE_FINGERPRINT": 15,
}

# API call risk scores
API_RISK_SCORES = {
    "Landroid/telephony/SmsManager": 95,
    "sendTextMessage": 90,
    "sendMultipartTextMessage": 90,
    "Landroid/provider/Telephony$Sms": 85,
    "AccessibilityService": 80,
    "performGlobalAction": 85,
    "DevicePolicyManager": 90,
    "lockNow": 85,
    "resetPassword": 90,
    "DexClassLoader": 85,
    "PathClassLoader": 75,
    "java/lang/Runtime": 80,
    "java/lang/reflect": 70,
    "getDeviceId": 75,
    "getSubscriberId": 75,
    "getImei": 80,
    "getSimSerialNumber": 75,
    "DESKeySpec": 60,
    "Ljavax/crypto/Cipher": 55,
    "HttpURLConnection": 20,
    "OkHttpClient": 15,
}

# URL risk patterns
SUSPICIOUS_URL_PATTERNS = [
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", 90, "Raw IP address URL"),
    (r"\.ru[/\s\"']", 70, "Russian TLD domain"),
    (r"\.cn[/\s\"']", 65, "Chinese TLD domain"),
    (r"\.tk[/\s\"']", 80, "Free domain (.tk)"),
    (r"\.pw[/\s\"']", 75, "Suspicious TLD (.pw)"),
    (r"\.xyz[/\s\"']", 60, "Suspicious TLD (.xyz)"),
    (r"ngrok\.io", 85, "Ngrok tunnel (C2 potential)"),
    (r"pastebin\.com", 75, "Pastebin (payload download)"),
    (r"bit\.ly|tinyurl", 60, "URL shortener (obfuscation)"),
    (r"/gate\.php", 95, "C2 gate endpoint"),
    (r"/panel/", 85, "Admin panel endpoint"),
    (r"/c2/", 90, "Command and Control endpoint"),
    (r"/bot/", 80, "Bot endpoint"),
    (r"/update\.php", 70, "Remote update endpoint"),
    (r"http://", 40, "Unencrypted HTTP"),
]


def score_permissions(permissions: List[str], dangerous_permissions: List[str]) -> Tuple[float, List[Dict]]:
    """Score based on permissions."""
    if not permissions:
        return 0.0, []

    details = []
    total_score = 0.0
    count = 0

    for perm in permissions:
        risk = PERMISSION_RISK_SCORES.get(perm, 10)  # Default 10 for unknown
        if risk > 10:
            details.append({
                "permission": perm,
                "risk": risk,
                "dangerous": perm in dangerous_permissions,
            })
        total_score += risk
        count += 1

    # Normalize: max possible is 100 per permission, but we cap total
    # Weight by number of dangerous permissions
    dangerous_ratio = len(dangerous_permissions) / max(len(permissions), 1)
    avg_score = total_score / max(count, 1)

    # Amplify based on count of dangerous permissions
    danger_bonus = min(dangerous_ratio * 40, 40)
    final_score = min(avg_score * 0.7 + danger_bonus, 100)

    return round(final_score, 2), sorted(details, key=lambda x: x["risk"], reverse=True)


def score_api_calls(api_calls: List[str]) -> Tuple[float, List[Dict]]:
    """Score based on API calls."""
    if not api_calls:
        return 0.0, []

    details = []
    max_score = 0.0

    for call in api_calls:
        for pattern, risk_score, description in [(k, v, k) for k, v in API_RISK_SCORES.items()]:
            if pattern in call:
                details.append({
                    "api": call[:100],
                    "risk": risk_score,
                    "pattern": pattern,
                })
                max_score = max(max_score, risk_score)
                break

    # Score based on worst API found + count
    count_bonus = min(len(details) * 5, 20)
    final_score = min(max_score * 0.85 + count_bonus, 100)

    return round(final_score, 2), sorted(details, key=lambda x: x["risk"], reverse=True)


def score_urls(urls: List[str]) -> Tuple[float, List[Dict]]:
    """Score based on URLs found in APK."""
    if not urls:
        return 0.0, []

    details = []
    max_score = 0.0

    for url in urls:
        for pattern, risk_score, description in SUSPICIOUS_URL_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                details.append({
                    "url": url[:200],
                    "risk": risk_score,
                    "reason": description,
                })
                max_score = max(max_score, risk_score)

    if not details:
        return 5.0, []  # Minor score for having any URLs

    count_bonus = min(len(details) * 3, 15)
    final_score = min(max_score * 0.9 + count_bonus, 100)

    return round(final_score, 2), sorted(details, key=lambda x: x["risk"], reverse=True)


def score_obfuscation(obfuscation_detected: bool, indicators: List[str]) -> float:
    """Score based on obfuscation indicators."""
    if not obfuscation_detected or not indicators:
        return 0.0

    base_score = 30.0
    per_indicator = 15.0
    score = base_score + min(len(indicators) * per_indicator, 70)
    return min(round(score, 2), 100)


def score_behavior(
    services: List[str],
    receivers: List[str],
    api_calls: List[str],
    permissions: List[str],
) -> float:
    """Score based on behavioral patterns."""
    score = 0.0

    # Background persistence
    has_boot = any("RECEIVE_BOOT_COMPLETED" in p for p in permissions)
    has_background_service = any(
        any(kw in s.lower() for kw in ["background", "exfil", "keylog", "monitor", "spy"])
        for s in services
    )

    if has_boot and has_background_service:
        score += 35  # Persistence mechanism

    # Accessibility abuse
    has_accessibility = any("AccessibilityService" in a for a in api_calls)
    if has_accessibility:
        score += 30

    # Device admin
    has_admin = any("DevicePolicyManager" in a or "BIND_DEVICE_ADMIN" in p
                    for a in api_calls for p in permissions)
    if has_admin:
        score += 35

    # SMS intercept combo
    has_sms_read = any("READ_SMS" in p or "RECEIVE_SMS" in p for p in permissions)
    has_sms_send = any("SEND_SMS" in p for p in permissions)
    if has_sms_read and has_sms_send:
        score += 25  # OTP theft pattern

    return min(round(score, 2), 100)


def determine_risk_level(score: float) -> str:
    """Convert numeric score to risk level."""
    if score < 25:
        return "SAFE"
    elif score < 55:
        return "SUSPICIOUS"
    else:
        return "BLOCK"


def compute_risk_score(apk_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main scoring function. Returns comprehensive score breakdown.
    """
    permissions = apk_data.get("permissions", [])
    dangerous_permissions = apk_data.get("dangerous_permissions", [])
    api_calls = apk_data.get("api_calls", [])
    urls = apk_data.get("urls", [])
    obfuscation_detected = apk_data.get("obfuscation_detected", False)
    obfuscation_indicators = apk_data.get("obfuscation_indicators", [])
    services = apk_data.get("services", [])
    receivers = apk_data.get("receivers", [])

    # Component scores
    perm_score, perm_details = score_permissions(permissions, dangerous_permissions)
    api_score, api_details = score_api_calls(api_calls)
    url_score, url_details = score_urls(urls)
    obf_score = score_obfuscation(obfuscation_detected, obfuscation_indicators)
    beh_score = score_behavior(services, receivers, api_calls, permissions)

    # Weighted composite
    overall = (
        perm_score * SCORING_WEIGHTS["permissions"]
        + api_score * SCORING_WEIGHTS["api_calls"]
        + url_score * SCORING_WEIGHTS["urls"]
        + obf_score * SCORING_WEIGHTS["obfuscation"]
        + beh_score * SCORING_WEIGHTS["behavior"]
    )
    overall = min(round(overall, 2), 100)

    risk_level = determine_risk_level(overall)

    return {
        "risk_score": overall,
        "risk_level": risk_level,
        "permission_score": perm_score,
        "api_score": api_score,
        "url_score": url_score,
        "obfuscation_score": obf_score,
        "behavior_score": beh_score,
        "weights": SCORING_WEIGHTS,
        "details": {
            "permissions": perm_details[:10],
            "api_calls": api_details[:10],
            "urls": url_details[:10],
        },
    }
