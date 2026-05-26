"""
Fraud Mapping Engine
Maps technical APK behaviors to specific banking/fraud threat categories.
"""
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


# Fraud type definitions with detection rules
FRAUD_RULES = [
    {
        "id": "OTP_THEFT",
        "name": "OTP / SMS Theft",
        "description": "App intercepts SMS messages to steal One-Time Passwords (OTPs) used in banking authentication.",
        "severity": "CRITICAL",
        "icon": "📱",
        "permission_triggers": [
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
        ],
        "api_triggers": [
            "Landroid/provider/Telephony$Sms",
            "SmsMessage",
            "sendTextMessage",
        ],
        "behavior_triggers": ["sms_receiver"],
        "required_triggers": 1,
    },
    {
        "id": "PHISHING",
        "name": "Phishing / Overlay Attack",
        "description": "App creates fake UI overlays on top of legitimate banking apps to steal credentials.",
        "severity": "CRITICAL",
        "icon": "🎣",
        "permission_triggers": [
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "api_triggers": [
            "AccessibilityService",
            "performGlobalAction",
        ],
        "url_patterns": [
            r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"/gate\.php",
            r"/panel/",
        ],
        "behavior_triggers": ["overlay"],
        "required_triggers": 1,
    },
    {
        "id": "SPYWARE",
        "name": "Spyware / Data Exfiltration",
        "description": "App silently collects and transmits sensitive data including contacts, location, call logs.",
        "severity": "HIGH",
        "icon": "🕵️",
        "permission_triggers": [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
        ],
        "api_triggers": [
            "getDeviceId",
            "getSubscriberId",
            "getSimSerialNumber",
        ],
        "service_triggers": ["background", "exfil", "monitor"],
        "required_triggers": 2,
    },
    {
        "id": "BANKING_TROJAN",
        "name": "Banking Trojan",
        "description": "Sophisticated malware that hijacks banking app sessions to perform unauthorized transactions.",
        "severity": "CRITICAL",
        "icon": "🏦",
        "permission_triggers": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "api_triggers": [
            "DevicePolicyManager",
            "AccessibilityService",
            "DexClassLoader",
        ],
        "required_triggers": 2,
    },
    {
        "id": "RANSOMWARE",
        "name": "Ransomware",
        "description": "App encrypts device data or locks the device and demands payment for restoration.",
        "severity": "CRITICAL",
        "icon": "🔐",
        "permission_triggers": [
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.WRITE_EXTERNAL_STORAGE",
        ],
        "api_triggers": [
            "lockNow",
            "resetPassword",
            "Ljavax/crypto/Cipher",
            "DESKeySpec",
        ],
        "required_triggers": 2,
    },
    {
        "id": "CREDENTIAL_STEALER",
        "name": "Credential Stealer",
        "description": "App captures login credentials through keylogging or fake login screens.",
        "severity": "HIGH",
        "icon": "🔑",
        "permission_triggers": [
            "android.permission.GET_ACCOUNTS",
            "android.permission.USE_CREDENTIALS",
            "android.permission.MANAGE_ACCOUNTS",
        ],
        "api_triggers": [
            "java/lang/reflect",
            "keylog",
        ],
        "service_triggers": ["keylog"],
        "required_triggers": 1,
    },
    {
        "id": "STALKERWARE",
        "name": "Stalkerware / Remote Access",
        "description": "App enables covert surveillance including location tracking, call recording, and remote control.",
        "severity": "HIGH",
        "icon": "👁️",
        "permission_triggers": [
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
        "api_triggers": ["java/lang/Runtime"],
        "service_triggers": ["spy", "remote", "rat"],
        "required_triggers": 2,
    },
    {
        "id": "BOOTKIT",
        "name": "Persistence / Bootkit",
        "description": "App installs itself as a persistent service that survives device reboots.",
        "severity": "MEDIUM",
        "icon": "⚡",
        "permission_triggers": [
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        "api_triggers": [],
        "service_triggers": ["background", "boot"],
        "required_triggers": 1,
    },
    {
        "id": "DROPPER",
        "name": "Dropper / Downloader",
        "description": "App downloads and installs additional malicious packages after installation.",
        "severity": "HIGH",
        "icon": "📦",
        "permission_triggers": [
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        "api_triggers": [
            "Dalvik.system.DexClassLoader",
            "DexClassLoader",
            "PathClassLoader",
            "loadClass",
        ],
        "required_triggers": 1,
    },
    {
        "id": "ADWARE",
        "name": "Aggressive Adware",
        "description": "App displays intrusive ads, tracks user behavior, and may redirect to malicious sites.",
        "severity": "LOW",
        "icon": "📢",
        "permission_triggers": [
            "android.permission.INTERNET",
        ],
        "url_patterns": [r"http://", r"ads\.", r"track\."],
        "required_triggers": 2,
    },
]


def check_permission_triggers(permissions: List[str], triggers: List[str]) -> List[str]:
    """Check which permission triggers are matched."""
    matched = []
    for trigger in triggers:
        if any(trigger in p for p in permissions):
            matched.append(trigger)
    return matched


def check_api_triggers(api_calls: List[str], triggers: List[str]) -> List[str]:
    """Check which API triggers are matched."""
    matched = []
    for trigger in triggers:
        if any(trigger in a for a in api_calls):
            matched.append(trigger)
    return matched


def check_service_triggers(services: List[str], triggers: List[str]) -> List[str]:
    """Check which service name pattern triggers are matched."""
    matched = []
    for trigger in triggers:
        if any(trigger.lower() in s.lower() for s in services):
            matched.append(trigger)
    return matched


def check_url_triggers(urls: List[str], patterns: List[str]) -> List[str]:
    """Check which URL pattern triggers are matched."""
    import re
    matched = []
    for pattern in patterns:
        for url in urls:
            if re.search(pattern, url, re.IGNORECASE):
                matched.append(pattern)
                break
    return matched


def map_fraud_types(apk_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main fraud mapping function.
    Returns detected fraud types with evidence.
    """
    permissions = apk_data.get("permissions", [])
    dangerous_permissions = apk_data.get("dangerous_permissions", [])
    api_calls = apk_data.get("api_calls", [])
    urls = apk_data.get("urls", [])
    services = apk_data.get("services", [])
    receivers = apk_data.get("receivers", [])

    detected_frauds = []
    all_fraud_types = []

    for rule in FRAUD_RULES:
        trigger_count = 0
        evidence = []

        # Check permissions
        perm_matches = check_permission_triggers(permissions, rule.get("permission_triggers", []))
        if perm_matches:
            trigger_count += len(perm_matches)
            evidence.extend([f"Permission: {p}" for p in perm_matches])

        # Check API calls
        api_matches = check_api_triggers(api_calls, rule.get("api_triggers", []))
        if api_matches:
            trigger_count += len(api_matches)
            evidence.extend([f"API Call: {a}" for a in api_matches])

        # Check service triggers
        service_matches = check_service_triggers(services, rule.get("service_triggers", []))
        if service_matches:
            trigger_count += len(service_matches)
            evidence.extend([f"Service: {s}" for s in service_matches])

        # Check URL patterns
        url_matches = check_url_triggers(urls, rule.get("url_patterns", []))
        if url_matches:
            trigger_count += len(url_matches)
            evidence.extend([f"Suspicious URL pattern: {p}" for p in url_matches])

        # Determine if fraud type is detected
        if trigger_count >= rule["required_triggers"]:
            detected_frauds.append({
                "id": rule["id"],
                "name": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "icon": rule["icon"],
                "evidence": evidence[:8],  # Limit evidence list
                "trigger_count": trigger_count,
                "confidence": min(round((trigger_count / max(rule["required_triggers"], 1)) * 100 * 0.7, 0), 100),
            })
            all_fraud_types.append(rule["name"])

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    detected_frauds.sort(key=lambda x: severity_order.get(x["severity"], 4))

    # Generate fraud indicators summary
    fraud_indicators = []
    for fraud in detected_frauds:
        fraud_indicators.append({
            "type": fraud["id"],
            "description": fraud["description"],
            "severity": fraud["severity"],
            "evidence": fraud["evidence"],
        })

    return {
        "fraud_types": all_fraud_types,
        "fraud_indicators": fraud_indicators,
        "detected_frauds": detected_frauds,
        "highest_severity": detected_frauds[0]["severity"] if detected_frauds else "NONE",
        "fraud_count": len(detected_frauds),
    }
