"""
Threat Similarity Engine
Uses cosine similarity on feature vectors to find similar APKs.
"""
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize

logger = logging.getLogger(__name__)

# All known permissions for vectorization
ALL_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.WRITE_SETTINGS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
    "android.permission.MANAGE_ACCOUNTS",
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.DISABLE_KEYGUARD",
]

# Key API patterns for vectorization
API_FEATURES = [
    "SmsManager",
    "AccessibilityService",
    "DevicePolicyManager",
    "DexClassLoader",
    "Runtime.exec",
    "Cipher",
    "getDeviceId",
    "getSubscriberId",
    "reflect",
    "loadClass",
]

# Numeric features
NUMERIC_FEATURES = [
    "risk_score",
    "permission_count",
    "dangerous_permission_count",
    "url_count",
    "service_count",
    "obfuscation_detected",
]


def build_feature_vector(apk_data: Dict[str, Any]) -> List[float]:
    """
    Convert APK analysis data into a numeric feature vector for similarity computation.
    """
    vector = []

    # Permission binary features
    permissions = apk_data.get("permissions", [])
    for perm in ALL_PERMISSIONS:
        vector.append(1.0 if perm in permissions else 0.0)

    # API binary features
    api_calls = apk_data.get("api_calls", [])
    api_text = " ".join(api_calls)
    for api_feat in API_FEATURES:
        vector.append(1.0 if api_feat.lower() in api_text.lower() else 0.0)

    # Numeric features (normalized)
    risk_score = apk_data.get("risk_score", 0.0)
    vector.append(risk_score / 100.0)  # Normalize to 0-1

    perm_count = len(permissions)
    vector.append(min(perm_count / 30.0, 1.0))  # Normalize

    dangerous_count = len(apk_data.get("dangerous_permissions", []))
    vector.append(min(dangerous_count / 10.0, 1.0))

    url_count = len(apk_data.get("urls", []))
    vector.append(min(url_count / 20.0, 1.0))

    service_count = len(apk_data.get("services", []))
    vector.append(min(service_count / 10.0, 1.0))

    obf = 1.0 if apk_data.get("obfuscation_detected", False) else 0.0
    vector.append(obf)

    return vector


def find_similar_apks(
    target_vector: List[float],
    stored_analyses: List[Dict[str, Any]],
    top_k: int = 5,
    min_similarity: float = 0.3,
) -> List[Dict[str, Any]]:
    """
    Find the most similar APKs from stored analyses using cosine similarity.
    """
    if not stored_analyses:
        return []

    similar = []
    target_arr = np.array(target_vector).reshape(1, -1)

    for analysis in stored_analyses:
        stored_vector = analysis.get("feature_vector")
        if not stored_vector or len(stored_vector) != len(target_vector):
            continue

        stored_arr = np.array(stored_vector).reshape(1, -1)

        # Avoid division by zero
        if np.linalg.norm(target_arr) == 0 or np.linalg.norm(stored_arr) == 0:
            continue

        similarity = cosine_similarity(target_arr, stored_arr)[0][0]
        similarity = float(round(similarity, 4))

        if similarity >= min_similarity:
            similar.append({
                "id": analysis.get("id"),
                "filename": analysis.get("filename"),
                "package_name": analysis.get("package_name"),
                "risk_level": analysis.get("risk_level"),
                "risk_score": analysis.get("risk_score"),
                "similarity_score": similarity,
                "fraud_types": analysis.get("fraud_types", []),
            })

    # Sort by similarity descending
    similar.sort(key=lambda x: x["similarity_score"], reverse=True)
    return similar[:top_k]
