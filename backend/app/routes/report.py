"""
Report generation route - PDF and JSON reports
"""
import os
import json
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import APKAnalysis

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/{analysis_id}/json")
async def get_json_report(analysis_id: int, db: Session = Depends(get_db)):
    """Get full analysis as structured JSON report."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    report = {
        "report_metadata": {
            "report_id": f"APK-{analysis_id:06d}",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "platform": "APK Malware Analysis Platform v1.0",
        },
        "application_info": {
            "filename": analysis.filename,
            "package_name": analysis.package_name,
            "app_name": analysis.app_name,
            "version_name": analysis.version_name,
            "version_code": analysis.version_code,
            "file_hash_sha256": analysis.file_hash,
            "file_size_bytes": analysis.file_size,
            "sdk_min": analysis.sdk_min,
            "sdk_target": analysis.sdk_target,
        },
        "risk_assessment": {
            "overall_risk_score": analysis.risk_score,
            "risk_level": analysis.risk_level,
            "permission_score": analysis.permission_score,
            "api_score": analysis.api_score,
            "url_score": analysis.url_score,
            "obfuscation_score": analysis.obfuscation_score,
            "behavior_score": analysis.behavior_score,
        },
        "permissions": {
            "all_permissions": analysis.permissions,
            "dangerous_permissions": analysis.dangerous_permissions,
            "total_count": len(analysis.permissions or []),
            "dangerous_count": len(analysis.dangerous_permissions or []),
        },
        "static_analysis": {
            "api_calls": analysis.api_calls,
            "urls_found": analysis.urls,
            "activities": analysis.activities,
            "services": analysis.services,
            "receivers": analysis.receivers,
        },
        "obfuscation_analysis": {
            "detected": analysis.obfuscation_detected,
            "indicators": analysis.obfuscation_indicators,
        },
        "fraud_intelligence": {
            "detected_fraud_types": analysis.fraud_types,
            "fraud_indicators": analysis.fraud_indicators,
        },
        "ai_analysis": {
            "explanation": analysis.ai_explanation,
            "recommendations": analysis.ai_recommendations,
        },
        "threat_similarity": {
            "similar_apks": analysis.similar_apks,
        },
        "verdict": {
            "decision": analysis.risk_level,
            "action_required": analysis.risk_level in ["SUSPICIOUS", "BLOCK"],
            "immediate_block": analysis.risk_level == "BLOCK",
        },
        "analysis_metadata": {
            "analyzed_at": (analysis.created_at.isoformat() + "Z") if analysis.created_at else None,
            "status": analysis.status,
        }
    }

    return JSONResponse(content=report)


@router.get("/{analysis_id}/summary")
async def get_analysis_summary(analysis_id: int, db: Session = Depends(get_db)):
    """Get a concise summary of the analysis."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "package_name": analysis.package_name,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "fraud_types": analysis.fraud_types,
        "dangerous_permissions_count": len(analysis.dangerous_permissions or []),
        "obfuscation_detected": analysis.obfuscation_detected,
        "verdict": analysis.risk_level,
        "analyzed_at": (analysis.created_at.isoformat() + "Z") if analysis.created_at else None,
    }
