"""
AI Explanation route - regenerate or get existing explanations
"""
import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import APKAnalysis
from app.analysis.ai_explainer import generate_explanation

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/{analysis_id}")
async def get_explanation(analysis_id: int, db: Session = Depends(get_db)):
    """Get AI explanation for an analysis."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "analysis_id": analysis.id,
        "explanation": analysis.ai_explanation,
        "recommendations": analysis.ai_recommendations,
        "threat_summary": (analysis.ai_explanation or "").split("\n")[0][:200],
    }


@router.post("/{analysis_id}/regenerate")
async def regenerate_explanation(analysis_id: int, db: Session = Depends(get_db)):
    """Regenerate AI explanation for an analysis."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    apk_data = {
        "permissions": analysis.permissions or [],
        "dangerous_permissions": analysis.dangerous_permissions or [],
        "api_calls": analysis.api_calls or [],
        "urls": analysis.urls or [],
        "services": analysis.services or [],
        "receivers": analysis.receivers or [],
        "obfuscation_detected": analysis.obfuscation_detected,
        "obfuscation_indicators": analysis.obfuscation_indicators or [],
        "app_name": analysis.app_name,
        "package_name": analysis.package_name,
    }

    score_data = {
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "permission_score": analysis.permission_score,
        "api_score": analysis.api_score,
        "url_score": analysis.url_score,
        "obfuscation_score": analysis.obfuscation_score,
        "behavior_score": analysis.behavior_score,
    }

    fraud_data = {
        "fraud_types": analysis.fraud_types or [],
        "fraud_indicators": analysis.fraud_indicators or [],
    }

    result = await generate_explanation(apk_data, score_data, fraud_data)
    analysis.ai_explanation = result["explanation"]
    analysis.ai_recommendations = result["recommendations"]
    db.commit()

    return {
        "analysis_id": analysis.id,
        "explanation": result["explanation"],
        "recommendations": result["recommendations"],
        "threat_summary": result.get("threat_summary", ""),
    }
