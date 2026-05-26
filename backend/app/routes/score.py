"""
Score breakdown route
"""
import logging
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import APKAnalysis
from app.analysis.risk_scorer import SCORING_WEIGHTS, determine_risk_level

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/{analysis_id}")
async def get_score_breakdown(analysis_id: int, db: Session = Depends(get_db)):
    """Get detailed score breakdown for an analysis."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "analysis_id": analysis.id,
        "overall_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "score_breakdown": {
            "permission_score": {
                "score": analysis.permission_score,
                "weight": SCORING_WEIGHTS["permissions"],
                "weighted_contribution": round(analysis.permission_score * SCORING_WEIGHTS["permissions"], 2),
                "label": "Permission Risk",
                "description": f"{len(analysis.dangerous_permissions or [])} dangerous permissions found",
            },
            "api_score": {
                "score": analysis.api_score,
                "weight": SCORING_WEIGHTS["api_calls"],
                "weighted_contribution": round(analysis.api_score * SCORING_WEIGHTS["api_calls"], 2),
                "label": "API Call Risk",
                "description": f"{len(analysis.api_calls or [])} suspicious API calls detected",
            },
            "url_score": {
                "score": analysis.url_score,
                "weight": SCORING_WEIGHTS["urls"],
                "weighted_contribution": round(analysis.url_score * SCORING_WEIGHTS["urls"], 2),
                "label": "Network Risk",
                "description": f"{len(analysis.urls or [])} suspicious URLs found",
            },
            "obfuscation_score": {
                "score": analysis.obfuscation_score,
                "weight": SCORING_WEIGHTS["obfuscation"],
                "weighted_contribution": round(analysis.obfuscation_score * SCORING_WEIGHTS["obfuscation"], 2),
                "label": "Obfuscation Risk",
                "description": "Code obfuscation detected" if analysis.obfuscation_detected else "No obfuscation detected",
            },
            "behavior_score": {
                "score": analysis.behavior_score,
                "weight": SCORING_WEIGHTS["behavior"],
                "weighted_contribution": round(analysis.behavior_score * SCORING_WEIGHTS["behavior"], 2),
                "label": "Behavioral Risk",
                "description": "Suspicious behavior patterns detected",
            },
        },
        "verdict": {
            "decision": analysis.risk_level,
            "confidence": min(100, int(abs(analysis.risk_score - 50) * 2 + 30)),
            "action": {
                "SAFE": "Allow installation. Continue monitoring.",
                "SUSPICIOUS": "Flag for review. Notify security team.",
                "BLOCK": "Block immediately. Quarantine device if installed.",
            }.get(analysis.risk_level, "Review required"),
        },
    }


@router.get("/stats/overview")
async def get_score_stats(db: Session = Depends(get_db)):
    """Get statistical overview of all analyses."""
    analyses = db.query(APKAnalysis).filter(APKAnalysis.status == "completed").all()

    if not analyses:
        return {
            "total": 0,
            "safe": 0,
            "suspicious": 0,
            "blocked": 0,
            "avg_risk_score": 0,
            "top_fraud_types": [],
        }

    total = len(analyses)
    safe = sum(1 for a in analyses if a.risk_level == "SAFE")
    suspicious = sum(1 for a in analyses if a.risk_level == "SUSPICIOUS")
    blocked = sum(1 for a in analyses if a.risk_level == "BLOCK")
    avg_score = sum(a.risk_score for a in analyses) / total

    # Fraud type frequency
    fraud_counter = {}
    for a in analyses:
        for ft in (a.fraud_types or []):
            fraud_counter[ft] = fraud_counter.get(ft, 0) + 1

    top_frauds = sorted(fraud_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total": total,
        "safe": safe,
        "suspicious": suspicious,
        "blocked": blocked,
        "avg_risk_score": round(avg_score, 2),
        "top_fraud_types": [{"type": k, "count": v} for k, v in top_frauds],
        "risk_distribution": {
            "safe_pct": round(safe / total * 100, 1) if total else 0,
            "suspicious_pct": round(suspicious / total * 100, 1) if total else 0,
            "blocked_pct": round(blocked / total * 100, 1) if total else 0,
        },
    }
