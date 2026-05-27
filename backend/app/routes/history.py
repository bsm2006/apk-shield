"""
History route - retrieve past analysis results
"""
import logging
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional
from app.database import get_db
from app.models import APKAnalysis

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/")
async def get_history(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    risk_level: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Get paginated history of all APK analyses."""
    query = db.query(APKAnalysis)

    if risk_level:
        query = query.filter(APKAnalysis.risk_level == risk_level.upper())

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            (APKAnalysis.filename.ilike(search_term))
            | (APKAnalysis.package_name.ilike(search_term))
            | (APKAnalysis.app_name.ilike(search_term))
        )

    total = query.count()
    analyses = (
        query.order_by(desc(APKAnalysis.created_at))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "pages": (total + limit - 1) // limit,
        "results": [
            {
                "id": a.id,
                "filename": a.filename,
                "package_name": a.package_name,
                "app_name": a.app_name,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "fraud_types": a.fraud_types or [],
                "obfuscation_detected": a.obfuscation_detected,
                "dangerous_permissions_count": len(a.dangerous_permissions or []),
                "status": a.status,
                "created_at": (a.created_at.isoformat() + "Z") if a.created_at else None,
            }
            for a in analyses
        ],
    }


@router.delete("/{analysis_id}")
async def delete_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Delete an analysis record."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Analysis not found")

    db.delete(analysis)
    db.commit()
    return {"message": f"Analysis {analysis_id} deleted successfully"}


@router.get("/stats/dashboard")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """Get statistics for the dashboard overview."""
    total = db.query(APKAnalysis).count()
    completed = db.query(APKAnalysis).filter(APKAnalysis.status == "completed").count()
    safe = db.query(APKAnalysis).filter(APKAnalysis.risk_level == "SAFE").count()
    suspicious = db.query(APKAnalysis).filter(APKAnalysis.risk_level == "SUSPICIOUS").count()
    blocked = db.query(APKAnalysis).filter(APKAnalysis.risk_level == "BLOCK").count()

    # Recent high-risk
    recent_high = (
        db.query(APKAnalysis)
        .filter(APKAnalysis.risk_level.in_(["SUSPICIOUS", "BLOCK"]))
        .order_by(desc(APKAnalysis.created_at))
        .limit(5)
        .all()
    )

    # Average score
    all_completed = db.query(APKAnalysis).filter(APKAnalysis.status == "completed").all()
    avg_score = sum(a.risk_score for a in all_completed) / max(len(all_completed), 1)

    # Fraud type counts
    fraud_counter = {}
    for a in all_completed:
        for ft in (a.fraud_types or []):
            fraud_counter[ft] = fraud_counter.get(ft, 0) + 1

    top_frauds = sorted(fraud_counter.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "totals": {
            "total": total,
            "completed": completed,
            "safe": safe,
            "suspicious": suspicious,
            "blocked": blocked,
        },
        "avg_risk_score": round(avg_score, 1),
        "recent_threats": [
            {
                "id": a.id,
                "filename": a.filename,
                "package_name": a.package_name,
                "risk_score": a.risk_score,
                "risk_level": a.risk_level,
                "created_at": (a.created_at.isoformat() + "Z") if a.created_at else None,
            }
            for a in recent_high
        ],
        "top_fraud_types": [{"type": k, "count": v} for k, v in top_frauds],
    }
