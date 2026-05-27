"""
APK Analysis Route - orchestrates the full analysis pipeline
"""
import os
import logging
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from typing import Optional

from app.database import get_db
from app.models import APKAnalysis
from app.analysis.apk_analyzer import analyze_apk
from app.analysis.risk_scorer import compute_risk_score
from app.analysis.fraud_mapper import map_fraud_types
from app.analysis.similarity_engine import build_feature_vector, find_similar_apks
from app.analysis.ai_explainer import generate_explanation

logger = logging.getLogger(__name__)
router = APIRouter()

UPLOAD_DIR = "uploads"


async def run_full_analysis(
    file_hash: str,
    filename: str,
    upload_path: str,
    db: Session,
) -> APKAnalysis:
    """Run the complete analysis pipeline."""

    # Check if already analyzed
    existing = db.query(APKAnalysis).filter(APKAnalysis.file_hash == file_hash).first()
    if existing and existing.status == "completed":
        logger.info(f"Returning cached analysis for hash {file_hash[:16]}")
        return existing

    # Create or update record
    if existing:
        analysis = existing
    else:
        analysis = APKAnalysis(
            filename=filename,
            file_hash=file_hash,
            status="processing",
        )
        db.add(analysis)
        db.commit()
        db.refresh(analysis)

    try:
        analysis.status = "processing"
        db.commit()

        # Step 1: Static analysis
        logger.info(f"Starting APK analysis: {filename}")
        apk_data = analyze_apk(upload_path)

        # Update analysis with extracted data
        analysis.file_size = apk_data.get("file_size", 0)
        analysis.package_name = apk_data.get("package_name")
        analysis.app_name = apk_data.get("app_name")
        analysis.version_code = apk_data.get("version_code")
        analysis.version_name = apk_data.get("version_name")
        analysis.sdk_min = apk_data.get("sdk_min")
        analysis.sdk_target = apk_data.get("sdk_target")
        analysis.permissions = apk_data.get("permissions", [])
        analysis.dangerous_permissions = apk_data.get("dangerous_permissions", [])
        analysis.api_calls = apk_data.get("api_calls", [])
        analysis.urls = apk_data.get("urls", [])
        analysis.receivers = apk_data.get("receivers", [])
        analysis.services = apk_data.get("services", [])
        analysis.activities = apk_data.get("activities", [])
        analysis.obfuscation_detected = apk_data.get("obfuscation_detected", False)
        analysis.obfuscation_indicators = apk_data.get("obfuscation_indicators", [])

        # Step 2: Risk scoring
        logger.info("Computing risk score...")
        score_data = compute_risk_score(apk_data)
        analysis.risk_score = score_data["risk_score"]
        analysis.risk_level = score_data["risk_level"]
        analysis.permission_score = score_data["permission_score"]
        analysis.api_score = score_data["api_score"]
        analysis.url_score = score_data["url_score"]
        analysis.obfuscation_score = score_data["obfuscation_score"]
        analysis.behavior_score = score_data["behavior_score"]

        # Step 3: Fraud mapping
        logger.info("Mapping fraud types...")
        fraud_data = map_fraud_types(apk_data)
        analysis.fraud_types = fraud_data.get("fraud_types", [])
        analysis.fraud_indicators = fraud_data.get("fraud_indicators", [])

        # Step 4: Build feature vector for similarity
        logger.info("Building feature vector...")
        full_data = {**apk_data, **score_data}
        feature_vector = build_feature_vector(full_data)
        analysis.feature_vector = feature_vector

        # Step 5: Find similar APKs
        logger.info("Finding similar APKs...")
        other_analyses = db.query(APKAnalysis).filter(
            APKAnalysis.id != analysis.id,
            APKAnalysis.status == "completed",
            APKAnalysis.feature_vector != None,
        ).limit(100).all()

        stored = [
            {
                "id": a.id,
                "filename": a.filename,
                "package_name": a.package_name,
                "risk_level": a.risk_level,
                "risk_score": a.risk_score,
                "fraud_types": a.fraud_types,
                "feature_vector": a.feature_vector,
            }
            for a in other_analyses
        ]
        similar_apks = find_similar_apks(feature_vector, stored)
        analysis.similar_apks = similar_apks

        # Step 6: AI Explanation
        logger.info("Generating AI explanation...")
        ai_result = await generate_explanation(apk_data, score_data, fraud_data)
        analysis.ai_explanation = ai_result.get("explanation", "")
        analysis.ai_recommendations = ai_result.get("recommendations", [])

        # Mark complete
        analysis.status = "completed"
        db.commit()
        db.refresh(analysis)

        logger.info(f"Analysis complete: {filename} | Score: {analysis.risk_score} | Level: {analysis.risk_level}")
        return analysis

    except Exception as e:
        logger.error(f"Analysis failed for {filename}: {e}", exc_info=True)
        analysis.status = "error"
        analysis.error_message = str(e)
        db.commit()
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/{file_hash}")
async def analyze_uploaded_apk(
    file_hash: str,
    filename: str,
    db: Session = Depends(get_db),
):
    """Trigger analysis for an uploaded APK by its hash."""
    # Find the uploaded file
    upload_path = None
    for f in os.listdir(UPLOAD_DIR):
        if f.startswith(file_hash[:16]):
            upload_path = os.path.join(UPLOAD_DIR, f)
            break

    if not upload_path or not os.path.exists(upload_path):
        raise HTTPException(
            status_code=404,
            detail=f"Uploaded file not found for hash {file_hash[:16]}. Please upload first.",
        )

    analysis = await run_full_analysis(file_hash, filename, upload_path, db)

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "file_hash": analysis.file_hash,
        "package_name": analysis.package_name,
        "app_name": analysis.app_name,
        "version_name": analysis.version_name,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "permissions": analysis.permissions,
        "dangerous_permissions": analysis.dangerous_permissions,
        "api_calls": analysis.api_calls,
        "urls": analysis.urls,
        "fraud_types": analysis.fraud_types,
        "fraud_indicators": analysis.fraud_indicators,
        "obfuscation_detected": analysis.obfuscation_detected,
        "obfuscation_indicators": analysis.obfuscation_indicators,
        "ai_explanation": analysis.ai_explanation,
        "ai_recommendations": analysis.ai_recommendations,
        "similar_apks": analysis.similar_apks,
        "services": analysis.services,
        "receivers": analysis.receivers,
        "activities": analysis.activities,
        "permission_score": analysis.permission_score,
        "api_score": analysis.api_score,
        "url_score": analysis.url_score,
        "obfuscation_score": analysis.obfuscation_score,
        "behavior_score": analysis.behavior_score,
        "status": analysis.status,
        "created_at": (analysis.created_at.isoformat() + "Z") if analysis.created_at else None,
    }


@router.get("/{analysis_id}")
async def get_analysis(analysis_id: int, db: Session = Depends(get_db)):
    """Get a specific analysis by ID."""
    analysis = db.query(APKAnalysis).filter(APKAnalysis.id == analysis_id).first()
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")

    return {
        "id": analysis.id,
        "filename": analysis.filename,
        "file_hash": analysis.file_hash,
        "package_name": analysis.package_name,
        "app_name": analysis.app_name,
        "version_name": analysis.version_name,
        "risk_score": analysis.risk_score,
        "risk_level": analysis.risk_level,
        "permissions": analysis.permissions,
        "dangerous_permissions": analysis.dangerous_permissions,
        "api_calls": analysis.api_calls,
        "urls": analysis.urls,
        "fraud_types": analysis.fraud_types,
        "fraud_indicators": analysis.fraud_indicators,
        "obfuscation_detected": analysis.obfuscation_detected,
        "obfuscation_indicators": analysis.obfuscation_indicators,
        "ai_explanation": analysis.ai_explanation,
        "ai_recommendations": analysis.ai_recommendations,
        "similar_apks": analysis.similar_apks,
        "services": analysis.services,
        "receivers": analysis.receivers,
        "activities": analysis.activities,
        "permission_score": analysis.permission_score,
        "api_score": analysis.api_score,
        "url_score": analysis.url_score,
        "obfuscation_score": analysis.obfuscation_score,
        "behavior_score": analysis.behavior_score,
        "status": analysis.status,
        "created_at": (analysis.created_at.isoformat() + "Z") if analysis.created_at else None,
    }
