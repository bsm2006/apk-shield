from sqlalchemy import Column, Integer, String, Float, JSON, DateTime, Text, Boolean
from sqlalchemy.sql import func
from app.database import Base


class APKAnalysis(Base):
    __tablename__ = "apk_analyses"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(500), nullable=False)
    file_hash = Column(String(64), unique=True, index=True)
    file_size = Column(Integer)
    package_name = Column(String(500))
    app_name = Column(String(500))
    version_code = Column(String(100))
    version_name = Column(String(100))
    sdk_min = Column(Integer)
    sdk_target = Column(Integer)

    # Extracted features
    permissions = Column(JSON, default=[])
    dangerous_permissions = Column(JSON, default=[])
    api_calls = Column(JSON, default=[])
    urls = Column(JSON, default=[])
    receivers = Column(JSON, default=[])
    services = Column(JSON, default=[])
    activities = Column(JSON, default=[])

    # Scoring
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(50), default="SAFE")  # SAFE, SUSPICIOUS, BLOCK
    permission_score = Column(Float, default=0.0)
    api_score = Column(Float, default=0.0)
    url_score = Column(Float, default=0.0)
    obfuscation_score = Column(Float, default=0.0)
    behavior_score = Column(Float, default=0.0)

    # Fraud mapping
    fraud_types = Column(JSON, default=[])
    fraud_indicators = Column(JSON, default=[])

    # Obfuscation indicators
    obfuscation_detected = Column(Boolean, default=False)
    obfuscation_indicators = Column(JSON, default=[])

    # AI Explanation
    ai_explanation = Column(Text)
    ai_recommendations = Column(JSON, default=[])

    # Similarity
    similar_apks = Column(JSON, default=[])
    feature_vector = Column(JSON, default=[])

    # Status
    status = Column(String(50), default="pending")  # pending, processing, completed, error
    error_message = Column(Text)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class ThreatSignature(Base):
    __tablename__ = "threat_signatures"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    category = Column(String(100))
    pattern = Column(String(500))
    description = Column(Text)
    severity = Column(String(50))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
