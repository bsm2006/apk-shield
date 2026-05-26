from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime


class FraudIndicator(BaseModel):
    type: str
    description: str
    severity: str
    evidence: List[str]


class SimilarAPK(BaseModel):
    id: int
    filename: str
    package_name: Optional[str]
    risk_level: str
    risk_score: float
    similarity_score: float


class APKAnalysisResponse(BaseModel):
    id: int
    filename: str
    file_hash: str
    package_name: Optional[str]
    app_name: Optional[str]
    version_name: Optional[str]
    risk_score: float
    risk_level: str
    permissions: List[str]
    dangerous_permissions: List[str]
    api_calls: List[str]
    urls: List[str]
    fraud_types: List[str]
    fraud_indicators: List[Dict[str, Any]]
    obfuscation_detected: bool
    obfuscation_indicators: List[str]
    ai_explanation: Optional[str]
    ai_recommendations: List[str]
    similar_apks: List[Dict[str, Any]]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AnalysisHistoryItem(BaseModel):
    id: int
    filename: str
    package_name: Optional[str]
    risk_score: float
    risk_level: str
    fraud_types: List[str]
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScoreBreakdown(BaseModel):
    overall_score: float
    risk_level: str
    permission_score: float
    api_score: float
    url_score: float
    obfuscation_score: float
    behavior_score: float
    weights: Dict[str, float]


class ExplainRequest(BaseModel):
    analysis_id: int


class ExplainResponse(BaseModel):
    analysis_id: int
    explanation: str
    recommendations: List[str]
    threat_summary: str


class UploadResponse(BaseModel):
    message: str
    file_id: str
    filename: str
    file_size: int
    file_hash: str
