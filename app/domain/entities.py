from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator, ConfigDict


class VulnerabilityCounts(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    critical: int = Field(default=0, ge=0, le=10000)
    high: int = Field(default=0, ge=0, le=10000)
    medium: int = Field(default=0, ge=0, le=10000)
    low: int = Field(default=0, ge=0, le=10000)
    unknown: int = Field(default=0, ge=0, le=10000)


class HighVulnerabilityDetail(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(..., max_length=50)
    package: str = Field(..., max_length=255)
    title: str = Field(..., max_length=500)
    description: Optional[str] = Field(default=None, max_length=1000)


class ImageReport(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    image_name: str = Field(..., min_length=1, max_length=255)
    image_size_mb: float = Field(..., gt=0, le=100000)
    vulnerabilities: VulnerabilityCounts = Field(default_factory=VulnerabilityCounts)
    dockerfile_content: Optional[str] = Field(default=None, max_length=50000)
    scanner_output: Optional[str] = Field(default=None, max_length=100000)
    base_image: Optional[str] = Field(default=None, max_length=255)
    os_family: Optional[str] = Field(default=None, max_length=100)
    high_vulnerabilities_details: Optional[list[HighVulnerabilityDetail]] = Field(
        default=None, max_length=10
    )

    @field_validator("image_name")
    @classmethod
    def validate_image_name(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-zA-Z0-9.:/_-]+$", v):
            raise ValueError("Invalid image name format")
        return v


class GateDecision(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    decision: str = Field(..., pattern=r"^(APPROVED|WARNING|REJECTED)$")
    reason: str = Field(..., max_length=500)
    recommendations: list[str] = Field(default_factory=list, max_length=5)
    summary: Optional[str] = Field(default=None, max_length=2000)
    source: str = Field(
        default="rule_engine",
        pattern=r"^(rule_engine|ai_model|secrets_detector)$",
    )
    image_name: str = Field(..., max_length=255)
    dashboard_url: Optional[str] = Field(default=None, max_length=2048)


class ScanRecord(BaseModel):
    id: Optional[int] = None
    image_name: str
    decision: str
    reason: str
    source: str
    critical_vulns: int = 0
    high_vulns: int = 0
    medium_vulns: int = 0
    low_vulns: int = 0
    image_size_mb: float = 0.0
    secrets_found: int = 0
    ai_provider: Optional[str] = None
    scanned_at: Optional[datetime] = None


class CVEException(BaseModel):
    id: Optional[int] = None
    cve_id: str = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=500)
    approved_by: Optional[str] = Field(default=None, max_length=255)
    expires_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    is_active: bool = True
