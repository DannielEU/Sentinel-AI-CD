from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional


class VulnerabilityCounts(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    critical: int = Field(default=0, ge=0, le=10000, description="Critical severity vulnerabilities")
    high: int = Field(default=0, ge=0, le=10000, description="High severity vulnerabilities")
    medium: int = Field(default=0, ge=0, le=10000, description="Medium severity vulnerabilities")
    low: int = Field(default=0, ge=0, le=10000, description="Low severity vulnerabilities")
    unknown: int = Field(default=0, ge=0, le=10000, description="Unknown severity vulnerabilities")


class ImageReport(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    image_name: str = Field(..., min_length=1, max_length=255, description="Full name of the container image (e.g. myapp:1.0.0)")
    image_size_mb: float = Field(..., gt=0, le=100000, description="Approximate image size in megabytes")
    vulnerabilities: VulnerabilityCounts = Field(default_factory=VulnerabilityCounts)
    dockerfile_content: Optional[str] = Field(default=None, max_length=50000, description="Raw Dockerfile content (max 50KB)")
    scanner_output: Optional[str] = Field(default=None, max_length=100000, description="Raw output from the security scanner (max 100KB)")
    base_image: Optional[str] = Field(default=None, max_length=255, description="Base image used in FROM instruction")
    os_family: Optional[str] = Field(default=None, max_length=100, description="OS family inside the image")

    @field_validator('image_name')
    @classmethod
    def validate_image_name(cls, v: str) -> str:
        # Only allow alphanumeric, dots, slashes, colons, hyphens, underscores
        import re
        if not re.match(r'^[a-zA-Z0-9.:/_-]+$', v):
            raise ValueError('Invalid image name format')
        return v


class GateDecision(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    decision: str = Field(..., pattern=r'^(APPROVED|WARNING|REJECTED)$', description="APPROVED | WARNING | REJECTED")
    reason: str = Field(..., max_length=500, description="Short explanation of the decision")
    recommendations: list[str] = Field(default_factory=list, max_length=5, description="List of actionable recommendations (max 5)")
    source: str = Field(default="rule_engine", pattern=r'^(rule_engine|ai_model)$', description="rule_engine | ai_model")
    image_name: str = Field(..., max_length=255, description="Image that was analysed")
