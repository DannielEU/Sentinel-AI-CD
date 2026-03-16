from pydantic import BaseModel, Field
from typing import Optional


class VulnerabilityCounts(BaseModel):
    critical: int = Field(default=0, ge=0, description="Critical severity vulnerabilities")
    high: int = Field(default=0, ge=0, description="High severity vulnerabilities")
    medium: int = Field(default=0, ge=0, description="Medium severity vulnerabilities")
    low: int = Field(default=0, ge=0, description="Low severity vulnerabilities")
    unknown: int = Field(default=0, ge=0, description="Unknown severity vulnerabilities")


class ImageReport(BaseModel):
    image_name: str = Field(..., description="Full name of the container image (e.g. myapp:1.0.0)")
    image_size_mb: float = Field(..., gt=0, description="Approximate image size in megabytes")
    vulnerabilities: VulnerabilityCounts = Field(default_factory=VulnerabilityCounts)
    dockerfile_content: Optional[str] = Field(default=None, description="Raw Dockerfile content")
    scanner_output: Optional[str] = Field(default=None, description="Raw output from the security scanner (e.g. Trivy)")
    base_image: Optional[str] = Field(default=None, description="Base image used in FROM instruction")
    os_family: Optional[str] = Field(default=None, description="OS family inside the image (e.g. debian, alpine)")


class GateDecision(BaseModel):
    decision: str = Field(..., description="APPROVED | WARNING | REJECTED")
    reason: str = Field(..., description="Short explanation of the decision")
    recommendations: list[str] = Field(default_factory=list, description="List of actionable recommendations")
    source: str = Field(default="rule_engine", description="rule_engine | ai_model")
    image_name: str = Field(..., description="Image that was analysed")
