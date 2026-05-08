from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_validator


class CodeFile(BaseModel):
    filename: str = Field(..., min_length=1, max_length=500)
    content: str = Field(..., min_length=1, max_length=50000)


class CodeVulnerability(BaseModel):
    type: str = Field(..., max_length=200)
    severity: str = Field(..., pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW)$")
    line_number: Optional[int] = None
    description: str = Field(..., max_length=1000)
    code_snippet: Optional[str] = Field(default=None, max_length=2000)
    suggestion: Optional[str] = Field(default=None, max_length=1000)
    cwe_id: Optional[str] = Field(default=None, max_length=50)
    filename: str = Field(..., max_length=500)


class VulnerabilitySummary(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0


class CodeScanReport(BaseModel):
    project_name: str = Field(..., min_length=1, max_length=255)
    commit_sha: Optional[str] = Field(default=None, max_length=100)
    branch: Optional[str] = Field(default=None, max_length=255)
    files: list[CodeFile] = Field(..., min_length=1, max_length=100)

    @field_validator("project_name")
    @classmethod
    def validate_project_name(cls, v: str) -> str:
        import re
        if not re.match(r"^[a-zA-Z0-9._/\-]+$", v):
            raise ValueError("Invalid project name format")
        return v


class CodeScanDecision(BaseModel):
    decision: str = Field(..., pattern=r"^(BLOCKED|WARNING|PASSED)$")
    reason: str = Field(..., max_length=500)
    files_analyzed: int
    total_vulnerabilities: int
    summary: VulnerabilitySummary
    vulnerabilities: list[CodeVulnerability] = Field(default_factory=list)
    blocked: bool
    project_name: str = Field(..., max_length=255)
    commit_sha: Optional[str] = Field(default=None, max_length=100)
    ai_provider: Optional[str] = Field(default=None, max_length=100)


class CodeScanRecord(BaseModel):
    id: Optional[int] = None
    project_name: str
    commit_sha: Optional[str] = None
    branch: Optional[str] = None
    decision: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    files_analyzed: int = 0
    ai_provider: Optional[str] = None
    scanned_at: Optional[datetime] = None
    vulnerabilities: list[CodeVulnerability] = Field(default_factory=list)
