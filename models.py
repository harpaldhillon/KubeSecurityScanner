"""
Pydantic models for API request/response structures
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ContainerIssue(BaseModel):
    """Base model for container security issues"""
    namespace: str = Field(..., description="Kubernetes namespace")
    pod: str = Field(..., description="Pod name")
    container: str = Field(..., description="Container name")


class LatestTagContainer(ContainerIssue):
    """Container using latest image tag"""
    image: str = Field(..., description="Full container image name with latest tag")


class RootContainer(ContainerIssue):
    """Container running as root user"""
    reason: str = Field(..., description="Reason why container is running as root")
    user_id: Optional[int] = Field(None, description="Explicit user ID if set")
    run_as_non_root: Optional[bool] = Field(None, description="runAsNonRoot setting")


class CISViolation(ContainerIssue):
    """CIS Kubernetes Benchmark violation"""
    control_id: str = Field(..., description="CIS control identifier (e.g., 5.1.1)")
    control_title: str = Field(..., description="CIS control title")
    severity: str = Field(..., description="Violation severity: Critical, High, Medium, Low")
    description: str = Field(..., description="Detailed description of the violation")
    remediation: str = Field(..., description="Recommended remediation steps")
    level: str = Field(..., description="CIS level: L1 or L2")


class NetworkPolicyViolation(BaseModel):
    """Network policy CIS violation"""
    namespace: str = Field(..., description="Kubernetes namespace")
    control_id: str = Field(..., description="CIS control identifier")
    control_title: str = Field(..., description="CIS control title")
    severity: str = Field(..., description="Violation severity")
    description: str = Field(..., description="Detailed description of the violation")
    remediation: str = Field(..., description="Recommended remediation steps")


class ServiceAccountViolation(BaseModel):
    """Service account CIS violation"""
    namespace: str = Field(..., description="Kubernetes namespace")
    service_account: str = Field(..., description="Service account name")
    control_id: str = Field(..., description="CIS control identifier")
    control_title: str = Field(..., description="CIS control title")
    severity: str = Field(..., description="Violation severity")
    description: str = Field(..., description="Detailed description of the violation")
    remediation: str = Field(..., description="Recommended remediation steps")


class ScanResponse(BaseModel):
    """Response model for cluster security scan"""
    latestTagContainers: List[LatestTagContainer] = Field(
        default_factory=list,
        description="Containers using latest image tags"
    )
    rootContainers: List[RootContainer] = Field(
        default_factory=list,
        description="Containers running as root"
    )
    cisViolations: List[CISViolation] = Field(
        default_factory=list,
        description="CIS Kubernetes Benchmark violations"
    )
    networkPolicyViolations: List[NetworkPolicyViolation] = Field(
        default_factory=list,
        description="Network policy related CIS violations"
    )
    serviceAccountViolations: List[ServiceAccountViolation] = Field(
        default_factory=list,
        description="Service account related CIS violations"
    )
    summary: dict = Field(
        default_factory=dict,
        description="Scan summary statistics"
    )


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str = Field(..., description="Error type")
    detail: str = Field(..., description="Detailed error message")
    timestamp: Optional[str] = Field(None, description="Error timestamp")


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str = Field(..., description="Service health status")
    kubernetes: Optional[str] = Field(None, description="Kubernetes connectivity status")
    service: str = Field(..., description="Service name")
    version: Optional[str] = Field(None, description="Service version")
