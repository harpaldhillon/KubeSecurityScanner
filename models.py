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
