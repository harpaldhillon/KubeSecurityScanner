"""
Kubernetes Security Scanner FastAPI Application
Detects containers using latest tags and running as root
"""

import asyncio
import logging
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn

from models import ScanResponse, ErrorResponse
from scanner import KubernetesSecurityScanner
from k8s_client import KubernetesClientManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Kubernetes Security Scanner",
    description="Detects containers using latest tags, running as root, and CIS Kubernetes Benchmark compliance violations",
    version="1.1.0"
)

# Global client manager
client_manager = KubernetesClientManager()


@app.on_event("startup")
async def startup_event():
    """Initialize Kubernetes client on startup"""
    try:
        await client_manager.initialize()
        logger.info("Kubernetes client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Kubernetes client: {e}")
        # Don't raise here - let individual requests handle the error


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await client_manager.close()
    logger.info("Kubernetes client closed")


@app.get("/", response_model=Dict[str, str])
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Kubernetes Security Scanner",
        "version": "1.0.0"
    }


@app.get("/health", response_model=Dict[str, str])
async def health_check():
    """Detailed health check including Kubernetes connectivity"""
    try:
        if not client_manager.is_initialized():
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "reason": "Kubernetes client not initialized"
                }
            )
        
        # Test basic connectivity
        await client_manager.test_connectivity()
        
        return {
            "status": "healthy",
            "kubernetes": "connected",
            "service": "Kubernetes Security Scanner"
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "reason": f"Kubernetes connectivity error: {str(e)}"
            }
        )


@app.get("/cis-controls", response_model=Dict[str, Any])
async def get_cis_controls():
    """Get information about CIS Kubernetes Benchmark controls supported by this scanner"""
    return {
        "benchmark_version": "CIS Kubernetes Benchmark v1.9.0",
        "release_date": "December 2024",
        "supported_controls": {
            "5.1.4": {
                "title": "Minimize access to secrets",
                "level": "L1",
                "description": "Checks for unnecessary secret volume mounts"
            },
            "5.2.1": {
                "title": "Minimize the admission of privileged containers",
                "level": "L1",
                "description": "Detects containers running with privileged: true"
            },
            "5.2.2": {
                "title": "Minimize the admission of containers wishing to share the host process ID namespace",
                "level": "L1",
                "description": "Detects pods using hostPID: true"
            },
            "5.2.3": {
                "title": "Minimize the admission of containers wishing to share the host IPC namespace",
                "level": "L1",
                "description": "Detects pods using hostIPC: true"
            },
            "5.2.4": {
                "title": "Minimize the admission of containers wishing to share the host network namespace",
                "level": "L1",
                "description": "Detects pods using hostNetwork: true"
            },
            "5.2.5": {
                "title": "Minimize the admission of containers with allowPrivilegeEscalation",
                "level": "L1",
                "description": "Detects containers without allowPrivilegeEscalation: false"
            },
            "5.2.7": {
                "title": "Minimize the admission of containers with the NET_RAW capability",
                "level": "L1",
                "description": "Detects containers with NET_RAW capability added"
            },
            "5.2.8": {
                "title": "Minimize the admission of containers with added capabilities",
                "level": "L1",
                "description": "Detects containers with unnecessary added capabilities"
            },
            "5.2.9": {
                "title": "Minimize the admission of containers with capabilities assigned",
                "level": "L1",
                "description": "Detects containers that don't drop ALL capabilities"
            },
            "5.3.2": {
                "title": "Ensure that all Namespaces have Network Policies defined",
                "level": "L1",
                "description": "Checks for missing network policies in namespaces"
            },
            "5.7.2": {
                "title": "Ensure that the seccomp profile is set to docker/default in your pod definitions",
                "level": "L1",
                "description": "Detects pods without seccomp profiles"
            },
            "5.7.3": {
                "title": "Apply Security Context to Your Pods and Containers",
                "level": "L1",
                "description": "Detects pods/containers without security context"
            },
            "5.7.4": {
                "title": "The default namespace should not be used",
                "level": "L1",
                "description": "Detects workloads deployed in the default namespace"
            }
        },
        "additional_checks": {
            "latest_tags": "Detects containers using :latest image tags",
            "root_users": "Detects containers running as root user",
            "service_accounts": "Checks for service accounts with automountServiceAccountToken enabled"
        }
    }


@app.get("/scan", response_model=ScanResponse)
async def scan_cluster():
    """
    Scan the Kubernetes cluster for security anti-patterns:
    - Containers using :latest image tags
    - Containers running as root
    - CIS Kubernetes Benchmark compliance violations
    - Network policy violations
    - Service account security issues
    """
    try:
        if not client_manager.is_initialized():
            raise HTTPException(
                status_code=503,
                detail="Kubernetes client not initialized. Check cluster connectivity."
            )
        
        # Initialize scanner with the client
        scanner = KubernetesSecurityScanner(client_manager.get_client())
        
        # Perform the security scan
        scan_results = await scanner.scan_cluster()
        
        logger.info(
            f"Scan completed: {len(scan_results.latestTagContainers)} latest tag issues, "
            f"{len(scan_results.rootContainers)} root user issues, "
            f"{len(scan_results.cisViolations)} CIS violations, "
            f"{len(scan_results.networkPolicyViolations)} network policy violations, "
            f"{len(scan_results.serviceAccountViolations)} service account violations"
        )
        
        return scan_results
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        
        # Handle specific error types
        if "permission denied" in str(e).lower() or "forbidden" in str(e).lower():
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions to scan cluster: {str(e)}"
            )
        elif "unauthorized" in str(e).lower():
            raise HTTPException(
                status_code=401,
                detail=f"Authentication failed: {str(e)}"
            )
        elif "connection" in str(e).lower() or "timeout" in str(e).lower():
            raise HTTPException(
                status_code=503,
                detail=f"Cluster connectivity error: {str(e)}"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Internal scan error: {str(e)}"
            )


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred while processing the request"
        }
    )


if __name__ == "__main__":
    """Run the FastAPI application"""
    logger.info("Starting Kubernetes Security Scanner...")
    
    # Run with uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=5000,
        log_level="info",
        reload=False
    )
