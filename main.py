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
    description="Detects containers using latest tags and running as root",
    version="1.0.0"
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


@app.get("/scan", response_model=ScanResponse)
async def scan_cluster():
    """
    Scan the Kubernetes cluster for security anti-patterns:
    - Containers using :latest image tags
    - Containers running as root
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
            f"{len(scan_results.rootContainers)} root user issues"
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
