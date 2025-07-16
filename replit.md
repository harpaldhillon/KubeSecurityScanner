# Kubernetes Security Scanner

## Overview

This is a Python FastAPI application that scans Kubernetes clusters to detect security anti-patterns and CIS Kubernetes Benchmark compliance violations. The application identifies containers using the `:latest` image tag, containers running as root user, and various CIS compliance violations, providing REST API endpoints to retrieve comprehensive security scan results in structured JSON format.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a modular, microservice-oriented architecture built with FastAPI. It's designed to run either inside a Kubernetes cluster (using in-cluster configuration) or externally (using kubeconfig). The architecture separates concerns into distinct components:

- **API Layer**: FastAPI application handling HTTP requests and responses
- **Scanner Logic**: Core security scanning functionality
- **Kubernetes Client**: Authentication and client management
- **Data Models**: Pydantic models for request/response validation

## Key Components

### 1. FastAPI Application (`main.py`)
- **Purpose**: Main application entry point and HTTP server
- **Technologies**: FastAPI, Uvicorn
- **Responsibilities**: 
  - API endpoint exposure
  - Application lifecycle management
  - Error handling and logging
  - Client initialization coordination

### 2. Kubernetes Client Manager (`k8s_client.py`)
- **Purpose**: Manages Kubernetes API authentication and client initialization
- **Authentication Strategy**: 
  - Primary: In-cluster configuration (for pods running inside cluster)
  - Fallback: Kubeconfig file (for external access)
- **Error Handling**: Graceful fallback between authentication methods

### 3. Security Scanner (`scanner.py`)
- **Purpose**: Core scanning logic for detecting security anti-patterns and CIS compliance violations
- **Detection Capabilities**:
  - Containers using `:latest` image tags
  - Containers running as root user
  - CIS Kubernetes Benchmark compliance violations
  - Network policy violations
  - Service account security issues
- **Scanning Strategy**: Namespace-by-namespace iteration with permission-aware error handling

### 4. CIS Compliance Checker (`cis_checker.py`)
- **Purpose**: Implements CIS Kubernetes Benchmark v1.9.0 compliance checks
- **Supported Controls**:
  - 5.1.4: Minimize access to secrets
  - 5.2.1: Minimize privileged containers
  - 5.2.2-5.2.4: Host namespace sharing controls
  - 5.2.5: Privilege escalation controls
  - 5.2.7-5.2.9: Container capabilities controls
  - 5.3.2: Network policy requirements
  - 5.7.2: Seccomp profile requirements
  - 5.7.3: Security context requirements
  - 5.7.4: Default namespace usage
- **Compliance Levels**: Both L1 (basic) and L2 (advanced) checks

### 5. Data Models (`models.py`)
- **Purpose**: Pydantic models for API request/response structures
- **Models**:
  - `ContainerIssue`: Base model for security issues
  - `LatestTagContainer`: Specific to latest tag violations
  - `RootContainer`: Specific to root user violations
  - `CISViolation`: CIS Kubernetes Benchmark violations
  - `NetworkPolicyViolation`: Network policy compliance issues
  - `ServiceAccountViolation`: Service account security issues
  - `ScanResponse`: Complete scan results with all violation types
  - `ErrorResponse`: Error handling structure

## Data Flow

1. **Initialization**: Application starts and initializes Kubernetes client
2. **Authentication**: Client manager attempts in-cluster config, falls back to kubeconfig
3. **API Request**: Client sends GET request to `/scan` endpoint
4. **Namespace Discovery**: Scanner retrieves all accessible namespaces
5. **Pod Scanning**: For each namespace, scanner examines all pods and containers
6. **Security Analysis**: 
   - Image tag inspection for `:latest` usage
   - Security context analysis for root user detection
   - CIS Kubernetes Benchmark compliance checking
   - Network policy validation
   - Service account security assessment
7. **Result Aggregation**: Security violations are collected and structured by type
8. **Response**: JSON response with categorized security issues, CIS violations, and comprehensive summary

## External Dependencies

### Core Dependencies
- **kubernetes**: Official Kubernetes Python client for cluster API access
- **fastapi**: Modern web framework for API development
- **uvicorn**: ASGI server for FastAPI application
- **pydantic**: Data validation and serialization

### Kubernetes Integration
- **Authentication**: Supports both service account (in-cluster) and kubeconfig authentication
- **RBAC**: Handles permission denied errors gracefully
- **API Version**: Uses CoreV1Api for pod and namespace access

## Deployment Strategy

### Container Deployment (Recommended)
- **Environment**: Designed to run as a pod within Kubernetes cluster
- **Service Account**: Requires appropriate RBAC permissions for cluster scanning
- **Configuration**: Uses in-cluster configuration automatically

### External Deployment
- **Environment**: Can run outside cluster with valid kubeconfig
- **Configuration**: Reads from `~/.kube/config` or `KUBECONFIG` environment variable
- **Use Case**: Development and testing scenarios

### Required Permissions
The application requires the following Kubernetes RBAC permissions:
- `get`, `list` on `pods` across all namespaces
- `get`, `list` on `namespaces`
- Read access to pod security contexts and container specifications

### Scalability Considerations
- **Async Design**: Uses asyncio for non-blocking I/O operations
- **Error Isolation**: Namespace-level error handling prevents complete scan failure
- **Resource Efficiency**: Streams results rather than loading entire cluster state

The architecture prioritizes security scanning accuracy, cluster compatibility, and operational reliability while maintaining simple deployment and maintenance characteristics.