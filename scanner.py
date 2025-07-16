"""
Kubernetes Security Scanner
Implements security anti-pattern detection logic
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from kubernetes import client
from kubernetes.client.rest import ApiException

from models import ScanResponse, LatestTagContainer, RootContainer

logger = logging.getLogger(__name__)


class KubernetesSecurityScanner:
    """
    Scans Kubernetes cluster for security anti-patterns:
    - Containers using :latest image tags
    - Containers running as root
    """
    
    def __init__(self, k8s_client: client.CoreV1Api):
        self.k8s_client = k8s_client
        
    async def scan_cluster(self) -> ScanResponse:
        """
        Perform a complete security scan of the cluster
        """
        logger.info("Starting cluster security scan...")
        
        latest_tag_containers = []
        root_containers = []
        
        try:
            # Get all namespaces
            namespaces = await self._get_all_namespaces()
            logger.info(f"Scanning {len(namespaces)} namespaces")
            
            # Scan each namespace
            for namespace in namespaces:
                try:
                    namespace_latest, namespace_root = await self._scan_namespace(namespace)
                    latest_tag_containers.extend(namespace_latest)
                    root_containers.extend(namespace_root)
                except ApiException as e:
                    if e.status == 403:
                        logger.warning(f"No permission to scan namespace {namespace}: {e}")
                    else:
                        logger.error(f"Error scanning namespace {namespace}: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error scanning namespace {namespace}: {e}")
            
            # Create summary
            summary = {
                "namespacesScanned": len(namespaces),
                "latestTagIssues": len(latest_tag_containers),
                "rootUserIssues": len(root_containers),
                "totalIssues": len(latest_tag_containers) + len(root_containers)
            }
            
            logger.info(f"Scan completed: {summary}")
            
            return ScanResponse(
                latestTagContainers=latest_tag_containers,
                rootContainers=root_containers,
                summary=summary
            )
            
        except Exception as e:
            logger.error(f"Cluster scan failed: {e}")
            raise
    
    async def _get_all_namespaces(self) -> List[str]:
        """Get list of all namespaces in the cluster"""
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            namespaces_response = await loop.run_in_executor(
                None, self.k8s_client.list_namespace
            )
            
            return [ns.metadata.name for ns in namespaces_response.items]
            
        except ApiException as e:
            logger.error(f"Failed to list namespaces: {e}")
            raise
    
    async def _scan_namespace(self, namespace: str) -> tuple[List[LatestTagContainer], List[RootContainer]]:
        """
        Scan a specific namespace for security issues
        """
        logger.debug(f"Scanning namespace: {namespace}")
        
        latest_tag_containers = []
        root_containers = []
        
        try:
            # Get all pods in namespace
            loop = asyncio.get_event_loop()
            pods_response = await loop.run_in_executor(
                None, self.k8s_client.list_namespaced_pod, namespace
            )
            
            for pod in pods_response.items:
                pod_name = pod.metadata.name
                
                # Check regular containers
                if pod.spec.containers:
                    for container in pod.spec.containers:
                        # Check for latest tag
                        latest_issue = self._check_latest_tag(
                            namespace, pod_name, container.name, container.image
                        )
                        if latest_issue:
                            latest_tag_containers.append(latest_issue)
                        
                        # Check for root user
                        root_issue = self._check_root_user(
                            namespace, pod_name, container.name, 
                            container.security_context, pod.spec.security_context
                        )
                        if root_issue:
                            root_containers.append(root_issue)
                
                # Check init containers
                if pod.spec.init_containers:
                    for init_container in pod.spec.init_containers:
                        # Check for latest tag
                        latest_issue = self._check_latest_tag(
                            namespace, pod_name, f"init-{init_container.name}", init_container.image
                        )
                        if latest_issue:
                            latest_tag_containers.append(latest_issue)
                        
                        # Check for root user
                        root_issue = self._check_root_user(
                            namespace, pod_name, f"init-{init_container.name}",
                            init_container.security_context, pod.spec.security_context
                        )
                        if root_issue:
                            root_containers.append(root_issue)
            
            logger.debug(
                f"Namespace {namespace}: {len(latest_tag_containers)} latest tag issues, "
                f"{len(root_containers)} root user issues"
            )
            
        except ApiException as e:
            logger.error(f"Failed to scan namespace {namespace}: {e}")
            raise
        
        return latest_tag_containers, root_containers
    
    def _check_latest_tag(self, namespace: str, pod_name: str, 
                         container_name: str, image: str) -> Optional[LatestTagContainer]:
        """
        Check if container is using latest tag
        """
        if not image:
            return None
        
        # Check for explicit :latest tag
        if image.endswith(':latest'):
            return LatestTagContainer(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                image=image
            )
        
        # Check for implicit latest (no tag specified)
        if ':' not in image or image.count(':') == 1 and '/' in image.split(':')[0]:
            # Image has no tag, which defaults to latest
            return LatestTagContainer(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                image=f"{image}:latest"
            )
        
        return None
    
    def _check_root_user(self, namespace: str, pod_name: str, container_name: str,
                        container_security_context, pod_security_context) -> Optional[RootContainer]:
        """
        Check if container is running as root user
        """
        # Priority: container security context > pod security context
        
        # Check container-level security context first
        if container_security_context:
            # Explicit runAsUser = 0
            if (hasattr(container_security_context, 'run_as_user') and 
                container_security_context.run_as_user is not None):
                if container_security_context.run_as_user == 0:
                    return RootContainer(
                        namespace=namespace,
                        pod=pod_name,
                        container=container_name,
                        reason="Container runAsUser=0",
                        user_id=0,
                        run_as_non_root=getattr(container_security_context, 'run_as_non_root', None)
                    )
                else:
                    # Explicit non-root user
                    return None
            
            # Explicit runAsNonRoot = false
            if (hasattr(container_security_context, 'run_as_non_root') and 
                container_security_context.run_as_non_root is False):
                return RootContainer(
                    namespace=namespace,
                    pod=pod_name,
                    container=container_name,
                    reason="Container runAsNonRoot=false",
                    user_id=getattr(container_security_context, 'run_as_user', None),
                    run_as_non_root=False
                )
        
        # Check pod-level security context
        if pod_security_context:
            # Explicit runAsUser = 0 at pod level
            if (hasattr(pod_security_context, 'run_as_user') and 
                pod_security_context.run_as_user is not None):
                if pod_security_context.run_as_user == 0:
                    return RootContainer(
                        namespace=namespace,
                        pod=pod_name,
                        container=container_name,
                        reason="Pod runAsUser=0",
                        user_id=0,
                        run_as_non_root=getattr(pod_security_context, 'run_as_non_root', None)
                    )
                else:
                    # Explicit non-root user at pod level
                    return None
            
            # Explicit runAsNonRoot = false at pod level
            if (hasattr(pod_security_context, 'run_as_non_root') and 
                pod_security_context.run_as_non_root is False):
                return RootContainer(
                    namespace=namespace,
                    pod=pod_name,
                    container=container_name,
                    reason="Pod runAsNonRoot=false",
                    user_id=getattr(pod_security_context, 'run_as_user', None),
                    run_as_non_root=False
                )
        
        # No security context defined - defaults to root in most cases
        # This is a potential security issue
        if not container_security_context and not pod_security_context:
            return RootContainer(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                reason="No security context defined (defaults to root)",
                user_id=None,
                run_as_non_root=None
            )
        
        # Security context exists but no explicit user settings - potential root
        has_user_setting = False
        
        if container_security_context:
            if (hasattr(container_security_context, 'run_as_user') and 
                container_security_context.run_as_user is not None):
                has_user_setting = True
            if (hasattr(container_security_context, 'run_as_non_root') and 
                container_security_context.run_as_non_root is not None):
                has_user_setting = True
        
        if pod_security_context and not has_user_setting:
            if (hasattr(pod_security_context, 'run_as_user') and 
                pod_security_context.run_as_user is not None):
                has_user_setting = True
            if (hasattr(pod_security_context, 'run_as_non_root') and 
                pod_security_context.run_as_non_root is not None):
                has_user_setting = True
        
        if not has_user_setting:
            return RootContainer(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                reason="Security context exists but no user settings (defaults to root)",
                user_id=None,
                run_as_non_root=None
            )
        
        return None
