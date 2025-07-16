"""
Kubernetes Client Manager
Handles authentication and client initialization
"""

import os
import asyncio
import logging
from typing import Optional
from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


class KubernetesClientManager:
    """
    Manages Kubernetes client initialization and authentication
    Supports both in-cluster and kubeconfig authentication
    """
    
    def __init__(self):
        self._client: Optional[client.CoreV1Api] = None
        self._initialized = False
    
    async def initialize(self) -> None:
        """
        Initialize Kubernetes client with appropriate authentication method
        """
        try:
            logger.info("Initializing Kubernetes client...")
            
            # Try in-cluster config first (for pods running in cluster)
            try:
                config.load_incluster_config()
                logger.info("Using in-cluster Kubernetes configuration")
            except config.ConfigException:
                # Fall back to kubeconfig file
                try:
                    # Try default kubeconfig path
                    kubeconfig_path = os.getenv('KUBECONFIG', os.path.expanduser('~/.kube/config'))
                    config.load_kube_config(config_file=kubeconfig_path)
                    logger.info(f"Using kubeconfig from: {kubeconfig_path}")
                except config.ConfigException as e:
                    logger.error(f"Failed to load kubeconfig: {e}")
                    raise Exception(
                        "Unable to load Kubernetes configuration. "
                        "Ensure you're running in a cluster with proper service account, "
                        "or have a valid kubeconfig file."
                    )
            
            # Create the client
            self._client = client.CoreV1Api()
            
            # Test basic connectivity
            await self.test_connectivity()
            
            self._initialized = True
            logger.info("Kubernetes client initialized successfully")
            
        except Exception as e:
            logger.error(f"Kubernetes client initialization failed: {e}")
            self._initialized = False
            raise
    
    async def test_connectivity(self) -> None:
        """
        Test basic connectivity to Kubernetes API
        """
        if not self._client:
            raise Exception("Kubernetes client not initialized")
        
        try:
            # Test with a simple API call
            loop = asyncio.get_event_loop()
            version_info = await loop.run_in_executor(
                None, self._client.get_api_resources
            )
            logger.debug("Kubernetes API connectivity test successful")
            
        except ApiException as e:
            if e.status == 401:
                raise Exception("Authentication failed - invalid credentials")
            elif e.status == 403:
                raise Exception("Authorization failed - insufficient permissions")
            else:
                raise Exception(f"Kubernetes API error: {e}")
        except Exception as e:
            raise Exception(f"Kubernetes connectivity test failed: {e}")
    
    def is_initialized(self) -> bool:
        """Check if client is properly initialized"""
        return self._initialized and self._client is not None
    
    def get_client(self) -> client.CoreV1Api:
        """Get the initialized Kubernetes client"""
        if not self.is_initialized():
            raise Exception("Kubernetes client not initialized")
        return self._client
    
    async def close(self) -> None:
        """Cleanup client resources"""
        if self._client:
            # Close any open connections
            try:
                if hasattr(self._client.api_client, 'close'):
                    self._client.api_client.close()
            except Exception as e:
                logger.warning(f"Error closing Kubernetes client: {e}")
            
            self._client = None
            self._initialized = False
            logger.info("Kubernetes client closed")
    
    async def reinitialize(self) -> None:
        """
        Reinitialize the client (useful for handling connection errors)
        """
        await self.close()
        await self.initialize()
