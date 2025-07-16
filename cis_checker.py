"""
CIS Kubernetes Benchmark Compliance Checker
Implements security checks based on CIS Kubernetes Benchmark v1.9.0
"""

import asyncio
import logging
from typing import List, Optional, Dict, Any
from kubernetes import client
from kubernetes.client.rest import ApiException

from models import CISViolation, NetworkPolicyViolation, ServiceAccountViolation

logger = logging.getLogger(__name__)


class CISComplianceChecker:
    """
    Implements CIS Kubernetes Benchmark compliance checks
    Based on CIS Kubernetes Benchmark v1.9.0 (December 2024)
    """
    
    def __init__(self, k8s_client: client.CoreV1Api):
        self.k8s_client = k8s_client
        self.networking_client = client.NetworkingV1Api()
        
    async def check_cis_compliance(self, namespace: str, pod_name: str, container_name: str,
                                 container_spec, pod_spec) -> List[CISViolation]:
        """
        Check container against CIS Kubernetes Benchmark controls
        """
        violations = []
        
        # CIS 5.1.1 - Ensure that the cluster-admin role is only used where required
        # This is checked at service account level
        
        # CIS 5.1.3 - Minimize wildcard use in Roles and ClusterRoles
        # This requires RBAC API access
        
        # CIS 5.1.4 - Minimize access to secrets
        # Check if container has unnecessary secret mounts
        violations.extend(self._check_secret_mounts(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.1.5 - Minimize access to create pods
        # This is RBAC related, checked separately
        
        # CIS 5.2.1 - Minimize the admission of privileged containers
        violations.extend(self._check_privileged_containers(namespace, pod_name, container_name, container_spec))
        
        # CIS 5.2.2 - Minimize the admission of containers wishing to share the host process ID namespace
        violations.extend(self._check_host_pid(namespace, pod_name, container_name, pod_spec))
        
        # CIS 5.2.3 - Minimize the admission of containers wishing to share the host IPC namespace
        violations.extend(self._check_host_ipc(namespace, pod_name, container_name, pod_spec))
        
        # CIS 5.2.4 - Minimize the admission of containers wishing to share the host network namespace
        violations.extend(self._check_host_network(namespace, pod_name, container_name, pod_spec))
        
        # CIS 5.2.5 - Minimize the admission of containers with allowPrivilegeEscalation
        violations.extend(self._check_privilege_escalation(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.2.6 - Minimize the admission of root containers
        # This is already handled by the main root container check
        
        # CIS 5.2.7 - Minimize the admission of containers with the NET_RAW capability
        violations.extend(self._check_net_raw_capability(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.2.8 - Minimize the admission of containers with added capabilities
        violations.extend(self._check_added_capabilities(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.2.9 - Minimize the admission of containers with capabilities assigned
        violations.extend(self._check_capabilities_not_dropped(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.3.1 - Ensure that the CNI in use supports Network Policies
        # This is checked at namespace level
        
        # CIS 5.3.2 - Ensure that all Namespaces have Network Policies defined
        # This is checked at namespace level
        
        # CIS 5.7.1 - Create administrative boundaries between resources using namespaces
        # This is an organizational control
        
        # CIS 5.7.2 - Ensure that the seccomp profile is set to docker/default in your pod definitions
        violations.extend(self._check_seccomp_profile(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.7.3 - Apply Security Context to Your Pods and Containers
        violations.extend(self._check_security_context(namespace, pod_name, container_name, container_spec, pod_spec))
        
        # CIS 5.7.4 - The default namespace should not be used
        violations.extend(self._check_default_namespace(namespace, pod_name, container_name))
        
        return violations
    
    def _check_secret_mounts(self, namespace: str, pod_name: str, container_name: str,
                           container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.1.4 - Minimize access to secrets"""
        violations = []
        
        if hasattr(pod_spec, 'volumes') and pod_spec.volumes:
            for volume in pod_spec.volumes:
                if hasattr(volume, 'secret') and volume.secret:
                    # Check if this secret mount is necessary
                    violations.append(CISViolation(
                        namespace=namespace,
                        pod=pod_name,
                        container=container_name,
                        control_id="5.1.4",
                        control_title="Minimize access to secrets",
                        severity="Medium",
                        description=f"Pod mounts secret volume '{volume.name}' which may provide unnecessary access to sensitive data",
                        remediation="Review if this secret mount is necessary and remove if not required. Use least privilege principle for secret access.",
                        level="L1"
                    ))
        
        return violations
    
    def _check_privileged_containers(self, namespace: str, pod_name: str, container_name: str,
                                   container_spec) -> List[CISViolation]:
        """CIS 5.2.1 - Minimize the admission of privileged containers"""
        violations = []
        
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'privileged') and
            container_spec.security_context.privileged):
            
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.1",
                control_title="Minimize the admission of privileged containers",
                severity="Critical",
                description="Container is running in privileged mode, which grants access to all host devices and bypasses security mechanisms",
                remediation="Remove 'privileged: true' from container security context. Run containers with minimal privileges required.",
                level="L1"
            ))
        
        return violations
    
    def _check_host_pid(self, namespace: str, pod_name: str, container_name: str,
                       pod_spec) -> List[CISViolation]:
        """CIS 5.2.2 - Minimize the admission of containers wishing to share the host process ID namespace"""
        violations = []
        
        if (hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'host_pid') and
            pod_spec.security_context.host_pid):
            
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.2",
                control_title="Minimize the admission of containers wishing to share the host process ID namespace",
                severity="High",
                description="Pod is sharing the host process ID namespace, which allows visibility into host processes",
                remediation="Remove 'hostPID: true' from pod security context unless absolutely necessary for the application function.",
                level="L1"
            ))
        
        return violations
    
    def _check_host_ipc(self, namespace: str, pod_name: str, container_name: str,
                       pod_spec) -> List[CISViolation]:
        """CIS 5.2.3 - Minimize the admission of containers wishing to share the host IPC namespace"""
        violations = []
        
        if (hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'host_ipc') and
            pod_spec.security_context.host_ipc):
            
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.3",
                control_title="Minimize the admission of containers wishing to share the host IPC namespace",
                severity="High",
                description="Pod is sharing the host IPC namespace, which allows access to host inter-process communication",
                remediation="Remove 'hostIPC: true' from pod security context unless required for specific application needs.",
                level="L1"
            ))
        
        return violations
    
    def _check_host_network(self, namespace: str, pod_name: str, container_name: str,
                           pod_spec) -> List[CISViolation]:
        """CIS 5.2.4 - Minimize the admission of containers wishing to share the host network namespace"""
        violations = []
        
        if (hasattr(pod_spec, 'host_network') and pod_spec.host_network):
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.4",
                control_title="Minimize the admission of containers wishing to share the host network namespace",
                severity="High",
                description="Pod is using the host network namespace, which provides access to the host's network interfaces",
                remediation="Remove 'hostNetwork: true' from pod specification. Use Kubernetes services and ingress for network access.",
                level="L1"
            ))
        
        return violations
    
    def _check_privilege_escalation(self, namespace: str, pod_name: str, container_name: str,
                                   container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.2.5 - Minimize the admission of containers with allowPrivilegeEscalation"""
        violations = []
        
        # Check container-level setting
        allow_privilege_escalation = None
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'allow_privilege_escalation')):
            allow_privilege_escalation = container_spec.security_context.allow_privilege_escalation
        
        # Check pod-level setting if not set at container level
        if (allow_privilege_escalation is None and
            hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'allow_privilege_escalation')):
            allow_privilege_escalation = pod_spec.security_context.allow_privilege_escalation
        
        # If not explicitly set to false, it defaults to true (which is a violation)
        if allow_privilege_escalation is None or allow_privilege_escalation:
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.5",
                control_title="Minimize the admission of containers with allowPrivilegeEscalation",
                severity="High",
                description="Container allows privilege escalation, which can be used to gain additional privileges",
                remediation="Set 'allowPrivilegeEscalation: false' in container security context.",
                level="L1"
            ))
        
        return violations
    
    def _check_net_raw_capability(self, namespace: str, pod_name: str, container_name: str,
                                 container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.2.7 - Minimize the admission of containers with the NET_RAW capability"""
        violations = []
        
        # Check container-level capabilities
        capabilities = None
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'capabilities')):
            capabilities = container_spec.security_context.capabilities
        
        # Check pod-level capabilities if not set at container level
        if (capabilities is None and
            hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'capabilities')):
            capabilities = pod_spec.security_context.capabilities
        
        if capabilities:
            # Check if NET_RAW is in added capabilities
            if (hasattr(capabilities, 'add') and capabilities.add and
                'NET_RAW' in capabilities.add):
                violations.append(CISViolation(
                    namespace=namespace,
                    pod=pod_name,
                    container=container_name,
                    control_id="5.2.7",
                    control_title="Minimize the admission of containers with the NET_RAW capability",
                    severity="Medium",
                    description="Container has NET_RAW capability, which allows raw socket access and network packet manipulation",
                    remediation="Remove NET_RAW from added capabilities unless specifically required for network operations.",
                    level="L1"
                ))
        
        return violations
    
    def _check_added_capabilities(self, namespace: str, pod_name: str, container_name: str,
                                 container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.2.8 - Minimize the admission of containers with added capabilities"""
        violations = []
        
        # Check container-level capabilities
        capabilities = None
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'capabilities')):
            capabilities = container_spec.security_context.capabilities
        
        # Check pod-level capabilities if not set at container level
        if (capabilities is None and
            hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'capabilities')):
            capabilities = pod_spec.security_context.capabilities
        
        if (capabilities and hasattr(capabilities, 'add') and capabilities.add):
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.8",
                control_title="Minimize the admission of containers with added capabilities",
                severity="Medium",
                description=f"Container has added capabilities: {', '.join(capabilities.add)}",
                remediation="Remove unnecessary capabilities from the container. Use principle of least privilege.",
                level="L1"
            ))
        
        return violations
    
    def _check_capabilities_not_dropped(self, namespace: str, pod_name: str, container_name: str,
                                       container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.2.9 - Minimize the admission of containers with capabilities assigned"""
        violations = []
        
        # Check container-level capabilities
        capabilities = None
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'capabilities')):
            capabilities = container_spec.security_context.capabilities
        
        # Check pod-level capabilities if not set at container level
        if (capabilities is None and
            hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'capabilities')):
            capabilities = pod_spec.security_context.capabilities
        
        # Check if ALL capabilities are dropped (recommended)
        if not capabilities or not hasattr(capabilities, 'drop') or not capabilities.drop:
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.9",
                control_title="Minimize the admission of containers with capabilities assigned",
                severity="Medium",
                description="Container does not drop all capabilities. Default capabilities may be unnecessary.",
                remediation="Add 'drop: [\"ALL\"]' to container capabilities and only add back required capabilities.",
                level="L1"
            ))
        elif 'ALL' not in capabilities.drop:
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.2.9",
                control_title="Minimize the admission of containers with capabilities assigned",
                severity="Low",
                description="Container does not drop ALL capabilities, which may leave unnecessary privileges",
                remediation="Consider dropping ALL capabilities first, then adding only required ones.",
                level="L2"
            ))
        
        return violations
    
    def _check_seccomp_profile(self, namespace: str, pod_name: str, container_name: str,
                              container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.7.2 - Ensure that the seccomp profile is set to docker/default in your pod definitions"""
        violations = []
        
        # Check container-level seccomp profile
        seccomp_profile = None
        if (hasattr(container_spec, 'security_context') and 
            container_spec.security_context and
            hasattr(container_spec.security_context, 'seccomp_profile')):
            seccomp_profile = container_spec.security_context.seccomp_profile
        
        # Check pod-level seccomp profile if not set at container level
        if (seccomp_profile is None and
            hasattr(pod_spec, 'security_context') and 
            pod_spec.security_context and
            hasattr(pod_spec.security_context, 'seccomp_profile')):
            seccomp_profile = pod_spec.security_context.seccomp_profile
        
        if not seccomp_profile:
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.7.2",
                control_title="Ensure that the seccomp profile is set to docker/default in your pod definitions",
                severity="Medium",
                description="No seccomp profile is set, which allows unrestricted system calls",
                remediation="Set seccomp profile to 'RuntimeDefault' or 'Localhost' with appropriate profile.",
                level="L1"
            ))
        
        return violations
    
    def _check_security_context(self, namespace: str, pod_name: str, container_name: str,
                               container_spec, pod_spec) -> List[CISViolation]:
        """CIS 5.7.3 - Apply Security Context to Your Pods and Containers"""
        violations = []
        
        # Check if security context is defined
        has_container_security_context = (hasattr(container_spec, 'security_context') and 
                                        container_spec.security_context)
        has_pod_security_context = (hasattr(pod_spec, 'security_context') and 
                                   pod_spec.security_context)
        
        if not has_container_security_context and not has_pod_security_context:
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.7.3",
                control_title="Apply Security Context to Your Pods and Containers",
                severity="High",
                description="No security context is defined for pod or container",
                remediation="Define security context with appropriate settings: runAsNonRoot, runAsUser, fsGroup, etc.",
                level="L1"
            ))
        
        return violations
    
    def _check_default_namespace(self, namespace: str, pod_name: str, container_name: str) -> List[CISViolation]:
        """CIS 5.7.4 - The default namespace should not be used"""
        violations = []
        
        if namespace == "default":
            violations.append(CISViolation(
                namespace=namespace,
                pod=pod_name,
                container=container_name,
                control_id="5.7.4",
                control_title="The default namespace should not be used",
                severity="Low",
                description="Pod is deployed in the default namespace, which is not recommended for production workloads",
                remediation="Create dedicated namespaces for different applications and environments instead of using 'default'.",
                level="L1"
            ))
        
        return violations
    
    async def check_network_policies(self, namespace: str) -> List[NetworkPolicyViolation]:
        """Check network policy compliance for namespace"""
        violations = []
        
        try:
            # Check if network policies exist in namespace
            loop = asyncio.get_event_loop()
            network_policies = await loop.run_in_executor(
                None, self.networking_client.list_namespaced_network_policy, namespace
            )
            
            if not network_policies.items:
                violations.append(NetworkPolicyViolation(
                    namespace=namespace,
                    control_id="5.3.2",
                    control_title="Ensure that all Namespaces have Network Policies defined",
                    severity="Medium",
                    description=f"Namespace '{namespace}' has no network policies defined, allowing unrestricted network access",
                    remediation="Create network policies to restrict ingress and egress traffic for pods in this namespace."
                ))
            
        except ApiException as e:
            if e.status != 403:  # Ignore permission denied errors
                logger.warning(f"Failed to check network policies for namespace {namespace}: {e}")
        
        return violations
    
    async def check_service_accounts(self, namespace: str) -> List[ServiceAccountViolation]:
        """Check service account compliance for namespace"""
        violations = []
        
        try:
            # Get all service accounts in namespace
            loop = asyncio.get_event_loop()
            service_accounts = await loop.run_in_executor(
                None, self.k8s_client.list_namespaced_service_account, namespace
            )
            
            for sa in service_accounts.items:
                # Check if service account has automountServiceAccountToken disabled
                if (not hasattr(sa, 'automount_service_account_token') or 
                    sa.automount_service_account_token is None or
                    sa.automount_service_account_token):
                    
                    violations.append(ServiceAccountViolation(
                        namespace=namespace,
                        service_account=sa.metadata.name,
                        control_id="5.1.6",
                        control_title="Ensure that Service Account Tokens are only mounted where necessary",
                        severity="Medium",
                        description=f"Service account '{sa.metadata.name}' has automountServiceAccountToken enabled",
                        remediation="Set 'automountServiceAccountToken: false' unless the pod specifically needs Kubernetes API access."
                    ))
            
        except ApiException as e:
            if e.status != 403:  # Ignore permission denied errors
                logger.warning(f"Failed to check service accounts for namespace {namespace}: {e}")
        
        return violations