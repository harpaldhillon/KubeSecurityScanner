# Kubernetes Security Scanner

A FastAPI-based application that scans Kubernetes clusters for security anti-patterns and CIS Kubernetes Benchmark compliance violations.

## Features

- **Latest Tag Detection**: Identifies containers using `:latest` image tags
- **Root User Detection**: Finds containers running as root user
- **CIS Compliance Checking**: Implements 13 key CIS Kubernetes Benchmark v1.9.0 controls
- **Network Policy Validation**: Checks for missing network policies
- **Service Account Security**: Validates service account configurations
- **Comprehensive Reporting**: Detailed violation reports with remediation guidance

## Requirements

- Python 3.8+
- Kubernetes cluster access (via kubeconfig or in-cluster configuration)
- Required Python packages (see `requirements.txt`)

## Local Installation

### 1. Clone and Setup

```bash
# Clone the repository (or download the files)
git clone [<repository-url>](https://github.com/harpaldhillon/KubeSecurityScanner.git)
cd kubernetes-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Kubernetes Configuration

The scanner supports two authentication methods:

#### Option A: Kubeconfig (Recommended for local development)
```bash
# Ensure your kubeconfig is properly configured
kubectl config current-context
kubectl get nodes  # Test connectivity
```

#### Option B: In-Cluster Configuration
This is automatically used when running inside a Kubernetes pod.

### 3. Running the Application

```bash
# Start the scanner
python main.py
```

The application will start on `http://localhost:5000`

## API Endpoints

### Health Check
```bash
curl http://localhost:5000/
curl http://localhost:5000/health
```

### Security Scan
```bash
curl http://localhost:5000/scan
```

### CIS Controls Information
```bash
curl http://localhost:5000/cis-controls
```

## Docker Deployment

### Build Docker Image
```bash
docker build -t k8s-security-scanner .
```

### Run with Docker
```bash
# Mount your kubeconfig
docker run -p 5000:5000 \
  -v ~/.kube/config:/root/.kube/config:ro \
  k8s-security-scanner
```

## Kubernetes Deployment

### Prerequisites
Create necessary RBAC permissions:

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-scanner
  namespace: default

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-scanner
rules:
- apiGroups: [""]
  resources: ["pods", "namespaces", "serviceaccounts"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-scanner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: security-scanner
subjects:
- kind: ServiceAccount
  name: security-scanner
  namespace: default
```

### Deploy the Scanner
```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: security-scanner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: security-scanner
  template:
    metadata:
      labels:
        app: security-scanner
    spec:
      serviceAccountName: security-scanner
      containers:
      - name: scanner
        image: k8s-security-scanner:latest
        ports:
        - containerPort: 5000
        env:
        - name: PYTHONUNBUFFERED
          value: "1"

---
apiVersion: v1
kind: Service
metadata:
  name: security-scanner
spec:
  selector:
    app: security-scanner
  ports:
  - port: 80
    targetPort: 5000
  type: LoadBalancer
```

Apply the configurations:
```bash
kubectl apply -f rbac.yaml
kubectl apply -f deployment.yaml
```

## Configuration

### Environment Variables
- `KUBECONFIG`: Path to kubeconfig file (default: `~/.kube/config`)
- `PYTHONUNBUFFERED`: Set to `1` for immediate log output

### Logging
The application uses Python's built-in logging with INFO level by default. Logs include:
- Kubernetes client initialization
- Scan progress and results
- Error handling and troubleshooting information

## Troubleshooting

### Common Issues

1. **"Unable to load Kubernetes configuration"**
   - Ensure your kubeconfig is valid: `kubectl config view`
   - Check cluster connectivity: `kubectl get nodes`
   - Verify the kubeconfig path is correct

2. **"Permission denied" errors**
   - Check RBAC permissions for the service account
   - Ensure the scanner has read access to pods, namespaces, and network policies

3. **"Connection refused"**
   - Verify the Kubernetes API server is accessible
   - Check network connectivity to the cluster

### Debugging
Enable debug logging by modifying the log level in `main.py`:
```python
logging.basicConfig(level=logging.DEBUG)
```

## CIS Compliance Controls

The scanner implements the following CIS Kubernetes Benchmark v1.9.0 controls:

### Level 1 (L1) Controls
- **5.1.4**: Minimize access to secrets
- **5.2.1**: Minimize privileged containers
- **5.2.2**: Minimize host PID namespace sharing
- **5.2.3**: Minimize host IPC namespace sharing
- **5.2.4**: Minimize host network namespace sharing
- **5.2.5**: Minimize privilege escalation
- **5.2.7**: Minimize NET_RAW capability
- **5.2.8**: Minimize added capabilities
- **5.2.9**: Minimize assigned capabilities
- **5.3.2**: Ensure network policies exist
- **5.7.2**: Ensure seccomp profiles are set
- **5.7.3**: Apply security contexts
- **5.7.4**: Avoid default namespace

### Additional Security Checks
- Container image tag validation (`:latest` detection)
- Root user detection
- Service account token mounting validation

## Sample Output

```json
{
  "latestTagContainers": [
    {
      "namespace": "default",
      "pod": "nginx-pod",
      "container": "nginx",
      "image": "nginx:latest"
    }
  ],
  "rootContainers": [
    {
      "namespace": "default",
      "pod": "nginx-pod",
      "container": "nginx",
      "reason": "No security context defined (defaults to root)",
      "user_id": null,
      "run_as_non_root": null
    }
  ],
  "cisViolations": [
    {
      "namespace": "default",
      "pod": "nginx-pod",
      "container": "nginx",
      "control_id": "5.7.3",
      "control_title": "Apply Security Context to Your Pods and Containers",
      "severity": "High",
      "description": "No security context is defined for pod or container",
      "remediation": "Define security context with appropriate settings: runAsNonRoot, runAsUser, fsGroup, etc.",
      "level": "L1"
    }
  ],
  "networkPolicyViolations": [],
  "serviceAccountViolations": [],
  "summary": {
    "namespacesScanned": 3,
    "latestTagIssues": 1,
    "rootUserIssues": 1,
    "cisViolations": 1,
    "networkPolicyViolations": 0,
    "serviceAccountViolations": 0,
    "totalIssues": 3
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License.
