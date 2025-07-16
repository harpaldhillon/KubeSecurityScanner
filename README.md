# Kubernetes Security Scanner

A FastAPI-based application that scans Kubernetes clusters for security anti-patterns and CIS Kubernetes Benchmark compliance violations.

## Features

- **Latest Tag Detection**: Identifies containers using `:latest` image tags
- **Root User Detection**: Finds containers running as root user
- **CIS Compliance Checking**: Implements 13 key CIS Kubernetes Benchmark v1.9.0 controls
- **Network Policy Validation**: Checks for missing network policies
- **Service Account Security**: Validates service account configurations
- **Comprehensive Reporting**: Detailed violation reports with remediation guidance
- **Modern Web Interface**: Interactive dashboard for easy cluster security management

## Quick Start

1. **Install and Setup**
   ```bash
   ./local-setup.sh
   ```

2. **Run the Scanner**
   ```bash
   source venv/bin/activate
   python main.py
   ```

3. **Access Web Interface**
   Open your browser and go to: `http://localhost:5000`

## Requirements

- Python 3.8+
- Kubernetes cluster access (via kubeconfig or in-cluster configuration)
- Required Python packages (see `requirements-local.txt`)

## Local Installation

### 1. Clone and Setup

```bash
# Clone the repository (or download the files)
git clone https://github.com/harpaldhillon/KubeSecurityScanner.git
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

## User Interface

### Web Dashboard
The application includes a modern web interface that provides an intuitive way to interact with the security scanner:

1. **Access the Interface**: Open your browser and go to `http://localhost:5000`
2. **Health Check**: Click "Check Health" to verify cluster connectivity
3. **Security Scan**: Click "Start Scan" to perform a comprehensive security assessment
4. **View Results**: Results are displayed with:
   - Summary statistics dashboard
   - Expandable violation sections by type
   - Color-coded severity levels (Critical, High, Medium, Low)
   - Detailed remediation guidance
5. **CIS Controls**: Click "View CIS Controls" to see all supported benchmark controls

### Key Features
- **Real-time Status**: Live feedback during scan operations
- **Interactive Results**: Click to expand/collapse different violation types
- **Severity Indicators**: Visual severity badges for quick prioritization
- **Comprehensive Details**: Full violation descriptions with remediation steps
- **Mobile Responsive**: Works on desktop, tablet, and mobile devices

### Screenshot Guide
The interface includes:
- **Dashboard Cards**: Quick access to health check, scanning, and CIS controls
- **Summary Statistics**: Visual overview of scan results
- **Violation Details**: Organized by type with detailed information
- **Remediation Guidance**: Step-by-step instructions to fix issues

## API Endpoints

The application also provides REST API endpoints for programmatic access:

### Health Check
```bash
curl http://localhost:5000/api          # API health check
curl http://localhost:5000/health       # Detailed health check
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
# Mount your kubeconfig and access the web interface
docker run -p 5000:5000 \
  -v ~/.kube/config:/root/.kube/config:ro \
  k8s-security-scanner

# Then open http://localhost:5000 in your browser
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

# Get the external IP or use port-forwarding to access the web interface
kubectl get service security-scanner

# Or use port-forwarding for local access
kubectl port-forward service/security-scanner 5000:80

# Then open http://localhost:5000 in your browser
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
