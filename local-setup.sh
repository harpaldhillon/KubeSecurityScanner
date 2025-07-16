#!/bin/bash
# Local setup script for Kubernetes Security Scanner

echo "🔧 Setting up Kubernetes Security Scanner locally..."

# Check if Python 3.8+ is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed. Please install Python 3.8 or higher."
    exit 1
fi

# Check if kubectl is installed and configured
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is required but not installed. Please install kubectl and configure it to access your cluster."
    exit 1
fi

# Test kubectl connectivity
echo "🔍 Testing Kubernetes cluster connectivity..."
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Unable to connect to Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

echo "✅ Kubernetes cluster connectivity verified"

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install fastapi uvicorn kubernetes pydantic

echo "✅ Dependencies installed successfully"

# Create a simple test script
cat > test_connection.py << 'EOF'
#!/usr/bin/env python3
"""Test script to verify Kubernetes connectivity"""

import asyncio
from k8s_client import KubernetesClientManager

async def test_connection():
    try:
        client_manager = KubernetesClientManager()
        await client_manager.initialize()
        await client_manager.test_connectivity()
        print("✅ Kubernetes connection successful!")
        
        # Test basic API call
        client = client_manager.get_client()
        namespaces = client.list_namespace()
        print(f"✅ Found {len(namespaces.items)} namespaces")
        
        await client_manager.close()
        return True
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_connection())
    exit(0 if success else 1)
EOF

# Test the connection
echo "🔍 Testing application connectivity..."
python test_connection.py

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 Setup complete! You can now run the scanner:"
    echo ""
    echo "1. Activate the virtual environment:"
    echo "   source venv/bin/activate"
    echo ""
    echo "2. Start the scanner:"
    echo "   python main.py"
    echo ""
    echo "3. Access the Web Interface at: http://localhost:5000"
    echo ""
    echo "🌐 Web Interface Features:"
    echo "   - Interactive dashboard with health checks"
    echo "   - Real-time security scanning"
    echo "   - Detailed violation reports with remediation"
    echo "   - CIS controls reference"
    echo "   - Mobile-responsive design"
    echo ""
    echo "📡 API Endpoints:"
    echo "   - GET /api           - API health check"
    echo "   - GET /health        - Detailed health check"
    echo "   - GET /scan          - Perform security scan"
    echo "   - GET /cis-controls  - View CIS controls info"
else
    echo "❌ Setup failed. Please check the error messages above."
    exit 1
fi