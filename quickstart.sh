#!/bin/bash
set -e

echo "SCAP-to-Prometheus Quick Start"
echo "==============================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function info() {
    echo -e "${BLUE}INFO:${NC} $1"
}

function success() {
    echo -e "${GREEN}SUCCESS:${NC} $1"
}

function warning() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

function error() {
    echo -e "${RED}ERROR:${NC} $1"
}

# Check if we're in the right directory
if [[ ! -f "scap_prometheus_exporter.py" ]]; then
    error "Please run this script from the scap_scan_development directory"
    exit 1
fi

# Function to check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed. Please install Python 3 first."
        exit 1
    fi
    
    success "All prerequisites are available"
}

# Function to setup Python environment
setup_python() {
    info "Setting up Python virtual environment..."
    
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    pip install -r requirements.txt
    success "Python environment ready"
}

# Function to run tests
run_tests() {
    info "Running test suite..."
    source venv/bin/activate
    python3 test_exporter.py
    success "All tests passed!"
}

# Function to build Docker image
build_image() {
    info "Building Docker image..."
    docker build -t scap-prometheus-exporter .
    success "Docker image built successfully"
}

# Function to start monitoring stack
start_stack() {
    info "Starting monitoring stack..."
    docker-compose up -d
    
    # Wait for services to be ready
    info "Waiting for services to start..."
    sleep 10
    
    # Check if services are running
    if docker-compose ps | grep -q "Up"; then
        success "Monitoring stack is running!"
        echo ""
        echo "Access URLs:"
        echo "  • Grafana:       http://localhost:3000 (admin/scap_admin_2024)"
        echo "  • Prometheus:    http://localhost:9090"
        echo "  • Alertmanager:  http://localhost:9093"
        echo "  • SCAP Exporter: http://localhost:9154/metrics"
        echo ""
        echo "To view logs: make logs"
        echo "To stop:      make down"
    else
        error "Some services failed to start. Check logs with: make logs"
        exit 1
    fi
}

# Function to show help
show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  setup     - Install dependencies and setup environment"
    echo "  test      - Run the test suite"
    echo "  build     - Build Docker image"
    echo "  start     - Start the monitoring stack"
    echo "  all       - Run setup, test, build, and start (full deployment)"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 all        # Full deployment"
    echo "  $0 setup      # Just setup environment"
    echo "  $0 test       # Run tests only"
}

# Main logic
case "${1:-help}" in
    "setup")
        check_prerequisites
        setup_python
        ;;
    "test")
        setup_python
        run_tests
        ;;
    "build")
        build_image
        ;;
    "start")
        start_stack
        ;;
    "all")
        check_prerequisites
        setup_python
        run_tests
        build_image
        start_stack
        ;;
    "help"|*)
        show_help
        ;;
esac
