.PHONY: help build run test clean up down logs

# Default target
help:
	@echo "Available targets:"
	@echo "  build       - Build the SCAP exporter Docker image"
	@echo "  run         - Run a single SCAP scan locally"
	@echo "  test        - Test the exporter with sample data"
	@echo "  up          - Start the monitoring stack"
	@echo "  down        - Stop the monitoring stack"
	@echo "  logs        - View logs from all services"
	@echo "  clean       - Clean up Docker images and containers"

# Build the SCAP exporter Docker image
build:
	docker build -t scap-prometheus-exporter .

# Run a single SCAP scan locally (requires local oscap installation)
run:
	python3 scap_prometheus_exporter.py --config scap_exporter.yaml --scan-once

# Test the exporter with comprehensive test suite
test:
	python3 test_exporter.py

# Test the exporter with an existing results file
test-file:
	@if [ -f "sample_results.xml" ]; then \
		python3 scap_prometheus_exporter.py --results-file sample_results.xml; \
	else \
		echo "No sample_results.xml found. Run 'make run' first or provide a SCAP results file."; \
	fi

# Start the full monitoring stack
up:
	docker-compose up -d

# Stop the monitoring stack
down:
	docker-compose down

# View logs from all services
logs:
	docker-compose logs -f

# Clean up Docker resources
clean:
	docker-compose down -v
	docker image prune -f
	docker container prune -f

# Install Python dependencies locally
install-deps:
	pip3 install -r requirements.txt

# Check available SCAP profiles (requires local oscap)
list-profiles:
	@echo "Available SCAP profiles:"
	@if command -v oscap >/dev/null 2>&1; then \
		find /usr/share/xml/scap/ssg/content -name "*.xml" -exec oscap info {} \; 2>/dev/null | grep "Profile" || echo "No profiles found"; \
	else \
		echo "oscap command not found. Install openscap-utils package."; \
	fi

# Download sample SCAP content
download-content:
	mkdir -p scap-content
	wget -O scap-content/ssg-debian11-ds.xml https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-debian11-ds.xml
	wget -O scap-content/ssg-ubuntu2004-ds.xml https://github.com/ComplianceAsCode/content/releases/latest/download/ssg-ubuntu2004-ds.xml

# Verify the setup
verify:
	@echo "Checking Docker..."
	@docker --version
	@echo "Checking Docker Compose..."
	@docker-compose --version
	@echo "Checking Python dependencies..."
	@python3 -c "import prometheus_client, yaml; print('Python deps OK')"
	@echo "Setup verification complete!"
