# SCAP-to-Prometheus Exporter

A comprehensive solution for monitoring SCAP (Security Content Automation Protocol) compliance using Prometheus and Grafana.

## Overview

This project provides:
- **SCAP Prometheus Exporter**: Runs SCAP scans and exports metrics to Prometheus
- **Monitoring Stack**: Complete setup with Prometheus, Grafana, and Alertmanager
- **Visualizations**: Pre-built Grafana dashboards for compliance monitoring
- **Alerting**: Configurable alerts for compliance violations

## Features

- ✅ Automated SCAP scanning with configurable profiles
- ✅ Comprehensive Prometheus metrics export
- ✅ Real-time compliance monitoring
- ✅ Grafana dashboards for visualization
- ✅ Alerting for compliance violations
- ✅ Docker containerization for easy deployment
- ✅ Support for multiple SCAP profiles and benchmarks

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   SCAP Scans    │───▶│ SCAP Exporter   │───▶│   Prometheus    │
│                 │    │                 │    │                 │
│ • CIS Benchmark │    │ • Parse Results │    │ • Store Metrics │
│ • STIG Profile  │    │ • Export Metrics│    │ • Run Queries   │
│ • Custom Checks │    │ • HTTP Endpoint │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Alertmanager   │◀───│    Grafana      │◀───│                 │
│                 │    │                 │    │                 │
│ • Send Alerts   │    │ • Dashboards    │    │                 │
│ • Notifications │    │ • Visualizations│    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.8+ (for local testing)
- OpenSCAP tools (for local scanning)

### 1. Clone and Setup

```bash
git clone <your-repo>
cd scap_scan_development

# Install dependencies
make install-deps

# Verify setup
make verify
```

### 2. Download SCAP Content

```bash
# Download sample SCAP content
make download-content
```

### 3. Configure

Edit `scap_exporter.yaml` to configure:
- Scan profiles
- Scan intervals
- SCAP content paths

### 4. Deploy

```bash
# Start the monitoring stack
make up

# Check logs
make logs
```

### 5. Access

- **Grafana**: http://localhost:3000 (admin/scap_admin_2024)
- **Prometheus**: http://localhost:9090
- **Alertmanager**: http://localhost:9093
- **SCAP Exporter**: http://localhost:9154/metrics

## Configuration

### SCAP Exporter Configuration (`scap_exporter.yaml`)

```yaml
# HTTP server settings
http_port: 9154
hostname: "server-01"

# Scanner configuration
scanner:
  oscap_binary: "oscap"
  content_dir: "/usr/share/xml/scap/ssg/content"

# Scan configurations
scans:
  - profile: "xccdf_org.ssgproject.content_profile_cis"
    content_file: "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml"
    interval: 3600  # 1 hour

  - profile: "xccdf_org.ssgproject.content_profile_standard"
    content_file: "/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml"
    interval: 7200  # 2 hours
```

### Available SCAP Profiles

Common profiles include:
- `xccdf_org.ssgproject.content_profile_cis` - CIS Benchmark
- `xccdf_org.ssgproject.content_profile_stig` - DISA STIG
- `xccdf_org.ssgproject.content_profile_pci-dss` - PCI-DSS
- `xccdf_org.ssgproject.content_profile_standard` - Standard hardening

List available profiles:
```bash
make list-profiles
```

## Metrics

The exporter provides these Prometheus metrics:

### Compliance Metrics
- `scap_compliance_score_percent` - Overall compliance percentage
- `scap_total_rules` - Total rules evaluated
- `scap_rules_by_status` - Rules count by status (passed, failed, etc.)
- `scap_failed_rules_by_severity` - Failed rules by severity level

### Operational Metrics
- `scap_last_scan_timestamp_seconds` - Timestamp of last scan
- `scap_scan_info` - Scan metadata (benchmark version, etc.)

All metrics include labels:
- `hostname` - Target hostname
- `profile` - SCAP profile used
- `benchmark` - Benchmark identifier

## Alerting

Pre-configured alerts include:

- **Low Compliance** - Compliance score < 80%
- **Critical Compliance** - Compliance score < 50%
- **High Severity Failures** - > 5 high-severity rule failures
- **Exporter Down** - SCAP exporter unavailable
- **Stale Scans** - No scan in > 2 hours

Configure notifications in `alertmanager/alertmanager.yml`.

## Usage Examples

### Run Single Scan

```bash
# Local scan
python3 scap_prometheus_exporter.py --config scap_exporter.yaml --scan-once --profile xccdf_org.ssgproject.content_profile_cis

# Parse existing results
python3 scap_prometheus_exporter.py --results-file /path/to/results.xml
```

### View Metrics

```bash
# Get metrics from running exporter
curl http://localhost:9154/metrics

# View scan results JSON
curl http://localhost:9154/results
```

### Docker Deployment

```bash
# Build and run
docker build -t scap-exporter .
docker run -p 9154:9154 -v $(pwd)/scap_exporter.yaml:/app/scap_exporter.yaml scap-exporter
```

## Development

### Project Structure

```
scap_scan_development/
├── scap_prometheus_exporter.py    # Main exporter code
├── scap_exporter.yaml            # Configuration
├── requirements.txt               # Python dependencies
├── Dockerfile                     # Container definition
├── docker-compose.yml            # Full stack
├── Makefile                      # Development tasks
├── prometheus/
│   ├── prometheus.yml            # Prometheus config
│   └── rules/
│       └── scap_alerts.yml       # Alert rules
├── grafana/
│   ├── provisioning/             # Auto-provisioning
│   └── dashboards/               # Dashboard definitions
└── alertmanager/
    └── alertmanager.yml          # Alert routing
```

### Adding New Metrics

1. Modify the `PrometheusExporter` class in `scap_prometheus_exporter.py`
2. Add metric definitions in `_setup_metrics()`
3. Update metrics in `update_metrics()`
4. Test locally with `make test`

### Custom Dashboards

1. Create dashboards in Grafana UI
2. Export JSON from Grafana
3. Save in `grafana/dashboards/`
4. Restart stack with `make down && make up`

## Troubleshooting

### Common Issues

**SCAP scan fails:**
- Check if OpenSCAP tools are installed: `oscap --version`
- Verify SCAP content file exists and is readable
- Check profile name matches content file

**No metrics appearing:**
- Check exporter logs: `docker-compose logs scap-exporter`
- Verify Prometheus is scraping: http://localhost:9090/targets
- Check metric endpoint: http://localhost:9154/metrics

**Grafana shows no data:**
- Verify Prometheus datasource connection
- Check time range in dashboards
- Confirm metrics exist in Prometheus: http://localhost:9090/graph

### Logs and Debugging

```bash
# View all logs
make logs

# View specific service logs
docker-compose logs scap-exporter
docker-compose logs prometheus
docker-compose logs grafana

# Debug single scan
python3 scap_prometheus_exporter.py --config scap_exporter.yaml --scan-once
```

## Security Considerations

- Run containers as non-root users (configured in Dockerfile)
- Secure Grafana admin password (change default in docker-compose.yml)
- Network isolation using Docker networks
- Readonly volume mounts where possible
- Regular updates of base images and dependencies

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Review logs for error messages
3. Open an issue with relevant details
