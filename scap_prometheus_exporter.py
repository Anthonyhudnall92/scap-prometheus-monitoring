#!/usr/bin/env python3
"""
SCAP Prometheus Exporter
A comprehensive solution for exposing SCAP compliance metrics to Prometheus
"""

import xml.etree.ElementTree as ET
import json
import time
import logging
import argparse
import subprocess
import os
import tempfile
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from prometheus_client import CollectorRegistry, Gauge, Counter, Info, generate_latest
from prometheus_client.core import REGISTRY
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class SCAPResult:
    """Data class for SCAP scan results"""
    hostname: str
    profile: str
    scan_time: float
    total_rules: int
    passed_rules: int
    failed_rules: int
    error_rules: int
    unknown_rules: int
    notapplicable_rules: int
    notchecked_rules: int
    informational_rules: int
    compliance_score: float
    severity_high_failed: int
    severity_medium_failed: int
    severity_low_failed: int
    severity_info_failed: int
    benchmark_id: str
    benchmark_version: str
    rule_details: List[Dict]

class SCAPParser:
    """Parser for SCAP XML results"""
    
    def __init__(self):
        self.namespaces = {
            'xccdf': 'http://checklists.nist.gov/xccdf/1.2',
            'oval-res': 'http://oval.mitre.org/XMLSchema/oval-results-5',
            'cpe': 'http://cpe.mitre.org/language/2.0'
        }
    
    def parse_results(self, xml_file: str, hostname: str = None) -> Optional[SCAPResult]:
        """Parse SCAP XML results file"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            # Extract basic info
            benchmark = root.find('.//xccdf:Benchmark', self.namespaces)
            if benchmark is None:
                logger.error("No benchmark found in SCAP results")
                return None
            
            benchmark_id = benchmark.get('id', 'unknown')
            benchmark_version = benchmark.get('version', 'unknown')
            
            # Get profile info - check if root is TestResult or find it
            if root.tag == '{http://checklists.nist.gov/xccdf/1.2}TestResult':
                test_result = root
            else:
                test_result = root.find('.//xccdf:TestResult', self.namespaces)
                if test_result is None:
                    logger.error("No test results found in SCAP results")
                    return None
            
            profile_elem = test_result.find('xccdf:profile', self.namespaces)
            profile = profile_elem.get('idref', 'unknown') if profile_elem is not None else 'unknown'
            
            # Get target info
            target_elem = test_result.find('xccdf:target', self.namespaces)
            target_hostname = target_elem.text if target_elem is not None else hostname or 'unknown'
            
            # Get scan time
            start_time_elem = test_result.find('xccdf:start-time', self.namespaces)
            scan_time = time.time()  # Default to now
            if start_time_elem is not None:
                try:
                    scan_time = datetime.fromisoformat(start_time_elem.text.replace('Z', '+00:00')).timestamp()
                except:
                    pass
            
            # Initialize counters
            metrics = {
                'total_rules': 0,
                'passed_rules': 0,
                'failed_rules': 0,
                'error_rules': 0,
                'unknown_rules': 0,
                'notapplicable_rules': 0,
                'notchecked_rules': 0,
                'informational_rules': 0,
                'severity_high_failed': 0,
                'severity_medium_failed': 0,
                'severity_low_failed': 0,
                'severity_info_failed': 0
            }
            
            rule_details = []
            
            # Process rule results
            for rule_result in test_result.findall('xccdf:rule-result', self.namespaces):
                rule_id = rule_result.get('idref', '')
                metrics['total_rules'] += 1
                
                # Get result status
                result_elem = rule_result.find('xccdf:result', self.namespaces)
                if result_elem is None:
                    continue
                
                result_status = result_elem.text.lower()
                
                # Count by status - map result status to metric key
                status_mapping = {
                    'pass': 'passed_rules',
                    'fail': 'failed_rules', 
                    'error': 'error_rules',
                    'unknown': 'unknown_rules',
                    'notapplicable': 'notapplicable_rules',
                    'notchecked': 'notchecked_rules',
                    'informational': 'informational_rules'
                }
                
                if result_status in status_mapping:
                    metrics[status_mapping[result_status]] += 1
                
                # Get rule definition for severity
                rule_def = benchmark.find(f'.//xccdf:Rule[@id="{rule_id}"]', self.namespaces)
                severity = 'unknown'
                rule_title = rule_id
                
                if rule_def is not None:
                    severity = rule_def.get('severity', 'unknown').lower()
                    title_elem = rule_def.find('xccdf:title', self.namespaces)
                    if title_elem is not None:
                        rule_title = title_elem.text or rule_id
                
                # Count failed rules by severity
                if result_status == 'fail':
                    severity_key = f'severity_{severity}_failed'
                    if severity_key in metrics:
                        metrics[severity_key] += 1
                
                # Store rule details
                rule_details.append({
                    'rule_id': rule_id,
                    'title': rule_title,
                    'result': result_status,
                    'severity': severity
                })
            
            # Calculate compliance score
            compliance_score = 0.0
            if metrics['total_rules'] > 0:
                # Compliance = passed / (total - notapplicable - notchecked)
                applicable_rules = metrics['total_rules'] - metrics['notapplicable_rules'] - metrics['notchecked_rules']
                if applicable_rules > 0:
                    compliance_score = (metrics['passed_rules'] / applicable_rules) * 100
            
            return SCAPResult(
                hostname=target_hostname,
                profile=profile,
                scan_time=scan_time,
                compliance_score=compliance_score,
                benchmark_id=benchmark_id,
                benchmark_version=benchmark_version,
                rule_details=rule_details,
                **metrics
            )
            
        except Exception as e:
            logger.error(f"Error parsing SCAP results: {e}")
            return None

class SCAPScanner:
    """SCAP scanner wrapper"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.oscap_binary = config.get('oscap_binary', 'oscap')
        self.content_dir = config.get('content_dir', '/usr/share/xml/scap/ssg/content')
        
    def scan(self, profile: str, content_file: str = None, target: str = None) -> Optional[str]:
        """Run SCAP scan and return results file path"""
        try:
            # Create temporary results file
            results_fd, results_file = tempfile.mkstemp(suffix='.xml', prefix='scap_results_')
            os.close(results_fd)
            
            # Determine content file
            if not content_file:
                # Try to find appropriate content file
                content_files = list(Path(self.content_dir).glob('ssg-*.xml'))
                if not content_files:
                    logger.error(f"No SCAP content files found in {self.content_dir}")
                    return None
                content_file = str(content_files[0])
            
            # Build oscap command
            cmd = [
                self.oscap_binary,
                'xccdf', 'eval',
                '--profile', profile,
                '--results', results_file
            ]
            
            # Add target if specified (for remote scanning)
            if target:
                cmd.extend(['--target', target])
            
            cmd.append(content_file)
            
            logger.info(f"Running SCAP scan: {' '.join(cmd)}")
            
            # Run scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # SCAP scans return non-zero exit codes for failed rules, which is normal
            if result.returncode > 2:  # Only worry about serious errors
                logger.error(f"SCAP scan failed: {result.stderr}")
                os.unlink(results_file)
                return None
            
            if result.stderr:
                logger.warning(f"SCAP scan warnings: {result.stderr}")
            
            return results_file
            
        except subprocess.TimeoutExpired:
            logger.error("SCAP scan timed out")
            return None
        except Exception as e:
            logger.error(f"Error running SCAP scan: {e}")
            return None

class PrometheusExporter:
    """Prometheus metrics exporter for SCAP results"""
    
    def __init__(self, registry: CollectorRegistry = None):
        self.registry = registry or REGISTRY
        self._setup_metrics()
        self.latest_results: Dict[str, SCAPResult] = {}
        
    def _setup_metrics(self):
        """Setup Prometheus metrics"""
        self.compliance_score = Gauge(
            'scap_compliance_score_percent',
            'SCAP compliance score percentage',
            ['hostname', 'profile', 'benchmark'],
            registry=self.registry
        )
        
        self.total_rules = Gauge(
            'scap_total_rules',
            'Total number of SCAP rules evaluated',
            ['hostname', 'profile', 'benchmark'],
            registry=self.registry
        )
        
        self.rules_by_status = Gauge(
            'scap_rules_by_status',
            'Number of SCAP rules by status',
            ['hostname', 'profile', 'benchmark', 'status'],
            registry=self.registry
        )
        
        self.failed_by_severity = Gauge(
            'scap_failed_rules_by_severity',
            'Number of failed SCAP rules by severity',
            ['hostname', 'profile', 'benchmark', 'severity'],
            registry=self.registry
        )
        
        self.last_scan_timestamp = Gauge(
            'scap_last_scan_timestamp_seconds',
            'Timestamp of last SCAP scan',
            ['hostname', 'profile', 'benchmark'],
            registry=self.registry
        )
        
        self.scan_info = Info(
            'scap_scan',
            'Information about SCAP scan',
            ['hostname', 'profile'],
            registry=self.registry
        )
    
    def update_metrics(self, result: SCAPResult):
        """Update Prometheus metrics with SCAP results"""
        labels = [result.hostname, result.profile, result.benchmark_id]
        
        # Update main metrics
        self.compliance_score.labels(*labels).set(result.compliance_score)
        self.total_rules.labels(*labels).set(result.total_rules)
        self.last_scan_timestamp.labels(*labels).set(result.scan_time)
        
        # Update rules by status
        status_metrics = {
            'passed': result.passed_rules,
            'failed': result.failed_rules,
            'error': result.error_rules,
            'unknown': result.unknown_rules,
            'notapplicable': result.notapplicable_rules,
            'notchecked': result.notchecked_rules,
            'informational': result.informational_rules
        }
        
        for status, count in status_metrics.items():
            self.rules_by_status.labels(*labels, status).set(count)
        
        # Update failed rules by severity
        severity_metrics = {
            'high': result.severity_high_failed,
            'medium': result.severity_medium_failed,
            'low': result.severity_low_failed,
            'info': result.severity_info_failed
        }
        
        for severity, count in severity_metrics.items():
            self.failed_by_severity.labels(*labels, severity).set(count)
        
        # Update scan info
        self.scan_info.labels(result.hostname, result.profile).info({
            'benchmark_id': result.benchmark_id,
            'benchmark_version': result.benchmark_version,
            'scan_time': datetime.fromtimestamp(result.scan_time).isoformat()
        })
        
        # Store result
        key = f"{result.hostname}_{result.profile}"
        self.latest_results[key] = result
        
        logger.info(f"Updated metrics for {result.hostname} ({result.profile}): "
                   f"{result.compliance_score:.1f}% compliance")

class MetricsHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus metrics endpoint"""
    
    def __init__(self, exporter: PrometheusExporter, *args, **kwargs):
        self.exporter = exporter
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        if self.path == '/metrics':
            try:
                metrics_output = generate_latest(self.exporter.registry)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(metrics_output)
            except Exception as e:
                logger.error(f"Error generating metrics: {e}")
                self.send_error(500)
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        elif self.path == '/results':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            results_json = {
                key: asdict(result) for key, result in self.exporter.latest_results.items()
            }
            self.wfile.write(json.dumps(results_json, indent=2).encode())
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        # Suppress default HTTP logging
        pass

class SCAPExporterDaemon:
    """Main SCAP exporter daemon"""
    
    def __init__(self, config_file: str):
        self.config = self._load_config(config_file)
        self.parser = SCAPParser()
        self.scanner = SCAPScanner(self.config.get('scanner', {}))
        self.exporter = PrometheusExporter()
        self.running = False
        
    def _load_config(self, config_file: str) -> Dict:
        """Load configuration from YAML file"""
        try:
            with open(config_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}
    
    def scan_and_update(self, profile: str, content_file: str = None):
        """Run scan and update metrics"""
        try:
            logger.info(f"Starting SCAP scan with profile: {profile}")
            
            # Run scan
            results_file = self.scanner.scan(profile, content_file)
            if not results_file:
                logger.error("SCAP scan failed")
                return
            
            # Parse results
            hostname = self.config.get('hostname', os.uname().nodename)
            result = self.parser.parse_results(results_file, hostname)
            
            # Cleanup temporary file
            os.unlink(results_file)
            
            if not result:
                logger.error("Failed to parse SCAP results")
                return
            
            # Update metrics
            self.exporter.update_metrics(result)
            
        except Exception as e:
            logger.error(f"Error in scan_and_update: {e}")
    
    def start_http_server(self, port: int = 9154):
        """Start HTTP server for metrics"""
        def handler_factory(*args, **kwargs):
            return MetricsHTTPHandler(self.exporter, *args, **kwargs)
        
        server = HTTPServer(('', port), handler_factory)
        logger.info(f"Starting HTTP server on port {port}")
        
        def serve():
            while self.running:
                server.handle_request()
        
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        return server
    
    def run(self):
        """Main run loop"""
        self.running = True
        
        # Start HTTP server
        port = self.config.get('http_port', 9154)
        server = self.start_http_server(port)
        
        # Get scan configuration
        scans = self.config.get('scans', [])
        if not scans:
            logger.warning("No scans configured")
            return
        
        try:
            while self.running:
                for scan_config in scans:
                    profile = scan_config.get('profile')
                    content_file = scan_config.get('content_file')
                    interval = scan_config.get('interval', 3600)  # Default 1 hour
                    
                    if not profile:
                        logger.warning("Scan configuration missing profile")
                        continue
                    
                    self.scan_and_update(profile, content_file)
                    
                    if not self.running:
                        break
                    
                    logger.info(f"Sleeping for {interval} seconds until next scan")
                    time.sleep(interval)
                    
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        finally:
            self.running = False
            server.server_close()

def main():
    parser = argparse.ArgumentParser(description='SCAP Prometheus Exporter')
    parser.add_argument('--config', '-c', default='scap_exporter.yaml',
                       help='Configuration file path')
    parser.add_argument('--scan-once', action='store_true',
                       help='Run single scan and exit')
    parser.add_argument('--profile', help='SCAP profile for single scan')
    parser.add_argument('--content-file', help='SCAP content file')
    parser.add_argument('--results-file', help='Parse existing results file')
    
    args = parser.parse_args()
    
    if args.results_file:
        # Parse existing results file
        parser_obj = SCAPParser()
        exporter = PrometheusExporter()
        
        result = parser_obj.parse_results(args.results_file)
        if result:
            exporter.update_metrics(result)
            print(generate_latest(exporter.registry).decode())
        return
    
    # Initialize daemon
    daemon = SCAPExporterDaemon(args.config)
    
    if args.scan_once:
        # Run single scan
        profile = args.profile or daemon.config.get('scans', [{}])[0].get('profile')
        if not profile:
            logger.error("No profile specified for single scan")
            return
        
        daemon.scan_and_update(profile, args.content_file)
        print(generate_latest(daemon.exporter.registry).decode())
    else:
        # Run as daemon
        daemon.run()

if __name__ == '__main__':
    main()

