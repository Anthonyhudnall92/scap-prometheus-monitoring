#!/usr/bin/env python3
"""
Test script for SCAP Prometheus Exporter
"""

import xml.etree.ElementTree as ET
import tempfile
import os
import subprocess
import sys
from datetime import datetime

def create_sample_scap_results():
    """Create a sample SCAP results XML for testing"""
    
    sample_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<xccdf:TestResult xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                  id="xccdf_org.open-scap_testresult_standard">
    <xccdf:benchmark href="/usr/share/xml/scap/ssg/content/ssg-test-ds.xml">
        <xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" 
                         id="xccdf_org.ssgproject.content_benchmark_DEBIAN"
                         version="1.0">
            <!-- Rule definitions with severity -->
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs" severity="medium">
                <xccdf:title>Set Password Minimum Length</xccdf:title>
            </xccdf:Rule>
            
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions" severity="high">
                <xccdf:title>Limit Concurrent Login Sessions</xccdf:title>
            </xccdf:Rule>
            
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_service_ssh_disabled" severity="low">
                <xccdf:title>Disable SSH Service</xccdf:title>
            </xccdf:Rule>
            
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_bootloader_password" severity="medium">
                <xccdf:title>Set Boot Loader Password</xccdf:title>
            </xccdf:Rule>
            
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_package_sudo_installed" severity="info">
                <xccdf:title>Install sudo Package</xccdf:title>
            </xccdf:Rule>
        </xccdf:Benchmark>
    </xccdf:benchmark>
    
    <xccdf:profile idref="xccdf_org.ssgproject.content_profile_cis"/>
    <xccdf:target>test-server</xccdf:target>
    <xccdf:start-time>2024-01-01T12:00:00Z</xccdf:start-time>
    
    <!-- Passed rule -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_accounts_password_minlen_login_defs">
        <xccdf:result>pass</xccdf:result>
    </xccdf:rule-result>
    
    <!-- Failed rules with different severities -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_accounts_max_concurrent_login_sessions">
        <xccdf:result>fail</xccdf:result>
    </xccdf:rule-result>
    
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_service_ssh_disabled">
        <xccdf:result>fail</xccdf:result>
    </xccdf:rule-result>
    
    <!-- Not applicable rule -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_bootloader_password">
        <xccdf:result>notapplicable</xccdf:result>
    </xccdf:rule-result>
    
    <!-- Error rule -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_package_sudo_installed">
        <xccdf:result>error</xccdf:result>
    </xccdf:rule-result>
</xccdf:TestResult>'''
    
    # Create temporary file
    fd, temp_file = tempfile.mkstemp(suffix='.xml', prefix='test_scap_results_')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(sample_xml)
        return temp_file
    except:
        os.close(fd)
        raise

def test_parser():
    """Test the SCAP parser functionality"""
    print("Testing SCAP parser...")
    
    try:
        from scap_prometheus_exporter import SCAPParser
        
        # Create sample results file
        results_file = create_sample_scap_results()
        
        # Test parsing
        parser = SCAPParser()
        result = parser.parse_results(results_file, "test-server")
        
        # Cleanup
        os.unlink(results_file)
        
        if result:
            print(f"✅ Parser test passed!")
            print(f"   Hostname: {result.hostname}")
            print(f"   Profile: {result.profile}")
            print(f"   Total rules: {result.total_rules}")
            print(f"   Passed: {result.passed_rules}")
            print(f"   Failed: {result.failed_rules}")
            print(f"   Error: {result.error_rules}")
            print(f"   Not applicable: {result.notapplicable_rules}")
            print(f"   Compliance score: {result.compliance_score:.1f}%")
            return True
        else:
            print("❌ Parser test failed - no result returned")
            return False
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Parser test failed: {e}")
        return False

def test_prometheus_export():
    """Test Prometheus metrics export"""
    print("Testing Prometheus export...")
    
    try:
        from scap_prometheus_exporter import SCAPParser, PrometheusExporter
        from prometheus_client import generate_latest
        
        # Create sample results and parse
        results_file = create_sample_scap_results()
        parser = SCAPParser()
        result = parser.parse_results(results_file, "test-server")
        os.unlink(results_file)
        
        if not result:
            print("❌ No result to export")
            return False
        
        # Create exporter and update metrics
        exporter = PrometheusExporter()
        exporter.update_metrics(result)
        
        # Generate metrics output
        metrics_output = generate_latest(exporter.registry).decode()
        
        # Check for expected metrics
        expected_metrics = [
            'scap_compliance_score_percent',
            'scap_total_rules',
            'scap_rules_by_status',
            'scap_failed_rules_by_severity'
        ]
        
        missing_metrics = []
        for metric in expected_metrics:
            if metric not in metrics_output:
                missing_metrics.append(metric)
        
        if missing_metrics:
            print(f"❌ Missing metrics: {missing_metrics}")
            return False
        
        print("✅ Prometheus export test passed!")
        print(f"   Generated {len(metrics_output.splitlines())} lines of metrics")
        return True
        
    except Exception as e:
        print(f"❌ Prometheus export test failed: {e}")
        return False

def test_http_server():
    """Test HTTP server functionality"""
    print("Testing HTTP server...")
    
    try:
        import threading
        import time
        import requests
        from scap_prometheus_exporter import PrometheusExporter, MetricsHTTPHandler
        from http.server import HTTPServer
        from prometheus_client import CollectorRegistry
        
        # Create separate registry to avoid conflicts
        registry = CollectorRegistry()
        exporter = PrometheusExporter(registry)
        
        # Start simple HTTP server for test
        def handler_factory(*args, **kwargs):
            return MetricsHTTPHandler(exporter, *args, **kwargs)
        
        server = HTTPServer(('', 9156), handler_factory)
        
        def serve():
            server.timeout = 0.1  # Short timeout to allow shutdown
            while True:
                try:
                    server.handle_request()
                except:
                    break
        
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        
        # Give server time to start
        time.sleep(0.5)
        
        # Test endpoints
        try:
            health_response = requests.get('http://localhost:9156/health', timeout=5)
            metrics_response = requests.get('http://localhost:9156/metrics', timeout=5)
            
            if health_response.status_code == 200 and metrics_response.status_code == 200:
                print("✅ HTTP server test passed!")
                print(f"   Health endpoint: {health_response.status_code}")
                print(f"   Metrics endpoint: {metrics_response.status_code}")
                success = True
            else:
                print(f"❌ HTTP server test failed - status codes: {health_response.status_code}, {metrics_response.status_code}")
                success = False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ HTTP server test failed - request error: {e}")
            success = False
        
        # Cleanup
        server.server_close()
        
        return success
            
    except Exception as e:
        print(f"❌ HTTP server test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("SCAP Prometheus Exporter Test Suite")
    print("====================================")
    
    tests = [
        test_parser,
        test_prometheus_export,
        test_http_server
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
        print()
    
    print("Test Summary")
    print("============")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Total:  {passed + failed}")
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        sys.exit(1)
    else:
        print("\n✅ All tests passed!")
        sys.exit(0)

if __name__ == '__main__':
    main()
