#!/usr/bin/env python3
"""
Simple SCAP Metrics Server for Demonstration
Serves working SCAP metrics on port 9155
"""

import http.server
import socketserver
import sys
import os

# Add current directory to path to import our exporter
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scap_prometheus_exporter import SCAPParser, PrometheusExporter
from prometheus_client import generate_latest, CollectorRegistry

# Global exporter instance
exporter = None

class MetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/metrics':
            try:
                if exporter:
                    metrics_output = generate_latest(exporter.registry)
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; charset=utf-8')
                    self.end_headers()
                    self.wfile.write(metrics_output)
                else:
                    self.send_error(503, "Exporter not ready")
            except Exception as e:
                print(f"Error: {e}")
                self.send_error(500)
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy", "metrics": "available"}')
        else:
            self.send_error(404)
    
    def log_message(self, format, *args):
        pass  # Suppress logging

def main():
    global exporter
    
    print("🚀 Starting SCAP Metrics Server...")
    
    # Create exporter with separate registry
    registry = CollectorRegistry()
    exporter = PrometheusExporter(registry)
    
    # Parse sample data
    parser = SCAPParser()
    result = parser.parse_results('sample_scap_results.xml')
    
    if result:
        exporter.update_metrics(result)
        print(f"✅ Loaded SCAP data: {result.compliance_score:.1f}% compliance")
        print(f"   • {result.total_rules} total rules")
        print(f"   • {result.passed_rules} passed")
        print(f"   • {result.failed_rules} failed")
        print(f"   • {result.severity_high_failed} high severity failures")
    else:
        print("❌ Failed to load SCAP data")
        return
    
    # Start server
    port = 9155
    print(f"📊 SCAP metrics available at: http://localhost:{port}/metrics")
    print(f"🔍 Health check at: http://localhost:{port}/health")
    print("Press Ctrl+C to stop...")
    
    with socketserver.TCPServer(("", port), MetricsHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server stopped")

if __name__ == '__main__':
    main()
