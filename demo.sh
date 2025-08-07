#!/bin/bash

echo "SCAP-to-Prometheus Exporter Demo"
echo "================================="

# Check if we're in the right directory
if [[ ! -f "scap_prometheus_exporter.py" ]]; then
    echo "ERROR: Please run this script from the scap_scan_development directory"
    exit 1
fi

# Check if virtual environment exists
if [[ ! -d "venv" ]]; then
    echo "Setting up virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo ""
echo "1. Running comprehensive test suite..."
echo "======================================="
python3 test_exporter.py

echo ""
echo "2. Demonstrating single SCAP scan parsing..."
echo "============================================="

# Create a sample SCAP results file for demo
cat > demo_results.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<xccdf:TestResult xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2"
                  id="xccdf_org.open-scap_testresult_demo">
    <xccdf:benchmark href="/usr/share/xml/scap/ssg/content/ssg-demo-ds.xml">
        <xccdf:Benchmark xmlns:xccdf="http://checklists.nist.gov/xccdf/1.2" 
                         id="xccdf_org.ssgproject.content_benchmark_DEMO"
                         version="1.0">
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_password_policy" severity="high">
                <xccdf:title>Configure Password Policy</xccdf:title>
            </xccdf:Rule>
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_ssh_config" severity="medium">
                <xccdf:title>Configure SSH Properly</xccdf:title>
            </xccdf:Rule>
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_firewall_enabled" severity="high">
                <xccdf:title>Enable Firewall</xccdf:title>
            </xccdf:Rule>
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_updates_installed" severity="medium">
                <xccdf:title>Install Security Updates</xccdf:title>
            </xccdf:Rule>
            <xccdf:Rule id="xccdf_org.ssgproject.content_rule_bootloader_config" severity="low">
                <xccdf:title>Configure Bootloader</xccdf:title>
            </xccdf:Rule>
        </xccdf:Benchmark>
    </xccdf:benchmark>
    
    <xccdf:profile idref="xccdf_org.ssgproject.content_profile_cis_demo"/>
    <xccdf:target>demo-server.example.com</xccdf:target>
    <xccdf:start-time>2024-01-15T14:30:00Z</xccdf:start-time>
    
    <!-- Passed rules -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_password_policy">
        <xccdf:result>pass</xccdf:result>
    </xccdf:rule-result>
    
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_ssh_config">
        <xccdf:result>pass</xccdf:result>
    </xccdf:rule-result>
    
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_updates_installed">
        <xccdf:result>pass</xccdf:result>
    </xccdf:rule-result>
    
    <!-- Failed rules -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_firewall_enabled">
        <xccdf:result>fail</xccdf:result>
    </xccdf:rule-result>
    
    <!-- Not applicable rules -->
    <xccdf:rule-result idref="xccdf_org.ssgproject.content_rule_bootloader_config">
        <xccdf:result>notapplicable</xccdf:result>
    </xccdf:rule-result>
</xccdf:TestResult>
EOF

# Parse the demo results
echo "Parsing demo SCAP results file..."
python3 scap_prometheus_exporter.py --results-file demo_results.xml > demo_metrics.txt

echo "Generated Prometheus metrics:"
echo "=============================="
head -20 demo_metrics.txt
echo "..."
echo "Total lines: $(wc -l < demo_metrics.txt)"

echo ""
echo "3. Key metrics from the demo scan:"
echo "=================================="
echo "Compliance Score: $(grep 'scap_compliance_score_percent{' demo_metrics.txt | head -1)"
echo "Total Rules:      $(grep 'scap_total_rules{' demo_metrics.txt | head -1)"
echo "Failed Rules:     $(grep 'scap_rules_by_status.*status=\"failed\"' demo_metrics.txt)"
echo "High Severity:    $(grep 'scap_failed_rules_by_severity.*severity=\"high\"' demo_metrics.txt)"

# Cleanup
rm -f demo_results.xml demo_metrics.txt

echo ""
echo "4. Available commands:"
echo "======================"
echo "• Run tests:              python3 test_exporter.py"
echo "• Parse SCAP file:        python3 scap_prometheus_exporter.py --results-file <file>"
echo "• Start exporter daemon:  python3 scap_prometheus_exporter.py --config scap_exporter.yaml"
echo "• Build Docker stack:     make build && make up"
echo "• View all options:       make help"
echo ""
echo "• Full deployment:        ./quickstart.sh all"

echo ""
echo "Demo complete! 🎉"
echo ""
echo "Next steps:"
echo "1. Edit scap_exporter.yaml to configure your SCAP profiles"
echo "2. Run './quickstart.sh all' to deploy the full monitoring stack"
echo "3. Access Grafana at http://localhost:3000 (admin/scap_admin_2024)"
