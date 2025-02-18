import json
import logging
from typing import Dict, List, Any
from datetime import datetime
import jinja2
import aiofiles
import csv
import io
from pathlib import Path
import asyncio
from weasyprint import HTML
import matplotlib.pyplot as plt
import numpy as np

class ReportGenerator:
    """Generates STIG compliance reports in various formats"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.template_dir = Path(__file__).parent / "templates"
        self.template_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )

    async def generate(self, scan_data: Dict[str, Any], format: str = "json") -> str:
        """Generate a report in the specified format"""
        try:
            if format == "json":
                return await self._generate_json(scan_data)
            elif format == "html":
                return await self._generate_html(scan_data)
            elif format == "pdf":
                return await self._generate_pdf(scan_data)
            elif format == "csv":
                return await self._generate_csv(scan_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            self.logger.error(f"Error generating {format} report: {str(e)}")
            raise

    async def _generate_json(self, scan_data: Dict[str, Any]) -> str:
        """Generate a JSON report"""
        report = await self._prepare_report_data(scan_data)
        return json.dumps(report, indent=2)

    async def _generate_html(self, scan_data: Dict[str, Any]) -> str:
        """Generate an HTML report"""
        report_data = await self._prepare_report_data(scan_data)
        
        # Generate compliance charts
        charts = await self._generate_charts(report_data)
        report_data["charts"] = charts

        template = self.template_env.get_template("report.html")
        return template.render(**report_data)

    async def _generate_pdf(self, scan_data: Dict[str, Any]) -> str:
        """Generate a PDF report"""
        html_content = await self._generate_html(scan_data)
        
        # Generate PDF from HTML
        output_path = f"/tmp/stig_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        HTML(string=html_content).write_pdf(output_path)
        return output_path

    async def _generate_csv(self, scan_data: Dict[str, Any]) -> str:
        """Generate a CSV report"""
        report_data = await self._prepare_report_data(scan_data)
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header
        writer.writerow([
            "Rule ID", "Title", "Severity", "Status", 
            "Description", "Fix", "Check Type"
        ])

        # Write findings
        for finding in report_data["findings"]:
            writer.writerow([
                finding["rule_id"],
                finding["title"],
                finding["severity"],
                finding["status"],
                finding["description"],
                finding.get("fix", ""),
                finding.get("check_type", "")
            ])

        return output.getvalue()

    async def _prepare_report_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare and enrich report data"""
        findings = scan_data["findings"]
        
        # Calculate statistics
        stats = {
            "total_checks": len(findings),
            "failed": len([f for f in findings if f["status"] == "failed"]),
            "passed": len([f for f in findings if f["status"] == "passed"]),
            "errors": len([f for f in findings if f["status"] == "error"]),
            "compliance_score": 0.0
        }
        
        if stats["total_checks"] > 0:
            stats["compliance_score"] = (stats["passed"] / stats["total_checks"]) * 100

        # Group findings by severity
        severity_counts = {
            "high": len([f for f in findings if f["severity"] == "high"]),
            "medium": len([f for f in findings if f["severity"] == "medium"]),
            "low": len([f for f in findings if f["severity"] == "low"])
        }

        return {
            "scan_info": {
                "timestamp": scan_data["timestamp"],
                "hostname": scan_data["hostname"],
                "report_generated": datetime.now().isoformat()
            },
            "findings": findings,
            "statistics": stats,
            "severity_counts": severity_counts
        }

    async def _generate_charts(self, report_data: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts for the report"""
        charts = {}
        
        # Create compliance pie chart
        plt.figure(figsize=(8, 8))
        labels = ['Compliant', 'Non-Compliant', 'Errors']
        sizes = [
            report_data["statistics"]["passed"],
            report_data["statistics"]["failed"],
            report_data["statistics"]["errors"]
        ]
        colors = ['#2ecc71', '#e74c3c', '#95a5a6']
        
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%')
        plt.title('Compliance Status')
        
        # Save to temporary file
        compliance_chart_path = f"/tmp/compliance_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(compliance_chart_path)
        plt.close()
        
        charts["compliance_chart"] = compliance_chart_path

        # Create severity bar chart
        plt.figure(figsize=(10, 6))
        severity_data = report_data["severity_counts"]
        
        x = np.arange(len(severity_data))
        plt.bar(x, severity_data.values(), color=['#e74c3c', '#f39c12', '#3498db'])
        plt.xticks(x, severity_data.keys())
        plt.title('Findings by Severity')
        plt.ylabel('Number of Findings')
        
        # Save to temporary file
        severity_chart_path = f"/tmp/severity_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(severity_chart_path)
        plt.close()
        
        charts["severity_chart"] = severity_chart_path

        return charts

    def _get_severity_color(self, severity: str) -> str:
        """Get color code for severity level"""
        return {
            "high": "#e74c3c",
            "medium": "#f39c12",
            "low": "#3498db",
            "info": "#95a5a6"
        }.get(severity, "#95a5a6") 