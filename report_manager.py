# report_manager.py
import json
import logging
from datetime import datetime

REPORT_FILE = "logs/scan_report.json"

def init_report():
    return {
        "scan_time": datetime.utcnow().isoformat(),
        "s3": [],
        "iam": [],
        "ec2": []
    }

def add_finding(report, service, resource, issue, severity):
    report[service].append({
        "resource": resource,
        "issue": issue,
        "severity": severity
    })

def save_report(report):
    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=4)

    logging.info(f"Scan report saved to {REPORT_FILE}")

