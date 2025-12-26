import json
from datetime import datetime
from ai_explainer import generate_ai_explanation

def generate_report(findings):
    report = {
        "scan_time": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": []
    }

    for f in findings:
        explanation = generate_ai_explanation(
            service=f["service"],
            issue=f["issue"],
            resource=f["resource"],
            severity=f["severity"]
        )

        entry = {
            "service": f["service"],
            "resource": f["resource"],
            "issue": f["issue"],
            "severity": f["severity"],
            "explanation": explanation
        }

        if "auto_fix_status" in f:
            entry["auto_fix_status"] = f["auto_fix_status"]

        if "fix_explanation" in f:
            entry["fix_explanation"] = f["fix_explanation"]

        report["findings"].append(entry)

    with open("security_report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("📄 Security report generated successfully")

