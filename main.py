from s3_scanner import scan_s3_buckets
from iam_scanner import scan_iam_security
from ec2_scanner import scan_ec2_security
from remediation_engine import fix_ec2_ssh
from report_generator import generate_report
from ai_explainer import explain_fix

AUTO_FIX = True

# Run scanners
s3_findings = scan_s3_buckets()
iam_findings = scan_iam_security()
ec2_findings = scan_ec2_security()

# Combine findings
all_findings = []
all_findings.extend(s3_findings)
all_findings.extend(iam_findings)
all_findings.extend(ec2_findings)

print("\n=== Scan Completed ===")

explained_findings = []

for finding in all_findings:

    if AUTO_FIX and finding["issue"] == "Port 22 open to world (0.0.0.0/0)":
        fix_result = fix_ec2_ssh(finding)

        finding["auto_fix_status"] = fix_result
        finding["fix_explanation"] = explain_fix(
            issue=finding["issue"],
            action=fix_result,
            resource=finding["resource"]
        )

    explained_findings.append(finding)

# Generate report
generate_report(explained_findings)

print("📄 Report generated with AI explanations")
print("📩 Alert sent via SNS")
print("\n=== PROGRAM COMPLETED ===\n")

