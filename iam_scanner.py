import boto3
from datetime import datetime, timezone

iam = boto3.client("iam")

def scan_iam_security():
    findings = []

    users = iam.list_users()["Users"]

    # 1️⃣ MFA check
    for user in users:
        mfa = iam.list_mfa_devices(UserName=user["UserName"])["MFADevices"]
        if not mfa:
            findings.append({
                "service": "IAM",
                "resource": user["UserName"],
                "issue": "IAM user without MFA",
                "severity": "HIGH"
            })

    # 2️⃣ Old access keys
    for user in users:
        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            age = datetime.now(timezone.utc) - key["CreateDate"]
            if age.days > 90:
                findings.append({
                    "service": "IAM",
                    "resource": user["UserName"],
                    "issue": f"Access key older than 90 days ({age.days} days)",
                    "severity": "MEDIUM"
                })

    # 3️⃣ Root MFA
    root = iam.get_account_summary()["SummaryMap"]
    if root.get("AccountMFAEnabled", 0) == 0:
        findings.append({
            "service": "IAM",
            "resource": "ROOT",
            "issue": "Root account MFA not enabled",
            "severity": "CRITICAL"
        })

    # 4️⃣ Password policy
    try:
        iam.get_account_password_policy()
    except:
        findings.append({
            "service": "IAM",
            "resource": "Account",
            "issue": "No IAM password policy configured",
            "severity": "HIGH"
        })

    return findings

