def generate_ai_explanation(service, issue, resource, severity):
    """
    Returns a COMPLETE human-readable AI explanation.
    """

    # IAM
    if service == "IAM":
        if "mfa" in issue.lower():
            return (
                "The IAM user does not have Multi-Factor Authentication (MFA) enabled. "
                "If the username and password are compromised, an attacker can log in "
                "without any additional verification.\n\n"
                "If ignored, this could lead to full account compromise, data deletion, "
                "or unexpected billing charges.\n\n"
                "Recommended fix: Enable MFA for the IAM user immediately."
            )

    # S3
    if service == "S3":
        if "public" in issue.lower():
            return (
                "The S3 bucket is publicly accessible, meaning anyone on the internet "
                "can view or download its contents.\n\n"
                "This can expose sensitive or private data.\n\n"
                "Recommended fix: Block public access and review bucket policies."
            )

        if "versioning" in issue.lower():
            return (
                "S3 versioning is disabled. Without versioning, deleted or overwritten "
                "files cannot be recovered.\n\n"
                "This increases the risk of permanent data loss.\n\n"
                "Recommended fix: Enable versioning on the S3 bucket."
            )

        if "encryption" in issue.lower():
            return (
                "The S3 bucket does not have encryption enabled. Data stored in the bucket "
                "is not protected at rest.\n\n"
                "If accessed unlawfully, sensitive data can be read in plain text.\n\n"
                "Recommended fix: Enable default encryption for the bucket."
            )

    # EC2
    if service == "EC2":
        if "public ip" in issue.lower():
            return (
                "The EC2 instance has a public IP address, making it directly reachable "
                "from the internet.\n\n"
                "This increases exposure to scanning, brute-force attacks, and exploits.\n\n"
                "Recommended fix: Remove the public IP or place the instance behind a load balancer."
            )

        if "port 22" in issue.lower():
            return (
                "SSH (port 22) is open to the entire internet (0.0.0.0/0).\n\n"
                "Attackers can attempt brute-force or credential-stuffing attacks.\n\n"
                "Recommended fix: Restrict SSH access to trusted IP addresses only."
            )

        if "not encrypted" in issue.lower():
            return (
                "The attached EBS volume is not encrypted. Data stored on the volume "
                "is readable if the storage is accessed.\n\n"
                "This may expose sensitive information.\n\n"
                "Recommended fix: Enable EBS encryption using AWS KMS."
            )

    return "Security issue detected. Review AWS security best practices."
    

def explain_findings(findings):
    """
    Attaches AI explanations to each finding.
    """
    for f in findings:
        f["explanation"] = generate_ai_explanation(
            service=f.get("service"),
            issue=f.get("issue"),
            resource=f.get("resource"),
            severity=f.get("severity")
        )
    return findings


def explain_fix(issue, action, resource):
    """
    Returns explanation for automated remediation.
    """
    return (
        f"Remediation for '{issue}' on resource '{resource}' executed. "
        f"Action performed: {action}."
    )

