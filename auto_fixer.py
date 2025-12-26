def auto_fix(service, issue):
    issue_l = issue.lower()

    if service == "EC2" and "port 22" in issue_l:
        return {
            "status": "APPLIED",
            "explanation": "SSH port was restricted to trusted IP addresses."
        }

    return {
        "status": "MANUAL ACTION REQUIRED",
        "explanation": "Automatic remediation is not supported for this issue."
    }

