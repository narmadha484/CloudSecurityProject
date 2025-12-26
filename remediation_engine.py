import boto3
import logging
import time

ec2 = boto3.client("ec2")
iam = boto3.client("iam")

def fix_ec2_ssh(finding):
    # Example: restrict SSH from 0.0.0.0/0 to a safer range
    print(f"Auto-fixing SSH for {finding['resource']}")
    return "SSH port restricted to allowed IPs"
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def remediate_issues():
    print("🔧 Remediation engine running...")
    time.sleep(1)

    fix_password_policy()
    fix_security_groups()

    print("🔧 Remediation engine finished")

# -------------------------
# IAM Fix
# -------------------------
def fix_password_policy():
    try:
        print("🔧 Applying IAM password policy...")
        iam.update_account_password_policy(
            MinimumPasswordLength=12,
            RequireSymbols=True,
            RequireNumbers=True,
            RequireUppercaseCharacters=True,
            RequireLowercaseCharacters=True
        )
        print("✅ Password policy applied")
        logger.info("Password policy applied")
    except Exception as e:
        print("❌ Password policy failed:", e)
        logger.error(e)

# -------------------------
# EC2 Fix (NON-BLOCKING)
# -------------------------
def fix_security_groups():
    print("🔧 Checking security groups...")
    sgs = ec2.describe_security_groups()["SecurityGroups"]

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            if perm.get("FromPort") == 22:
                for ip in perm.get("IpRanges", []):
                    if ip.get("CidrIp") == "0.0.0.0/0":
                        print(f"🔧 Closing SSH open to world in {sg['GroupId']}")
                        try:
                            ec2.revoke_security_group_ingress(
                                GroupId=sg["GroupId"],
                                IpPermissions=[perm]
                            )
                            print("✅ SSH rule removed")
                            logger.info(f"SSH closed in {sg['GroupId']}")
                        except Exception as e:
                            print("❌ Failed to close SSH:", e)
                            logger.error(e)

