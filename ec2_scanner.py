import boto3

ec2 = boto3.client("ec2")

def scan_ec2_security():
    findings = []

    instances = ec2.describe_instances()

    for r in instances["Reservations"]:
        for i in r["Instances"]:
            instance_id = i["InstanceId"]

            # 1️⃣ Public IP
            if i.get("PublicIpAddress"):
                findings.append({
                    "service": "EC2",
                    "resource": instance_id,
                    "issue": "Instance has public IP",
                    "severity": "MEDIUM"
                })

            # 2️⃣ Security Groups check
            for sg in i["SecurityGroups"]:
                sg_data = ec2.describe_security_groups(
                    GroupIds=[sg["GroupId"]]
                )["SecurityGroups"][0]

                for perm in sg_data.get("IpPermissions", []):
                    from_port = perm.get("FromPort")

                    for ip in perm.get("IpRanges", []):
                        if ip.get("CidrIp") == "0.0.0.0/0":
                            findings.append({
                                "service": "EC2",
                                "resource": instance_id,
                                "issue": f"Port {from_port} open to world (0.0.0.0/0)",
                                "severity": "CRITICAL" if from_port in [22, 3389] else "HIGH"
                            })

            # 3️⃣ EBS Encryption
            for block in i.get("BlockDeviceMappings", []):
                volume_id = block["Ebs"]["VolumeId"]
                vol = ec2.describe_volumes(
                    VolumeIds=[volume_id]
                )["Volumes"][0]

                if not vol["Encrypted"]:
                    findings.append({
                        "service": "EC2",
                        "resource": volume_id,
                        "issue": "EBS volume not encrypted",
                        "severity": "HIGH"
                    })

    return findings

