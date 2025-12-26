import boto3

s3 = boto3.client("s3")

def scan_s3_buckets():
    findings = []

    buckets = s3.list_buckets()["Buckets"]

    print("\n=== S3 Security Scan ===")

    for bucket in buckets:
        name = bucket["Name"]
        print(f"\n🔍 Bucket: {name}")

        # --- Public Access check ---
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            public = any(
                grant["Grantee"].get("URI") ==
                "http://acs.amazonaws.com/groups/global/AllUsers"
                for grant in acl["Grants"]
            )

            if public:
                print("  - Public Access: YES ❌")
                findings.append({
                    "service": "S3",
                    "resource": name,
                    "issue": "S3 bucket is public",
                    "severity": "CRITICAL",
                    "auto_fix_status": "Cannot auto-fix S3 public access",
                    "fix_explanation": "Please manually update the bucket ACL or Block Public Access settings."
                })
            else:
                print("  - Public Access: NO ✅")
        except Exception:
            print("  - Public Access: ERROR")

        # --- Encryption check ---
        try:
            s3.get_bucket_encryption(Bucket=name)
            print("  - Encryption: ENABLED 🔐")
        except s3.exceptions.ClientError:
            print("  - Encryption: NOT ENABLED ⚠️")
            # Auto-enable encryption
            s3.put_bucket_encryption(
                Bucket=name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': 'AES256'}}]
                }
            )
            print("    > Auto-fixed: Encryption ENABLED 🔐")
            findings.append({
                "service": "S3",
                "resource": name,
                "issue": "S3 encryption not enabled",
                "severity": "HIGH",
                "auto_fix_status": "Encryption enabled automatically",
                "fix_explanation": "Default AES256 encryption applied to bucket."
            })

        # --- Versioning check ---
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            status = ver.get("Status", "Disabled")

            if status != "Enabled":
                print("  - Versioning: Disabled ❌")
                # Auto-enable versioning
                s3.put_bucket_versioning(
                    Bucket=name,
                    VersioningConfiguration={'Status': 'Enabled'}
                )
                print("    > Auto-fixed: Versioning ENABLED ✅")
                findings.append({
                    "service": "S3",
                    "resource": name,
                    "issue": "S3 versioning disabled",
                    "severity": "MEDIUM",
                    "auto_fix_status": "Versioning enabled automatically",
                    "fix_explanation": "Bucket versioning turned on to track all object changes."
                })
            else:
                print("  - Versioning: Enabled ✅")
        except Exception:
            print("  - Versioning: ERROR")

    return findings

