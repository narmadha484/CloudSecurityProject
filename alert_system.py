import boto3
import json

sns = boto3.client("sns")

SNS_TOPIC_ARN ="arn:aws:sns:us-east-1:182025016916:cloud-security-alerts"

def send_alert(findings):
    if not findings:
        return

    message = "🚨 AWS Security Alert Detected 🚨\n\n"

    for f in findings:
        message += (
            f"Service  : {f.get('service')}\n"
            f"Resource : {f.get('resource')}\n"
            f"Issue    : {f.get('issue')}\n"
            f"Severity : {f.get('severity')}\n"
            "-----------------------------\n"
        )

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject="AWS Security Alert",
        Message=message
    )

