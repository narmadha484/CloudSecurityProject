# AI-Driven Cloud Security Scanner 🚀

## Project Description
This project is an AI-powered AWS security scanner that detects misconfigurations
across S3, IAM, and EC2 services, explains risks using AI, and automatically remediates
critical vulnerabilities.

## Features
- S3 security scanning (public access, encryption, versioning)
- IAM security checks (MFA enforcement)
- EC2 security checks (public IP, open ports, unencrypted EBS)
- AI-generated risk explanations
- Auto-remediation for critical SSH exposure
- Security report generation (JSON)
- Interactive Streamlit dashboard
- SNS alert notifications

## Technologies Used
- AWS (EC2, S3, IAM, SNS)
- Python
- Boto3
- Streamlit
- OpenAI API

## How to Run
```bash
python3 main.py
streamlit run dashboard.py

