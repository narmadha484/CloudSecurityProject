import json
import streamlit as st
from datetime import datetime

# Page config
st.set_page_config(page_title="AI Cloud Security Dashboard", layout="wide")

st.title("🔐 AI-Driven Cloud Security Dashboard")

try:
    # Load report
    with open("security_report.json", "r") as f:
        report = json.load(f)

    # Display scan info
    st.success(f"Last Scan Time: {report['scan_time']}")
    st.warning(f"Total Findings: {report['total_findings']}")

    # Display each finding
    for finding in report["findings"]:
        with st.expander(f"🚨 {finding.get('service', 'Unknown')} | {finding.get('issue', 'No issue')}"):
            st.markdown(f"**Resource:** {finding.get('resource', 'Unknown')}")
            st.markdown(f"**Severity:** {finding.get('severity', 'N/A')}")

            # AI explanation (multi-line)
            explanation = finding.get("explanation", "No explanation provided.")
            st.markdown("**AI Explanation:**")
            st.markdown(explanation)

            # Auto-fix status and fix explanation if present
            if "auto_fix_status" in finding:
                st.markdown("**Auto-Fix Status:**")
                st.success(finding["auto_fix_status"])

            if "fix_explanation" in finding:
                st.markdown("**Fix Explanation:**")
                st.info(finding["fix_explanation"])

except FileNotFoundError:
    st.error("Security report not found. Run the scanner first.")
except json.JSONDecodeError:
    st.error("Security report is corrupted. Please re-run the scanner.")
except Exception as e:
    st.error(f"Unexpected error: {str(e)}")


