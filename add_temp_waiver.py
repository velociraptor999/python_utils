import requests
import datetime
import argparse
import os
import csv
from urllib.parse import quote
from pathlib import Path

# --- Configuration ---
NEXUS_IQ_URL = os.getenv("NEXUS_IQ_URL", "https://your-nexus-iq-server.com")
IQ_USERNAME = os.getenv("NEXUS_IQ_USERNAME", "admin")
IQ_PASSWORD = os.getenv("NEXUS_IQ_PASSWORD", "admin123")

HEADERS = {
    "Content-Type": "application/json"
}


def get_application_id(project_name):
    url = f"{NEXUS_IQ_URL}/api/v2/applications"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS)
    response.raise_for_status()
    apps = response.json()["applications"]
    for app in apps:
        if app["name"].strip().lower() == project_name.strip().lower():
            return app["id"]
    raise ValueError(f"Project '{project_name}' not found in Nexus IQ.")


def get_latest_report_id(application_id):
    url = f"{NEXUS_IQ_URL}/api/v2/reports/applications/{quote(application_id)}"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS)
    response.raise_for_status()
    reports = response.json()
    if not reports:
        raise ValueError("No reports found for the specified application.")
    latest_url = reports[0]["reportHtmlUrl"]
    report_id = latest_url.rstrip("/").split("/")[-1]
    return report_id


def get_security_policy_violations(report_id):
    url = f"{NEXUS_IQ_URL}/api/v2/reports/{quote(report_id)}/policyViolations"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS)
    response.raise_for_status()
    violations = response.json().get("policyViolations", [])
    return [v for v in violations if v.get("policyThreatCategory") == "SECURITY"]


def write_csv_report(filename, rows):
    file_exists = Path(filename).exists()

    with open(filename, mode='a', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow([
                "Project Name",
                "Component Name",
                "Policy Name",
                "Violation ID",
                "Expiry Date",
                "Action",
                "Execution Time"
            ])
        writer.writerows(rows)

    print(f"\n📄 Waiver report appended to: {filename}")


def add_waiver(project_name, violation, expiry_days, execution_time, dry_run=False):
    component = violation["component"]
    component_hash = component.get("hash")
    component_name = component.get("displayName", "Unknown")
    violation_id = violation.get("policyViolationId")
    policy_name = violation.get("policyName")

    expiry_date = (datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)).strftime('%Y-%m-%d')
    reason = f"Temporary security waiver for {expiry_days} days"

    url = f"{NEXUS_IQ_URL}/api/v2/policyWaivers/component/{quote(component_hash)}/violations/{quote(violation_id)}"

    if dry_run:
        print(f"[DRY-RUN] Would add waiver for '{policy_name}' in component '{component_name}' (expires {expiry_date})")
        return (project_name, component_name, policy_name, violation_id, expiry_date, "dry-run", execution_time)

    waiver_data = {
        "reason": reason,
        "expiresOn": expiry_date
    }

    response = requests.post(url, json=waiver_data, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS)
    if response.status_code == 201:
        print(f"Waiver added for '{policy_name}' in '{component_name}' (expires {expiry_date})")
        return (project_name, component_name, policy_name, violation_id, expiry_date, "waived", execution_time)
    elif response.status_code == 409:
        print(f"Waiver already exists for '{policy_name}' in '{component_name}' – skipping")
        return (project_name, component_name, policy_name, violation_id, expiry_date, "already exists", execution_time)
    else:
        print(f"Failed to add waiver for '{policy_name}' in '{component_name}': {response.status_code} - {response.text}")
        return (project_name, component_name, policy_name, violation_id, expiry_date, "failed", execution_time)


def main():
    parser = argparse.ArgumentParser(description="Add waivers to Nexus IQ security violations")
    parser.add_argument("project_name", help="Project name as configured in Nexus IQ")
    parser.add_argument("--days", type=int, default=7, help="Waiver expiry duration in days (default: 7)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate waiver creation without changes")
    parser.add_argument("--output", default="waiver_report.csv", help="CSV output filename (default: waiver_report.csv)")
    args = parser.parse_args()

    report_rows = []
    execution_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        app_id = get_application_id(args.project_name)
        report_id = get_latest_report_id(app_id)
        security_violations = get_security_policy_violations(report_id)

        if not security_violations:
            print("No security violations found in the latest report.")
        else:
            for violation in security_violations:
                result_row = add_waiver(args.project_name, violation, args.days, execution_time, dry_run=args.dry_run)
                if result_row:
                    report_rows.append(result_row)

        write_csv_report(args.output, report_rows)

    except Exception as e:
        print(f"\n Error: {e}")


if __name__ == "__main__":
    main()
