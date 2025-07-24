import requests
import datetime
import argparse
import os
import csv
import urllib3
from urllib.parse import quote
from pathlib import Path
from collections import Counter

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
NEXUS_IQ_URL = os.getenv("NEXUS_IQ_URL", "https://your-nexus-iq-server.com")
IQ_USERNAME = os.getenv("NEXUS_IQ_USERNAME", "admin")
IQ_PASSWORD = os.getenv("NEXUS_IQ_PASSWORD", "admin123")

HEADERS = {
    "Content-Type": "application/json"
}

def get_application_id(project_name, verify_ssl):
    print("[INFO] Looking up application by publicId:", project_name)
    url = f"{NEXUS_IQ_URL}/api/v2/applications?publicId={quote(project_name)}"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS, verify=verify_ssl)

    if response.status_code == 404:
        raise ValueError(f"[ERROR] Project '{project_name}' not found in Nexus IQ.")
    response.raise_for_status()

    data = response.json()
    applications = data.get("applications")
    if not applications:
        raise ValueError(f"[ERROR] No applications found for publicId '{project_name}'")

    app_id = applications[0].get("id")
    if not app_id:
        raise ValueError(f"[ERROR] 'id' missing in application object for project '{project_name}'")

    print("[INFO] Found application ID:", app_id)
    return app_id

def get_latest_report_id(application_id, verify_ssl):
    print("[INFO] Fetching latest report for application ID:", application_id)
    url = f"{NEXUS_IQ_URL}/api/v2/reports/applications/{quote(application_id)}"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS, verify=verify_ssl)
    response.raise_for_status()
    reports = response.json()
    print("[INFO] Number of reports retrieved:", len(reports))
    if not reports:
        raise ValueError("[ERROR] No reports found for the specified application.")
    latest_url = reports[0]["reportHtmlUrl"]
    report_id = latest_url.rstrip("/").split("/")[-1]
    print("[INFO] Latest report ID:", report_id)
    return report_id

def get_security_policy_violations(application_public_id, report_id, verify_ssl):
    print("[INFO] Fetching policy data for report:", report_id)
    url = f"{NEXUS_IQ_URL}/api/v2/applications/{quote(application_public_id)}/reports/{quote(report_id)}/policy"
    response = requests.get(url, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS, verify=verify_ssl)
    response.raise_for_status()
    data = response.json()
    components = data.get("components", [])
    print("[INFO] Total components returned:", len(components))

    security_violations = []

    for i, comp in enumerate(components):
        if not comp:
            print(f"[WARN] Skipping null component at index {i}")
            continue

        comp_hash = comp.get("hash")
        comp_name = comp.get("displayName") or comp.get("packageUrl") or f"Component {i}"

        violations = comp.get("violations")
        if not violations:
            continue

        for vio in violations:
            if not vio:
                continue

            if vio.get("policyThreatCategory", "").upper() == "SECURITY":
                vio["component"] = {
                    "hash": comp_hash,
                    "displayName": comp_name,
                    "packageUrl": comp.get("packageUrl")
                }
                security_violations.append(vio)

    print("[INFO] Security violations found:", len(security_violations))
    return security_violations

def write_csv_report(filename, rows):
    file_exists = Path(filename).exists()
    print("[INFO] Writing", len(rows), "entries to CSV file:", filename)
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
    print("[INFO] Waiver report successfully written to:", filename)

def add_waiver(project_name, violation, expiry_days, execution_time, dry_run=False, verify_ssl=True):
    component = violation.get("component", {})
    component_name = component.get("displayName", "Unknown")
    violation_id = violation.get("policyViolationId")
    policy_name = violation.get("policyName")

    expiry_timestamp = (datetime.datetime.utcnow() + datetime.timedelta(days=expiry_days)).strftime('%Y-%m-%dT%H:%M:%S.000+0000')
    reason = f"Temporary security waiver for {expiry_days} days"

    print("[INFO] Processing waiver for component:", component_name, "| policy:", policy_name)

    if dry_run:
        print("[DRY-RUN] Would add waiver (expires", expiry_timestamp + ")")
        return (project_name, component_name, policy_name, violation_id, expiry_timestamp, "dry-run", execution_time)

    url = f"{NEXUS_IQ_URL}/api/v2/policyWaivers/application/{quote(project_name)}/{quote(violation_id)}"

    waiver_data = {
        "comment": reason,
        "expiryTime": expiry_timestamp
    }

    response = requests.post(url, json=waiver_data, auth=(IQ_USERNAME, IQ_PASSWORD), headers=HEADERS, verify=verify_ssl)

    if response.status_code == 201:
        print("[INFO] Waiver added (expires", expiry_timestamp + ")")
        return (project_name, component_name, policy_name, violation_id, expiry_timestamp, "waived", execution_time)
    elif response.status_code == 409:
        print("[INFO] Waiver already exists – skipping")
        return (project_name, component_name, policy_name, violation_id, expiry_timestamp, "already exists", execution_time)
    else:
        print("[ERROR] Failed to add waiver:", response.status_code, "-", response.text)
        return (project_name, component_name, policy_name, violation_id, expiry_timestamp, "failed", execution_time)

def summarize_actions(report_rows):
    print("\n[SUMMARY] Waiver processing results:")
    counter = Counter(row[5] for row in report_rows)
    total = len(report_rows)
    for status in ["waived", "already exists", "dry-run", "skipped", "failed"]:
        print(f"  {status:<15}: {counter.get(status, 0)}")
    print(f"  {'total':<15}: {total}")

def main():
    parser = argparse.ArgumentParser(description="Add waivers to Nexus IQ security violations")
    parser.add_argument("project_name", help="Project name as configured in Nexus IQ")
    parser.add_argument("--days", type=int, default=7, help="Waiver expiry duration in days (default: 7)")
    parser.add_argument("--dry-run", action="store_true", help="Simulate waiver creation without changes")
    parser.add_argument("--output", default="waiver_report.csv", help="CSV output filename (default: waiver_report.csv)")
    parser.add_argument("--secure", action="store_true", help="Enable SSL verification (default is disabled)")

    args = parser.parse_args()
    verify_ssl = args.secure is True

    print("[INFO] Starting waiver process...")
    print(f"[INFO] SSL verification is {'ENABLED' if verify_ssl else 'DISABLED'}")
    report_rows = []
    execution_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        app_id = get_application_id(args.project_name, verify_ssl)
        report_id = get_latest_report_id(app_id, verify_ssl)
        security_violations = get_security_policy_violations(args.project_name, report_id, verify_ssl)

        if not security_violations:
            print("[INFO] No security violations found.")
        else:
            for index, violation in enumerate(security_violations, start=1):
                print("[INFO] Processing violation", index, "of", len(security_violations))
                result_row = add_waiver(
                    args.project_name,
                    violation,
                    args.days,
                    execution_time,
                    dry_run=args.dry_run,
                    verify_ssl=verify_ssl
                )
                if result_row:
                    report_rows.append(result_row)

        write_csv_report(args.output, report_rows)
        summarize_actions(report_rows)
        print("[INFO] Waiver process completed.")

    except Exception as e:
        print("[ERROR]", e)

if __name__ == "__main__":
    main()
