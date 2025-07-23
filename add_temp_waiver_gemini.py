import os
import requests
import json
import argparse
from datetime import datetime, timedelta, timezone

# --- Configuration ---
# It is strongly recommended to use environment variables for credentials
# instead of hardcoding them in the script.
NEXUS_IQ_URL = os.getenv("NEXUS_IQ_URL", "http://localhost:8070")
USERNAME = os.getenv("NEXUS_IQ_USERNAME", "admin")
PASSWORD = os.getenv("NEXUS_IQ_PASSWORD", "admin123")

# --- Helper Functions ---

def get_application_internal_id(public_id: str) -> str | None:
    """
    Retrieves the internal application ID for a given public ID.

    Args:
        public_id: The public identifier of the application (project name).

    Returns:
        The internal application ID as a string, or None if not found.
    """
    print(f"Attempting to find application with public ID: {public_id}")
    api_url = f"{NEXUS_IQ_URL}/api/v2/applications"
    params = {'publicId': public_id}
    
    try:
        response = requests.get(api_url, auth=(USERNAME, PASSWORD), params=params)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        
        data = response.json()
        applications = data.get('applications', [])
        
        if not applications:
            print(f"Error: No application found with public ID '{public_id}'.")
            return None
            
        app_id = applications[0].get('id')
        print(f"Successfully found application. Internal ID: {app_id}")
        return app_id

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Nexus IQ API: {e}")
        return None
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON response from the server.")
        return None

def get_policy_violations(app_internal_id: str, stage: str) -> list:
    """
    Fetches all policy violations for a specific application and stage.

    Args:
        app_internal_id: The internal ID of the application.
        stage: The stage to get violations for (e.g., 'build', 'stage-release').

    Returns:
        A list of policy violation objects, or an empty list if none are found.
    """
    print(f"Fetching policy violations for application ID {app_internal_id} at stage '{stage}'...")
    api_url = f"{NEXUS_IQ_URL}/api/v2/policyViolations"
    # Note: Filtering by stage requires getting a report first. 
    # This example gets all violations for simplicity. For stage-specific violations,
    # you would first get the latest report for that stage.
    params = {'applicationId': app_internal_id}

    try:
        response = requests.get(api_url, auth=(USERNAME, PASSWORD), params=params)
        response.raise_for_status()
        
        violations = response.json().get('policyViolations', [])
        if violations:
            print(f"Found {len(violations)} policy violations.")
        else:
            print("No policy violations found for this application.")
        return violations

    except requests.exceptions.RequestException as e:
        print(f"Error fetching policy violations: {e}")
        return []

def waive_violations(app_internal_id: str, violations: list, expiry_days: int):
    """
    Applies a waiver to a list of component policy violations.

    Args:
        app_internal_id: The internal ID of the application.
        violations: A list of violation objects to be waived.
        expiry_days: The number of days the waiver should be valid.
    """
    if not violations:
        print("No violations to waive.")
        return

    print(f"Preparing to waive {len(violations)} violations...")
    
    # Prepare the list of violations for the waiver payload
    violations_to_waive = []
    for violation in violations:
        # We only want to waive security violations for this script's purpose
        if violation.get('policyThreatCategory') == 'SECURITY':
            violations_to_waive.append({
                "policyViolationId": violation.get("policyViolationId"),
                "componentIdentifier": violation.get("componentIdentifier")
            })

    if not violations_to_waive:
        print("No security violations found to waive.")
        return

    # Calculate the expiration time
    expiry_time = datetime.now(timezone.utc) + timedelta(days=expiry_days)
    expiry_time_str = expiry_time.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

    # Construct the waiver request payload
    waiver_payload = {
        "componentPolicyViolations": violations_to_waive,
        "comment": f"Bulk waiver applied by script for {expiry_days} days.",
        "expiryTime": expiry_time_str
    }

    api_url = f"{NEXUS_IQ_URL}/api/v2/waivers/application/{app_internal_id}"
    headers = {'Content-Type': 'application/json'}

    try:
        print(f"Sending bulk waiver request for {len(violations_to_waive)} security violations...")
        response = requests.post(api_url, auth=(USERNAME, PASSWORD), headers=headers, data=json.dumps(waiver_payload))
        response.raise_for_status()
        
        print("\nSuccessfully applied waivers!")
        print(f"Waiver Comment: {waiver_payload['comment']}")
        print(f"Expires On: {expiry_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    except requests.exceptions.HTTPError as e:
        print(f"\nError applying waiver: {e.response.status_code} {e.response.reason}")
        print(f"Response Body: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Nexus IQ API to apply waiver: {e}")


# --- Main Execution ---

def main():
    """
    Main function to parse arguments and orchestrate the waiver process.
    """
    parser = argparse.ArgumentParser(
        description="Waive security policy violations in a Sonatype Nexus IQ project.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-p", "--project",
        required=True,
        help="The public ID (name) of the project in Nexus IQ."
    )
    parser.add_argument(
        "-d", "--days",
        type=int,
        default=7,
        help="The number of days the waiver should be valid. Default is 7."
    )
    parser.add_argument(
        "-s", "--stage",
        type=str,
        default="build",
        help="The stage to check for violations (e.g., 'build'). Default is 'build'."
    )
    args = parser.parse_args()

    print("--- Starting Nexus IQ Waiver Script ---")
    
    app_id = get_application_internal_id(args.project)
    
    if app_id:
        violations = get_policy_violations(app_id, args.stage)
        if violations:
            waive_violations(app_id, violations, args.days)

    print("\n--- Script Finished ---")


if __name__ == "__main__":
    main()
