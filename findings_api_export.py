import argparse
import datetime as dt
import json
import time
import csv

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


# API Base URLs
BASE_URL = "https://api.veracode.com"
APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"

DEFAULT_PAGE_SIZE = 500  # Maximum page size for findings API


def parse_args():
    parser = argparse.ArgumentParser(
        description="Export Veracode FINDINGS data via Findings REST API (per application)."
    )
    
    parser.add_argument(
        "--output",
        default="veracode_findings_api.csv",
        help="Output CSV filename (default: veracode_findings_api.csv).",
    )
    parser.add_argument(
        "--app-name",
        help="Filter by specific application name (optional).",
    )
    parser.add_argument(
        "--app-guid",
        help="Filter by specific application GUID (optional).",
    )
    parser.add_argument(
        "--scan-type",
        help="Filter by scan type: STATIC, DYNAMIC, MANUAL, SCA (comma-separated).",
    )
    parser.add_argument(
        "--severity",
        type=int,
        help="Filter by exact severity (0-5).",
    )
    parser.add_argument(
        "--severity-gte",
        type=int,
        help="Filter by severity greater than or equal to (0-5).",
    )
    parser.add_argument(
        "--cwe",
        help="Filter by CWE ID (single or comma-separated).",
    )
    parser.add_argument(
        "--status",
        help="Filter by finding status: OPEN or CLOSED.",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Sleep in seconds between API calls (default: 0.5).",
    )
    parser.add_argument(
        "--max-apps",
        type=int,
        help="Limit number of applications to process (for testing).",
    )
    return parser.parse_args()


def get_applications(session, sleep_time=0.5):
    """
    Fetch all applications using pagination.
    Returns a list of application objects with guid and profile.name.
    """
    print("\n" + "=" * 70)
    print("  FETCHING APPLICATIONS")
    print("=" * 70)
    
    all_apps = []
    page = 0
    
    while True:
        print(f"  Fetching applications page {page}...")
        
        resp = session.get(
            APPLICATIONS_URL,
            params={"page": page, "size": 500},
            auth=RequestsAuthPluginVeracodeHMAC(),
            timeout=60,
        )
        
        if resp.status_code != 200:
            print(f"  ERROR: Status {resp.status_code}")
            print(f"  Response: {resp.text}")
            resp.raise_for_status()
        
        data = resp.json()
        
        embedded = data.get("_embedded", {})
        applications = embedded.get("applications", [])
        
        if not applications:
            break
        
        all_apps.extend(applications)
        print(f"  Page {page}: {len(applications)} applications (Total: {len(all_apps)})")
        
        links = data.get("_links", {})
        if not links.get("next"):
            break
        
        page += 1
        time.sleep(sleep_time)
    
    print(f"\n  Total applications found: {len(all_apps)}\n")
    return all_apps


def get_findings_for_app(session, app_guid, app_name, app_profile, filters, sleep_time=0.5):
    """
    Fetch all findings for a specific application using pagination.
    Returns a list of finding objects.
    """
    url = FINDINGS_URL_TEMPLATE.format(app_guid=app_guid)
    all_findings = []
    page = 0
    
    params = {
        "page": page,
        "size": DEFAULT_PAGE_SIZE,
    }
    
    if filters.get("scan_type"):
        params["scan_type"] = filters["scan_type"]
    if filters.get("severity") is not None:
        params["severity"] = filters["severity"]
    if filters.get("severity_gte") is not None:
        params["severity_gte"] = filters["severity_gte"]
    if filters.get("cwe"):
        params["cwe"] = filters["cwe"]
    
    while True:
        params["page"] = page
        
        try:
            resp = session.get(
                url,
                params=params,
                auth=RequestsAuthPluginVeracodeHMAC(),
                timeout=120,
            )
            
            if resp.status_code == 404:
                print(f"    No findings or app not found (404)")
                break
            
            if resp.status_code != 200:
                print(f"    ERROR: Status {resp.status_code}")
                print(f"    Response: {resp.text}")
                resp.raise_for_status()
            
            data = resp.json()
            
            embedded = data.get("_embedded", {})
            findings = embedded.get("findings", [])
            
            if not findings:
                break
            
            for finding in findings:
                finding["_app_name"] = app_name
                finding["_app_guid"] = app_guid
                finding["_app_profile"] = app_profile
            
            all_findings.extend(findings)
            
            if page == 0:
                print(f"    Page {page}: {len(findings)} findings")
            else:
                print(f"    Page {page}: {len(findings)} findings (Total: {len(all_findings)})")
            
            links = data.get("_links", {})
            if not links.get("next"):
                break
            
            page += 1
            time.sleep(sleep_time)
            
        except Exception as e:
            print(f"    ERROR fetching findings: {e}")
            break
    
    return all_findings


def calculate_days_to_resolve(first_found, resolution_date):
    """Calculate days between first found and resolution date."""
    if not first_found or not resolution_date:
        return None
    
    try:
        if isinstance(first_found, str):
            first_found_dt = dt.datetime.fromisoformat(first_found.replace('Z', '+00:00'))
        else:
            first_found_dt = first_found
            
        if isinstance(resolution_date, str):
            resolution_date_dt = dt.datetime.fromisoformat(resolution_date.replace('Z', '+00:00'))
        else:
            resolution_date_dt = resolution_date
        
        delta = resolution_date_dt - first_found_dt
        return delta.days
    except Exception:
        return None


def extract_cwe_id(finding_details):
    """Extract CWE ID from finding_details."""
    if not finding_details:
        return None
    
    cwe = finding_details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id")
    elif isinstance(cwe, (int, float)):
        return int(cwe)
    return None


def extract_cwe_name(finding_details):
    """Extract CWE name/flaw name from finding_details."""
    if not finding_details:
        return None
    
    cwe = finding_details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("name")
    
    return (
        finding_details.get("finding_category") or
        finding_details.get("flaw_name")
    )


def extract_cve_id(finding_details):
    """Extract CVE ID from finding_details (mainly for SCA)."""
    if not finding_details:
        return None
    
    cve = finding_details.get("cve")
    if isinstance(cve, dict):
        return cve.get("name")
    elif isinstance(cve, str):
        return cve
    return None


def extract_cvss(finding_details):
    """Extract CVSS score from finding_details."""
    if not finding_details:
        return None
    
    cve = finding_details.get("cve")
    if isinstance(cve, dict):
        cvss3 = cve.get("cvss3", {})
        if cvss3 and cvss3.get("score"):
            return cvss3.get("score")
        return cve.get("cvss")
    
    return finding_details.get("cvss")


def extract_filename(finding_details, scan_type):
    """Extract filename/class/component based on scan type."""
    if not finding_details:
        return None
    
    if scan_type == "STATIC":
        return finding_details.get("file_name") or finding_details.get("file_path")
    
    elif scan_type == "DYNAMIC":
        return finding_details.get("path") or finding_details.get("URL")
    
    elif scan_type == "MANUAL":
        return finding_details.get("location") or finding_details.get("module")
    
    elif scan_type == "SCA":
        return finding_details.get("component_filename") or finding_details.get("version")
    
    return None


def normalize_finding(finding):
    """
    Extract and normalize required fields from a finding record.
    """
    app_name = finding.get("_app_name")
    app_guid = finding.get("_app_guid")
    app_profile = finding.get("_app_profile", {})
    scan_type = finding.get("scan_type")
    description = finding.get("description")
    
    # Extract team name from business unit or teams array
    team_name = None
    business_unit = app_profile.get("business_unit")
    if isinstance(business_unit, dict):
        bu_name = business_unit.get("name")
        if bu_name and bu_name != "Not Specified":
            team_name = bu_name
    
    if not team_name:
        teams = app_profile.get("teams", [])
        if isinstance(teams, list) and teams:
            first_team = teams[0]
            if isinstance(first_team, dict):
                team_name = first_team.get("team_name")
    
    finding_status_obj = finding.get("finding_status", {})
    first_found = finding_status_obj.get("first_found_date")
    status = finding_status_obj.get("status")
    resolution_status = finding_status_obj.get("resolution_status")
    resolution = finding_status_obj.get("resolution")
    
    fixed_date = None
    if status == "CLOSED" or resolution_status == "FIXED":
        fixed_date = finding_status_obj.get("last_seen_date")
    
    finding_details = finding.get("finding_details", {})
    
    cwe_id = extract_cwe_id(finding_details)
    flaw_name = extract_cwe_name(finding_details)
    cve_id = extract_cve_id(finding_details)
    cvss = extract_cvss(finding_details)
    filename = extract_filename(finding_details, scan_type)
    
    severity = finding_details.get("severity")
    
    custom_severity_map = {
        5: "Very High",
        4: "High",
        3: "Medium",
        2: "Low",
        1: "Very Low",
        0: "Informational",
    }
    custom_severity = custom_severity_map.get(severity) if severity is not None else None
    
    days_to_resolve = calculate_days_to_resolve(first_found, fixed_date)
    
    vuln_title = description[:100] if description else None
    
    return {
        "Application Name": app_name,
        "Application ID": app_guid,
        "Custom Severity Name": custom_severity,
        "CVE ID": cve_id,
        "Description": description,
        "Vulnerability Title": vuln_title,
        "CWE ID": cwe_id,
        "Flaw Name": flaw_name,
        "First Found Date": first_found,
        "Filename/Class": filename,
        "Finding Status": status,
        "Fixed Date": fixed_date,
        "Team Name": team_name,
        "Days to Resolve": days_to_resolve,
        "Scan Type": scan_type,
        "CVSS": cvss,
        "Severity": severity,
        "Resolution Status": resolution_status,
        "Resolution": resolution,
    }


def main():
    args = parse_args()
    
    # Print header banner
    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS API EXPORT")
    print("=" * 70)
    print(f"  Output File: {args.output}")
    if args.app_name:
        print(f"  Filter: Application Name = {args.app_name}")
    if args.app_guid:
        print(f"  Filter: Application GUID = {args.app_guid}")
    if args.scan_type:
        print(f"  Filter: Scan Type = {args.scan_type}")
    if args.severity is not None:
        print(f"  Filter: Severity = {args.severity}")
    if args.severity_gte is not None:
        print(f"  Filter: Severity >= {args.severity_gte}")
    if args.cwe:
        print(f"  Filter: CWE = {args.cwe}")
    print("=" * 70 + "\n")
    
    session = requests.Session()
    
    # Build filters
    filters = {}
    if args.scan_type:
        filters["scan_type"] = args.scan_type
    if args.severity is not None:
        filters["severity"] = args.severity
    if args.severity_gte is not None:
        filters["severity_gte"] = args.severity_gte
    if args.cwe:
        filters["cwe"] = args.cwe
    
    # Step 1: Get applications
    if args.app_guid:
        # Single application by GUID
        applications = [{"guid": args.app_guid, "profile": {"name": "Unknown"}}]
        print(f"Processing single application: {args.app_guid}\n")
    else:
        # Get all applications
        applications = get_applications(session, args.sleep)
        
        # Filter by app name if specified
        if args.app_name:
            applications = [
                app for app in applications
                if args.app_name.lower() in app.get("profile", {}).get("name", "").lower()
            ]
            print(f"Filtered to {len(applications)} applications matching '{args.app_name}'\n")
        
        # Limit number of apps if specified (for testing)
        if args.max_apps:
            applications = applications[:args.max_apps]
            print(f"Limited to {args.max_apps} applications (for testing)\n")
    
    # Step 2: Fetch findings for each application
    print("\n" + "=" * 70)
    print("  FETCHING FINDINGS FROM APPLICATIONS")
    print("=" * 70 + "\n")
    
    all_findings = []
    apps_with_findings = 0
    
    for idx, app in enumerate(applications, start=1):
        app_guid = app.get("guid")
        app_profile = app.get("profile", {})
        app_name = app_profile.get("name", "Unknown")
        
        print(f"  [{idx}/{len(applications)}] {app_name}")
        print(f"    GUID: {app_guid}")
        
        findings = get_findings_for_app(
            session=session,
            app_guid=app_guid,
            app_name=app_name,
            app_profile=app_profile,
            filters=filters,
            sleep_time=args.sleep,
        )
        
        if findings:
            all_findings.extend(findings)
            apps_with_findings += 1
            print(f"    ✓ Total: {len(findings)} findings\n")
        else:
            print(f"    ✗ No findings\n")
    
    # Step 3: Save results
    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)
    
    # Save raw JSON for debugging
    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"veracode_findings_api_raw_{timestamp}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)
    print(f"  Raw JSON: {json_file} ({len(all_findings)} findings)")
    
    # Normalize and save to CSV
    if all_findings:
        normalized_findings = [normalize_finding(f) for f in all_findings]
        
        fieldnames = [
            "Application Name",
            "Application ID",
            "Custom Severity Name",
            "CVE ID",
            "Description",
            "Vulnerability Title",
            "CWE ID",
            "Flaw Name",
            "First Found Date",
            "Filename/Class",
            "Finding Status",
            "Fixed Date",
            "Team Name",
            "Days to Resolve",
            "Scan Type",
            "CVSS",
            "Severity",
            "Resolution Status",
            "Resolution",
        ]
        
        with open(args.output, "w", encoding="utf-8", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(normalized_findings)
        
        print(f"  CSV File: {args.output} ({len(normalized_findings)} findings)")
    else:
        print("  No findings found with the specified filters.")
    
    print("\n" + "=" * 70)
    print("  EXPORT COMPLETED")
    print("=" * 70)
    print(f"  Applications processed: {len(applications)}")
    print(f"  Applications with findings: {apps_with_findings}")
    print(f"  Total findings: {len(all_findings)}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
