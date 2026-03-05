import argparse
import datetime as dt
import json
import time
import csv
import re
import html

import requests
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC


BASE_URL = "https://api.veracode.com"
APPLICATIONS_URL = f"{BASE_URL}/appsec/v1/applications"
SANDBOXES_URL_TEMPLATE = f"{BASE_URL}/appsec/v1/applications/{{app_guid}}/sandboxes"
FINDINGS_URL_TEMPLATE = f"{BASE_URL}/appsec/v2/applications/{{app_guid}}/findings"

DEFAULT_PAGE_SIZE = 500

# SCA must be fetched in a separate API call; cannot be mixed with other scan types
NON_SCA_SCAN_TYPES = ["STATIC", "DYNAMIC", "MANUAL"]


def strip_html(text):
    """Remove HTML tags and unescape HTML entities from text. Also decodes base64 if needed."""
    if not text:
        return text
    
    import base64
    if len(text) > 50 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in text):
        try:
            # Try to decode as base64
            decoded = base64.b64decode(text).decode('utf-8')
            text = decoded
        except Exception:
            pass
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    text = ' '.join(text.split())
    return text


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
        "--include-sandbox",
        action="store_true",
        default=False,
        help="Also fetch findings from all sandboxes (default: policy scan only).",
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
    """Fetch all applications using pagination."""
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
        applications = data.get("_embedded", {}).get("applications", [])

        if not applications:
            break

        all_apps.extend(applications)
        print(f"  Page {page}: {len(applications)} applications (Total: {len(all_apps)})")

        if not data.get("_links", {}).get("next"):
            break

        page += 1
        time.sleep(sleep_time)

    print(f"\n  Total applications found: {len(all_apps)}\n")
    return all_apps


def get_sandboxes_for_app(session, app_guid, sleep_time=0.5):
    """Returns all development sandboxes for an application."""
    url = SANDBOXES_URL_TEMPLATE.format(app_guid=app_guid)

    try:
        resp = session.get(
            url,
            auth=RequestsAuthPluginVeracodeHMAC(),
            timeout=60,
        )

        if resp.status_code == 404:
            return []

        if resp.status_code != 200:
            print(f"    WARNING: Could not fetch sandboxes (status {resp.status_code})")
            return []

        data = resp.json()
        sandboxes = data.get("_embedded", {}).get("sandboxes", [])
        time.sleep(sleep_time)
        return sandboxes

    except Exception as e:
        print(f"    WARNING: Error fetching sandboxes: {e}")
        return []


def get_sca_workspaces(session, sleep_time=0.5):
    """Fetch all SCA workspaces and their projects for mapping agent-based findings."""
    sca_api_base = "https://api.veracode.com/srcclr/v3"
    workspace_project_map = {}
    
    try:
        resp = session.get(
            f"{sca_api_base}/workspaces",
            auth=RequestsAuthPluginVeracodeHMAC(),
            timeout=60,
        )
        
        if resp.status_code != 200:
            return workspace_project_map
        
        data = resp.json()
        workspaces = data.get("_embedded", {}).get("workspaces", [])
        
        for workspace in workspaces:
            workspace_id = workspace.get("id")
            workspace_site_id = workspace.get("site_id")
            
            if not workspace_id:
                continue
            
            projects_url = f"{sca_api_base}/workspaces/{workspace_id}/projects"
            resp = session.get(
                projects_url,
                auth=RequestsAuthPluginVeracodeHMAC(),
                timeout=60,
            )
            
            if resp.status_code == 200:
                projects_data = resp.json()
                projects = projects_data.get("_embedded", {}).get("projects", [])
                
                for project in projects:
                    project_site_id = project.get("site_id")
                    project_name = project.get("name", "")
                    linked_app = project.get("linked_application", {})
                    linked_app_guid = linked_app.get("guid")
                    
                    if project_site_id and workspace_site_id:
                        mapping = {
                            "workspace_guid": workspace_site_id,
                            "project_id": project_site_id,
                            "project_name": project_name
                        }
                        
                        workspace_project_map[project_name.lower()] = mapping
                        
                        if linked_app_guid:
                            workspace_project_map[f"guid:{linked_app_guid}"] = mapping
            
            time.sleep(sleep_time)
        
    except Exception as e:
        print(f"    WARNING: Could not fetch SCA workspaces: {e}")
    
    return workspace_project_map


def get_dynamic_analyses(session, sleep_time=0.5):
    """Fetch all Dynamic Analysis analyses for mapping Dynamic findings."""
    dynamic_analyses_map = {}
    
    try:
        resp = session.get(
            "https://api.veracode.com/was/configservice/v1/analyses",
            params={"size": 500},
            auth=RequestsAuthPluginVeracodeHMAC(),
            timeout=60,
        )
        
        if resp.status_code != 200:
            return dynamic_analyses_map
        
        data = resp.json()
        analyses = data.get("_embedded", {}).get("analyses", [])
        
        for analysis in analyses:
            analysis_id = analysis.get("analysis_id")
            analysis_name = analysis.get("name")
            
            if not analysis_id:
                continue
            
            # Fetch scans for this analysis to get linked app info
            scans_url = f"https://api.veracode.com/was/configservice/v1/analyses/{analysis_id}/scans"
            resp_scans = session.get(
                scans_url,
                auth=RequestsAuthPluginVeracodeHMAC(),
                timeout=60,
            )
            
            if resp_scans.status_code == 200:
                scans_data = resp_scans.json()
                scans = scans_data.get("_embedded", {}).get("scans", [])
                
                for scan in scans:
                    linked_app_guid = scan.get("linked_platform_app_uuid")
                    
                    if linked_app_guid:
                        # Store Dynamic Analysis info mapped by app GUID
                        if linked_app_guid not in dynamic_analyses_map:
                            dynamic_analyses_map[linked_app_guid] = []
                        
                        dynamic_analyses_map[linked_app_guid].append({
                            "analysis_id": analysis_id,
                            "analysis_name": analysis_name,
                            "scan_id": scan.get("scan_id"),
                            "scan_type": analysis.get("scan_type"),
                            "latest_occurrence_id": analysis.get("latest_occurrence_id"),
                        })
            
            time.sleep(sleep_time)
        
    except Exception as e:
        print(f"    WARNING: Could not fetch Dynamic Analysis analyses: {e}")
    
    return dynamic_analyses_map


def get_findings_for_app(
    session,
    app_guid,
    app_name,
    app_profile,
    filters,
    sleep_time=0.5,
    sandbox_guid=None,
    sandbox_name=None,
    app_id=None,
    app_oid=None,
):
    """Fetch all findings for an application (or sandbox) using pagination."""
    url = FINDINGS_URL_TEMPLATE.format(app_guid=app_guid)
    all_findings = []
    page = 0

    params = {
        "page": page,
        "size": DEFAULT_PAGE_SIZE,
    }

    if sandbox_guid:
        params["context"] = sandbox_guid

    if filters.get("scan_type"):
        params["scan_type"] = filters["scan_type"]
    if filters.get("severity") is not None:
        params["severity"] = filters["severity"]
    if filters.get("severity_gte") is not None:
        params["severity_gte"] = filters["severity_gte"]
    if filters.get("cwe"):
        params["cwe"] = filters["cwe"]
    if filters.get("status"):
        params["status"] = filters["status"].upper()

    if sandbox_guid:
        context_label = f"sandbox '{sandbox_name}'"
    elif sandbox_name:
        context_label = sandbox_name
    else:
        context_label = "policy scan"

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
                print(f"    No findings or app not found (404) [{context_label}]")
                break

            if resp.status_code != 200:
                print(f"    ERROR: Status {resp.status_code} [{context_label}]")
                print(f"    Response: {resp.text}")
                resp.raise_for_status()

            data = resp.json()
            findings = data.get("_embedded", {}).get("findings", [])

            if not findings:
                break

            for finding in findings:
                finding["_app_name"] = app_name
                finding["_app_guid"] = app_guid
                finding["_app_profile"] = app_profile
                finding["_sandbox_name"] = sandbox_name if sandbox_guid else None
                finding["_sandbox_guid"] = sandbox_guid
                finding["_app_id"] = app_id
                finding["_app_oid"] = app_oid

            all_findings.extend(findings)

            if page == 0:
                print(f"    [{context_label}] Page {page}: {len(findings)} findings")
            else:
                print(
                    f"    [{context_label}] Page {page}: {len(findings)} findings "
                    f"(Total so far: {len(all_findings)})"
                )

            if not data.get("_links", {}).get("next"):
                break

            page += 1
            time.sleep(sleep_time)

        except Exception as e:
            print(f"    ERROR fetching findings [{context_label}]: {e}")
            break

    return all_findings


def get_all_findings_for_app(session, app_guid, app_name, app_profile, filters, sleep_time, include_sandboxes, app_id=None, app_oid=None):
    """Fetches findings across policy scan and (optionally) all sandboxes. SCA is fetched separately per API requirements."""
    all_findings = []

    requested_scan_types = filters.get("scan_type", "").upper().split(",") if filters.get("scan_type") else []
    requested_scan_types = [s.strip() for s in requested_scan_types if s.strip()]

    if requested_scan_types:
        fetch_sca = "SCA" in requested_scan_types
        fetch_non_sca = any(t in NON_SCA_SCAN_TYPES for t in requested_scan_types)
        non_sca_types = [t for t in requested_scan_types if t in NON_SCA_SCAN_TYPES]
    else:
        fetch_sca = True
        fetch_non_sca = True
        non_sca_types = NON_SCA_SCAN_TYPES

    def run_pass(scan_type_filter, context_guid=None, context_name=None):
        pass_filters = dict(filters)
        if scan_type_filter:
            pass_filters["scan_type"] = scan_type_filter
        else:
            pass_filters.pop("scan_type", None)
        return get_findings_for_app(
            session=session,
            app_guid=app_guid,
            app_name=app_name,
            app_profile=app_profile,
            filters=pass_filters,
            sleep_time=sleep_time,
            sandbox_guid=context_guid,
            sandbox_name=context_name,
            app_id=app_id,
            app_oid=app_oid,
        )

    if fetch_non_sca:
        all_findings.extend(run_pass(",".join(non_sca_types)))

    if fetch_sca:
        all_findings.extend(run_pass("SCA", context_name="policy scan (SCA)"))

    if include_sandboxes:
        sandboxes = get_sandboxes_for_app(session, app_guid, sleep_time)

        if sandboxes:
            print(f"    Found {len(sandboxes)} sandbox(es), fetching findings for each...")

        for sandbox in sandboxes:
            sb_guid = sandbox.get("guid")
            sb_name = sandbox.get("name", sb_guid)

            if not sb_guid:
                continue

            if fetch_non_sca:
                all_findings.extend(run_pass(",".join(non_sca_types), context_guid=sb_guid, context_name=sb_name))

            if fetch_sca:
                all_findings.extend(run_pass("SCA", context_guid=sb_guid, context_name=f"{sb_name} (SCA)"))

    return all_findings


def calculate_days_to_resolve(first_found, resolution_date):
    """Calculate days between first found and resolution date."""
    if not first_found or not resolution_date:
        return None
    try:
        if isinstance(first_found, str):
            first_found_dt = dt.datetime.fromisoformat(first_found.replace("Z", "+00:00"))
        else:
            first_found_dt = first_found

        if isinstance(resolution_date, str):
            resolution_date_dt = dt.datetime.fromisoformat(resolution_date.replace("Z", "+00:00"))
        else:
            resolution_date_dt = resolution_date

        return (resolution_date_dt - first_found_dt).days
    except Exception:
        return None


def extract_cwe_id(finding_details):
    if not finding_details:
        return None
    cwe = finding_details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("id")
    elif isinstance(cwe, (int, float)):
        return int(cwe)
    return None


def extract_cwe_name(finding_details):
    if not finding_details:
        return None
    cwe = finding_details.get("cwe")
    if isinstance(cwe, dict):
        return cwe.get("name")
    return finding_details.get("finding_category") or finding_details.get("flaw_name")


def extract_cve_id(finding_details):
    if not finding_details:
        return None
    cve = finding_details.get("cve")
    if isinstance(cve, dict):
        return cve.get("name")
    elif isinstance(cve, str):
        return cve
    return None


def extract_cvss(finding_details):
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


def generate_veracode_link(app_guid, scan_type, finding_details, sandbox_guid=None, finding_obj=None, app_id=None, app_oid=None):
    """Generate the appropriate Veracode platform link based on scan type."""
    if not app_guid:
        return None
    
    base_analysis_center = "https://analysiscenter.veracode.com/auth/index.jsp"
    
    if scan_type == "STATIC":
        scan_params = None
        
        if finding_obj:
            scan_params = finding_obj.get("_latest_scan_params")
            
            if not scan_params:
                scan_params = finding_obj.get("_finding_scan_params")
        
        if scan_params and app_oid and app_id:
            return f"{base_analysis_center}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{scan_params}"
        else:
            build_id = None
            if finding_obj:
                build_id = finding_obj.get("build_id")
            if not build_id and finding_details:
                build_id = finding_details.get("build_id")
            
            if build_id and app_oid and app_id:
                return f"{base_analysis_center}#ReviewResultsAllFlaws:{app_oid}:{app_id}:{build_id}"
            elif app_oid and app_id:
                return f"{base_analysis_center}#AnalyzeAppModuleList:{app_oid}:{app_id}:"
            else:
                if sandbox_guid:
                    return f"{base_analysis_center}#AnalyzeAppModuleList:{app_guid}:{sandbox_guid}"
                else:
                    return f"{base_analysis_center}#AnalyzeAppModuleList:{app_guid}:"
    
    elif scan_type == "DYNAMIC":
        # Check if this is a Dynamic Analysis scan
        da_analysis_id = None
        if finding_obj:
            da_analysis_id = finding_obj.get("_da_analysis_id")

        # Dynamic Analysis scans page
        if da_analysis_id:
            return f"https://web.analysiscenter.veracode.com/was/#/analysis/{da_analysis_id}/scans"

        # Check for DAST scan URL
        dynamic_scan_url = None
        if finding_obj:
            dynamic_scan_url = finding_obj.get("_dynamic_scan_url")

        if dynamic_scan_url:
            # Use DAST link format
            return f"{base_analysis_center}#{dynamic_scan_url}"

        # Fallback to dynamic analysis list view
        if sandbox_guid:
            return f"{base_analysis_center}#AnalyzeAppDynamicList:{app_guid}:{sandbox_guid}"
        else:
            return f"{base_analysis_center}#AnalyzeAppDynamicList:{app_guid}:"
    
    elif scan_type == "MANUAL":
        if sandbox_guid:
            return f"{base_analysis_center}#AnalyzeAppManualList:{app_guid}:{sandbox_guid}"
        else:
            return f"{base_analysis_center}#AnalyzeAppManualList:{app_guid}:"
    
    elif scan_type == "SCA":
        if finding_details:
            metadata = finding_details.get("metadata", {})
            sca_scan_mode = metadata.get("sca_scan_mode", "").upper()
            
            if sca_scan_mode == "AGENT":
                workspace_guid = (finding_details.get("workspace_guid") or 
                                finding_details.get("workspace_id") or
                                metadata.get("workspace_guid") or
                                metadata.get("workspace_id"))
                
                project_id = (finding_details.get("project_id") or
                            metadata.get("project_id"))
                
                if finding_obj:
                    if not workspace_guid:
                        workspace_guid = finding_obj.get("_sca_workspace_guid") or finding_obj.get("workspace_guid") or finding_obj.get("workspace_id")
                    if not project_id:
                        project_id = finding_obj.get("_sca_project_id") or finding_obj.get("project_id")
                
                if workspace_guid and project_id:
                    return f"https://sca.analysiscenter.veracode.com/workspaces/{workspace_guid}/projects/{project_id}/issues"
                else:
                    return "https://sca.analysiscenter.veracode.com/workspaces"
            
            scan_params = None
            if finding_obj:
                scan_params = finding_obj.get("_latest_scan_params")
            
            if scan_params and app_oid and app_id:
                return f"{base_analysis_center}#ReviewResultsSCA:{app_oid}:{app_id}:{scan_params}"
            elif app_oid and app_id:
                return f"{base_analysis_center}#AnalyzeAppSourceComposition:{app_oid}:{app_id}:"
            else:
                if sandbox_guid:
                    return f"{base_analysis_center}#AnalyzeAppSourceComposition:{app_guid}:{sandbox_guid}"
                else:
                    return f"{base_analysis_center}#AnalyzeAppSourceComposition:{app_guid}:"
    
    return f"{base_analysis_center}#AnalyzeAppModuleList:{app_guid}:"


def normalize_finding(finding):
    """Extract and normalize required fields from a finding record."""
    app_name = finding.get("_app_name")
    app_guid = finding.get("_app_guid")
    app_profile = finding.get("_app_profile", {})
    sandbox_name = finding.get("_sandbox_name")
    scan_type = finding.get("scan_type")
    original_scan_type = scan_type
    description = finding.get("description")
    
    finding_details = finding.get("finding_details", {})
    if scan_type == "SCA":
        metadata = finding_details.get("metadata", {})
        if metadata.get("sca_scan_mode") == "AGENT":
            scan_type = "SCA Agent"
    elif scan_type == "DYNAMIC":
        # Differentiate between Dynamic Analysis and DAST
        if finding.get("_da_analysis_id"):
            scan_type = "Dynamic Analysis"
        elif finding.get("_dynamic_scan_url"):
            scan_type = "DAST"

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
        fixed_date = (
            finding_status_obj.get("resolution_date")
            or finding_status_obj.get("last_seen_date")
        )

    cwe_id = extract_cwe_id(finding_details)
    flaw_name = extract_cwe_name(finding_details)
    cve_id = extract_cve_id(finding_details)
    cvss = extract_cvss(finding_details)
    filename = extract_filename(finding_details, original_scan_type)
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
    
    sandbox_guid = finding.get("_sandbox_guid")
    app_id = finding.get("_app_id")
    app_oid = finding.get("_app_oid")
    veracode_link = generate_veracode_link(app_guid, original_scan_type, finding_details, sandbox_guid, finding_obj=finding, app_id=app_id, app_oid=app_oid)
    
    clean_description = strip_html(description)
    
    if scan_type == "SCA":
        vuln_title = cve_id if cve_id else flaw_name
    elif scan_type == "DYNAMIC" or scan_type == "MANUAL":
        vuln_title = flaw_name
    else:
        vuln_title = None

    return {
        "Application Name": app_name,
        "Application ID": app_guid,
        "Veracode Link": veracode_link,
        "Sandbox Name": sandbox_name,
        "Custom Severity Name": custom_severity,
        "CVE ID": cve_id,
        "Description": clean_description,
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

    include_sandboxes = args.include_sandbox

    print("\n" + "=" * 70)
    print("  VERACODE FINDINGS API EXPORT")
    print("=" * 70)
    print(f"  Output File      : {args.output}")
    print(f"  Include Sandboxes: {include_sandboxes}")
    if args.app_name:
        print(f"  Filter App Name  : {args.app_name}")
    if args.app_guid:
        print(f"  Filter App GUID  : {args.app_guid}")
    if args.scan_type:
        print(f"  Filter Scan Type : {args.scan_type}")
    if args.severity is not None:
        print(f"  Filter Severity  : {args.severity}")
    if args.severity_gte is not None:
        print(f"  Filter Sev >=    : {args.severity_gte}")
    if args.cwe:
        print(f"  Filter CWE       : {args.cwe}")
    if args.status:
        print(f"  Filter Status    : {args.status}")
    print("=" * 70 + "\n")

    session = requests.Session()

    # Fetch SCA workspace/project mappings for agent-based SCA links
    print("\n" + "=" * 70)
    print("  FETCHING SCA WORKSPACE MAPPINGS")
    print("=" * 70)
    sca_workspace_map = get_sca_workspaces(session, args.sleep)
    if sca_workspace_map:
        print(f"  Found {len(sca_workspace_map)} SCA projects")
        # Show a few sample project names for debugging
        sample_projects = list(sca_workspace_map.keys())[:5]
        if sample_projects:
            print(f"  Sample project names: {', '.join(sample_projects)}")
    else:
        print("  No SCA projects found or unable to fetch")
    print("=" * 70 + "\n")

    # Fetch Dynamic Analysis analyses for linking
    print("\n" + "=" * 70)
    print("  FETCHING DYNAMIC ANALYSIS MAPPINGS")
    print("=" * 70)
    dynamic_analyses_map = get_dynamic_analyses(session, args.sleep)
    if dynamic_analyses_map:
        total_analyses = sum(len(analyses) for analyses in dynamic_analyses_map.values())
        print(f"  Found {total_analyses} Dynamic Analysis analyses across {len(dynamic_analyses_map)} applications")
    else:
        print("  No Dynamic Analysis analyses found or unable to fetch")
    print("=" * 70 + "\n")

    filters = {}
    if args.scan_type:
        filters["scan_type"] = args.scan_type
    if args.severity is not None:
        filters["severity"] = args.severity
    if args.severity_gte is not None:
        filters["severity_gte"] = args.severity_gte
    if args.cwe:
        filters["cwe"] = args.cwe
    if args.status:
        filters["status"] = args.status

    if args.app_guid:
        # Fetch the specific application details
        print(f"Fetching application details for GUID: {args.app_guid}\n")
        resp = session.get(
            f"{APPLICATIONS_URL}/{args.app_guid}",
            auth=RequestsAuthPluginVeracodeHMAC(),
            timeout=60,
        )
        if resp.status_code == 200:
            applications = [resp.json()]
        else:
            print(f"ERROR: Could not fetch application (status {resp.status_code})")
            print(f"Response: {resp.text}")
            return
    else:
        applications = get_applications(session, args.sleep)

        if args.app_name:
            applications = [
                app for app in applications
                if args.app_name.lower() in app.get("profile", {}).get("name", "").lower()
            ]
            print(f"Filtered to {len(applications)} applications matching '{args.app_name}'\n")

        if args.max_apps:
            applications = applications[: args.max_apps]
            print(f"Limited to {args.max_apps} applications (for testing)\n")

    print("\n" + "=" * 70)
    print("  FETCHING FINDINGS FROM APPLICATIONS")
    print("=" * 70 + "\n")

    all_findings = []
    apps_with_findings = 0

    for idx, app in enumerate(applications, start=1):
        app_guid = app.get("guid")
        app_profile = app.get("profile", {})
        app_name = app_profile.get("name", "Unknown")
        app_id = app.get("id")
        app_oid = app.get("oid") or app.get("alt_org_id")
        
        # Map build_id to full scan parameters for accurate SAST linking
        scan_params_by_build = {}
        dynamic_scan_params_by_build = {}
        scans = app.get("scans", [])
        for scan in scans:
            scan_url = scan.get("scan_url", "")
            if not scan_url:
                continue
                
            if scan.get("scan_type") == "STATIC":
                if scan_url:
                    parts = scan_url.split(":")
                    if len(parts) >= 4:
                        try:
                            scan_build_id = int(parts[3])
                            full_params = ":".join(parts[3:])
                            scan_params_by_build[scan_build_id] = full_params
                        except (ValueError, IndexError):
                            pass
            
            elif scan.get("scan_type") == "DYNAMIC":
                # Parse DAST scan URL format: DynamicParamsView:oid:app_id:build_id:unknown::scan_id
                if scan_url.startswith("DynamicParamsView:"):
                    parts = scan_url.split(":")
                    if len(parts) >= 4:
                        try:
                            scan_build_id = int(parts[3])
                            # Store the full scan URL for DAST
                            dynamic_scan_params_by_build[scan_build_id] = scan_url
                        except (ValueError, IndexError):
                            pass
        
        # Get latest STATIC scan params for SCA fallback
        latest_static_build_id = None
        latest_scan_params = None
        for scan in scans:
            if scan.get("scan_type") == "STATIC":
                scan_url = scan.get("scan_url", "")
                if scan_url:
                    parts = scan_url.split(":")
                    if len(parts) >= 4:
                        try:
                            latest_static_build_id = int(parts[3])
                            latest_scan_params = ":".join(parts[3:])
                            break
                        except (ValueError, IndexError):
                            pass

        print(f"  [{idx}/{len(applications)}] {app_name}")
        print(f"    GUID: {app_guid}")

        findings = get_all_findings_for_app(
            session=session,
            app_guid=app_guid,
            app_name=app_name,
            app_profile=app_profile,
            filters=filters,
            sleep_time=args.sleep,
            include_sandboxes=include_sandboxes,
            app_id=app_id,
            app_oid=app_oid,
        )
        
        for finding in findings:
            finding["_latest_static_build_id"] = latest_static_build_id
            finding["_latest_scan_params"] = latest_scan_params
            finding["_scan_params_by_build"] = scan_params_by_build
            finding["_dynamic_scan_params_by_build"] = dynamic_scan_params_by_build
            
            # For STATIC findings, lookup full params by build_id
            if finding.get("scan_type") == "STATIC":
                finding_build_id = finding.get("build_id")
                if finding_build_id and finding_build_id in scan_params_by_build:
                    finding["_finding_scan_params"] = scan_params_by_build[finding_build_id]
            
            # For DYNAMIC findings, lookup DAST scan URL by build_id
            elif finding.get("scan_type") == "DYNAMIC":
                finding_build_id = finding.get("build_id")
                if finding_build_id and finding_build_id in dynamic_scan_params_by_build:
                    finding["_dynamic_scan_url"] = dynamic_scan_params_by_build[finding_build_id]

            # Map agent-based SCA to workspace/project (exact GUID match only)
            if finding.get("scan_type") == "SCA":
                metadata = finding.get("finding_details", {}).get("metadata", {})
                if metadata.get("sca_scan_mode") == "AGENT":
                    guid_key = f"guid:{app_guid}"
                    if guid_key in sca_workspace_map:
                        mapping = sca_workspace_map[guid_key]
                        finding["_sca_workspace_guid"] = mapping["workspace_guid"]
                        finding["_sca_project_id"] = mapping["project_id"]
            
            # Map Dynamic findings to Dynamic Analysis
            if finding.get("scan_type") == "DYNAMIC":
                if app_guid in dynamic_analyses_map:
                    da_analyses = dynamic_analyses_map[app_guid]
                    if da_analyses:
                        # Use the first/latest analysis for this app
                        da_info = da_analyses[0]
                        finding["_da_analysis_id"] = da_info.get("analysis_id")
                        finding["_da_analysis_name"] = da_info.get("analysis_name")
                        finding["_da_scan_id"] = da_info.get("scan_id")
                        finding["_da_scan_type"] = da_info.get("scan_type")
                        finding["_da_occurrence_id"] = da_info.get("latest_occurrence_id")

        if findings:
            all_findings.extend(findings)
            apps_with_findings += 1
            print(f"    ✓ Total findings for this app: {len(findings)}\n")
        else:
            print(f"    ✗ No findings\n")

    print("\n" + "=" * 70)
    print("  SAVING RESULTS")
    print("=" * 70)

    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_file = f"veracode_findings_api_raw_{timestamp}.json"
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(all_findings, f, indent=2)
    print(f"  Raw JSON: {json_file} ({len(all_findings)} findings)")

    if all_findings:
        normalized_findings = [normalize_finding(f) for f in all_findings]

        fieldnames = [
            "Application Name",
            "Application ID",
            "Veracode Link",
            "Sandbox Name",
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
    print(f"  Applications processed    : {len(applications)}")
    print(f"  Applications with findings: {apps_with_findings}")
    print(f"  Total findings            : {len(all_findings)}")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
