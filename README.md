# Veracode Findings API Export

A Python script to export vulnerability findings from Veracode using the **Findings REST API**. This script iterates through all applications in your Veracode account and retrieves findings for each application.

## Overview

This script uses the Veracode Findings API to export vulnerability findings:
- **Real-time data** - gets the latest findings status directly from the platform
- **Flexible filtering** - supports filtering by scan type, severity, CWE, and more
- **Comprehensive coverage** - exports STATIC, DYNAMIC, MANUAL, and SCA findings

## Prerequisites

### 1. Veracode API Credentials

You need Veracode API credentials configured on your system. The script uses HMAC authentication.

**Required Veracode Roles:**

Before you can use the Findings API, you must have one of these account configurations:
- **API Service Account** with the **Results API** role
- **User Account** with one of these roles:
  - **Reviewer**
  - **Security Lead**

**Credential Setup:**

Create a Veracode API credentials file at:
- **Windows:** `C:\Users\<username>\.veracode\credentials`
- **Mac/Linux:** `~/.veracode/credentials`

File format:
```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

Alternatively, set environment variables:
```bash
export VERACODE_API_KEY_ID=your_key_id
export VERACODE_API_KEY_SECRET=your_key_secret
```

### 2. Python Requirements

- Python 3.7 or higher
- Required packages:
  ```
  requests
  veracode-api-signing
  ```

## Installation

1. Clone or download this repository

2. Install required Python packages:
   ```bash
   pip install requests veracode-api-signing
   ```

3. Verify your Veracode credentials are configured (see Prerequisites above)

## Usage

### Basic Usage

Export all findings from all applications:
```bash
python findings_api_export.py
```

### Filter by Application

Export findings from a specific application:
```bash
# By application name (partial match)
python findings_api_export.py --app-name "MyApp"

# By application GUID
python findings_api_export.py --app-guid "12345678-1234-1234-1234-123456789abc"
```

### Filter by Scan Type

Export only specific scan types:
```bash
# Single scan type
python findings_api_export.py --scan-type STATIC

# Multiple scan types (comma-separated)
python findings_api_export.py --scan-type STATIC,SCA
```

### Filter by Severity

```bash
# Exact severity (0-5)
python findings_api_export.py --severity 5

# Severity greater than or equal to (0-5)
python findings_api_export.py --severity-gte 4
```

### Filter by CWE

```bash
# Single CWE
python findings_api_export.py --cwe 79

# Multiple CWEs (comma-separated)
python findings_api_export.py --cwe 79,89,22
```

### Combined Filters

```bash
python findings_api_export.py \
  --scan-type STATIC,SCA \
  --severity-gte 4 \
  --output high_severity_findings.csv
```

### Testing Mode

Limit the number of applications processed (useful for testing):
```bash
python findings_api_export.py --max-apps 5
```

## Command-Line Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `--output` | String | `veracode_findings_api.csv` | Output CSV filename. |
| `--app-name` | String | None | Filter by application name (partial match, case-insensitive). |
| `--app-guid` | String | None | Filter by specific application GUID. |
| `--scan-type` | String | None | Filter by scan type: STATIC, DYNAMIC, MANUAL, SCA (comma-separated). |
| `--severity` | Integer | None | Filter by exact severity (0-5). |
| `--severity-gte` | Integer | None | Filter by severity >= value (0-5). |
| `--cwe` | String | None | Filter by CWE ID (single or comma-separated). |
| `--sleep` | Float | `0.5` | Sleep time in seconds between API calls. |
| `--max-apps` | Integer | None | Limit number of applications to process (for testing). |

## Output Files

The script generates two output files:

### 1. CSV File (Normalized)
**Default:** `veracode_findings_api.csv`

Contains normalized findings data with the following columns:
- Application Name
- Application ID (GUID)
- Custom Severity Name (Very High, High, Medium, Low, Very Low, Informational)
- CVE ID (for SCA findings)
- Description
- Vulnerability Title (truncated description)
- CWE ID
- Flaw Name (CWE name/category)
- First Found Date
- Filename/Class (varies by scan type)
- Finding Status (OPEN, CLOSED)
- Fixed Date (approximated from last_seen_date if closed)
- Team Name (from Applications API: business_unit.name or first team name)
- Days to Resolve (calculated if fixed)
- Scan Type (STATIC, DYNAMIC, MANUAL, SCA)
- CVSS (score)
- Severity (0-5)
- Resolution Status
- Resolution

### 2. JSON File (Raw)
**Format:** `veracode_findings_api_raw_<timestamp>.json`

Contains the raw findings data from the API for debugging purposes.

## How It Works

1. **Fetch Applications**: Retrieves all applications from your Veracode account using pagination
2. **Filter Applications**: Optionally filters by application name or GUID
3. **Iterate Applications**: For each application:
   - Fetches findings using the Findings API endpoint
   - Handles pagination (up to 500 findings per page)
   - Applies optional filters (scan type, severity, CWE)
4. **Normalize Data**: Extracts and standardizes fields across different scan types
5. **Calculate Metrics**: Computes days to resolve for fixed findings
6. **Export**: Saves normalized data to CSV and raw data to JSON

## Data Sources

The script combines data from two Veracode REST APIs:
- **Applications API** - Provides application metadata (name, GUID, team/business unit)
- **Findings API** - Provides vulnerability findings and details

## Severity Mapping

The script maps Veracode severity levels to custom severity names:

| Severity | Custom Severity Name |
|----------|---------------------|
| 5 | Very High |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1 | Very Low |
| 0 | Informational |

## Field Extraction by Scan Type

### STATIC Analysis
- **Filename/Class**: `file_name` or `file_path`
- **CWE**: From `finding_details.cwe`
- **Location**: `file_line_number`, `module`, `procedure`

### DYNAMIC Analysis
- **Filename/Class**: `path` or `URL`
- **CWE**: From `finding_details.cwe`
- **Location**: `hostname`, `port`, `vulnerable_parameter`

### MANUAL Testing
- **Filename/Class**: `location` or `module`
- **CWE**: From `finding_details.cwe`
- **Location**: `input_vector`, `capec_id`

### SCA (Software Composition Analysis)
- **Filename/Class**: `component_filename` or `version`
- **CVE**: From `finding_details.cve.name`
- **CWE**: From `finding_details.cwe`
- **CVSS**: Prefers CVSS v3 over v2
- **Component**: `component_id`, `product_id`, `component_path`

## Example Output

### Console Output
```
======================================================================
  VERACODE FINDINGS API EXPORT
======================================================================
  Output File: veracode_findings_api.csv
======================================================================


======================================================================
  FETCHING APPLICATIONS
======================================================================
  Fetching applications page 0...
  Page 0: 50 applications (Total: 50)
  Fetching applications page 1...
  Page 1: 23 applications (Total: 73)

  Total applications found: 73


======================================================================
  FETCHING FINDINGS FROM APPLICATIONS
======================================================================

  [1/73] MyWebApp
    GUID: 12345678-1234-1234-1234-123456789abc
    Page 0: 248 findings
    Page 1: 152 findings (Total: 400)
    ✓ Total: 400 findings

  [2/73] MobileApp
    GUID: 87654321-4321-4321-4321-cba987654321
    Page 0: 87 findings
    ✓ Total: 87 findings

  [3/73] LegacyApp
    GUID: abcdef12-3456-7890-abcd-ef1234567890
    ✗ No findings

...

======================================================================
  SAVING RESULTS
======================================================================
  Raw JSON: veracode_findings_api_raw_20250209_153045.json (1487 findings)
  CSV File: veracode_findings_api.csv (1487 findings)

======================================================================
  EXPORT COMPLETED
======================================================================
  Applications processed: 73
  Applications with findings: 45
  Total findings: 1487
======================================================================
```

## Limitations

### Data Availability

1. **Fixed Date is Approximated**
   - The Findings API doesn't provide an explicit "fixed date"
   - For closed findings, the script uses `last_seen_date` as an approximation
   - This may not reflect the actual remediation date

2. **Historical Data**
   - Only returns current findings in the platform
   - Does not include findings that were deleted or aged out

### Performance Considerations

- **Application-by-application processing**: Makes one API call per application
- **Rate Limiting**: Default 0.5s sleep between calls to avoid rate limits
- **Large Portfolios**: May take 10-30 minutes for accounts with 100+ applications
- **Pagination overhead**: Each application may require multiple API calls if it has many findings

## Troubleshooting

### Authentication Errors

**Error:** `401 Unauthorized` or `403 Forbidden`

**Solutions:**
- Verify your API credentials file is correctly formatted
- Ensure your Veracode user/service account has the required roles (Results API or Reviewer)
- Check that credentials have not expired

### No Applications Returned

**Issue:** Script shows 0 applications

**Solutions:**
- Verify your user has access to applications in the Veracode platform
- Check that you're using the correct API region (US, EU, or Federal)
- Ensure your user role has permission to view applications

### 404 Errors for Specific Applications

**Issue:** Some applications return 404 when fetching findings

**Solutions:**
- Application may not have any scans yet
- Application may have been deleted or archived
- Your user may not have permission to view findings for that application
- This is normal - the script will continue to the next application

### Rate Limit Errors (429)

**Error:** `429 Too Many Requests`

**Solutions:**
- Increase `--sleep` value (e.g., `--sleep 1.0` or `--sleep 2.0`)
- Avoid running multiple instances of the script simultaneously
- If persistent, contact Veracode support about your rate limits

### Incomplete Data in CSV

**Issue:** Some fields are empty or null

**Solutions:**
- **Fixed Date**: Only approximated for closed findings
- **CVE ID**: Only available for SCA findings
- **CWE/Severity**: Should always be present - check raw JSON if missing
- **Team Name**: May be null if not configured in the application profile

## Veracode API Documentation

For more information about the Veracode Findings API:
- [Veracode Findings API Documentation](https://docs.veracode.com/r/c_findings_v2_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)
- [Applications API](https://docs.veracode.com/r/c_apps_intro)

## License

This script is provided as-is for use with Veracode's API. Ensure compliance with your Veracode license agreement.

## Support

For issues with:
- **This script**: Open an issue in this repository
- **Veracode API**: Contact Veracode Support at support@veracode.com
- **API credentials or roles**: Contact your Veracode Administrator
