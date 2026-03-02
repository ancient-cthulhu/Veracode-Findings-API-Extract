# Veracode Findings API Export

A Python script to export vulnerability findings from Veracode using the **Findings REST API**. Iterates through all applications in your Veracode account and retrieves findings for each one, with optional sandbox coverage.

## Prerequisites

### Veracode API Credentials

Requires HMAC authentication. Your account must have one of the following:

- **API Service Account** with the **Results API** role
- **User Account** with the **Reviewer** or **Security Lead** role

Create a credentials file at:

- **Windows:** `C:\Users\<username>\.veracode\credentials`
- **Mac/Linux:** `~/.veracode/credentials`

```ini
[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

Or set environment variables:

```bash
export VERACODE_API_KEY_ID=your_key_id
export VERACODE_API_KEY_SECRET=your_key_secret
```

### Python Requirements

- Python 3.7+
- `requests`
- `veracode-api-signing`

```bash
pip install requests veracode-api-signing
```

## Usage

### Export all findings (policy scans only)

```bash
python veracode_findings_export.py
```

### Include sandbox findings

```bash
python veracode_findings_export.py --include-sandbox
```

### Filter by application

```bash
python veracode_findings_export.py --app-name "MyApp"
python veracode_findings_export.py --app-guid "12345678-1234-1234-1234-123456789abc"
```

### Filter by scan type

```bash
python veracode_findings_export.py --scan-type STATIC
python veracode_findings_export.py --scan-type STATIC,DYNAMIC
```

> **Note:** SCA findings must be requested separately from other scan types. The script handles this automatically, if you include `SCA` in `--scan-type` alongside others, it will run two separate API passes and merge the results.

### Filter by severity

```bash
python veracode_findings_export.py --severity 5
python veracode_findings_export.py --severity-gte 3
```

### Filter by status

```bash
python veracode_findings_export.py --status OPEN
python veracode_findings_export.py --status CLOSED
```

### Filter by CWE

```bash
python veracode_findings_export.py --cwe 79
python veracode_findings_export.py --cwe 79,89,22
```

### Combined example

```bash
python veracode_findings_export.py \
  --scan-type STATIC \
  --severity-gte 4 \
  --status OPEN \
  --include-sandbox \
  --output high_severity_open.csv
```

## Command-Line Arguments

|Argument           |Default                    |Description                                                 |
|-------------------|---------------------------|------------------------------------------------------------|
|`--output`         |`veracode_findings_api.csv`|Output CSV filename                                         |
|`--app-name`       |None                       |Filter by application name (partial match, case-insensitive)|
|`--app-guid`       |None                       |Filter by specific application GUID                         |
|`--scan-type`      |None                       |STATIC, DYNAMIC, MANUAL, SCA or comma-separated combination |
|`--severity`       |None                       |Exact severity (0–5)                                        |
|`--severity-gte`   |None                       |Severity greater than or equal to (0–5)                     |
|`--cwe`            |None                       |CWE ID, single or comma-separated                           |
|`--status`         |None                       |`OPEN` or `CLOSED`                                          |
|`--include-sandbox`|False                      |Also fetch findings from all development sandboxes          |
|`--sleep`          |`0.5`                      |Seconds to sleep between API calls                          |
|`--max-apps`       |None                       |Cap number of apps to process (useful for testing)          |

## Output Files

### CSV - `veracode_findings_api.csv`

|Column              |Description                                                           |
|--------------------|----------------------------------------------------------------------|
|Application Name    |Application profile name                                              |
|Application ID      |Application GUID                                                      |
|Sandbox Name        |Sandbox name if finding is from a sandbox; blank for policy scan      |
|Custom Severity Name|Very High / High / Medium / Low / Very Low / Informational            |
|CVE ID              |CVE identifier (SCA findings only)                                    |
|Description         |Finding description                                                   |
|Vulnerability Title |First 100 characters of description                                   |
|CWE ID              |CWE numeric ID                                                        |
|Flaw Name           |CWE name or finding category                                          |
|First Found Date    |Date the finding was first observed                                   |
|Filename/Class      |File, path, URL, or component — varies by scan type                   |
|Finding Status      |`OPEN` or `CLOSED`                                                    |
|Fixed Date          |Resolution date; falls back to last seen date if not available        |
|Team Name           |Business unit name or first assigned team from the application profile|
|Days to Resolve     |Days between first found and fixed date                               |
|Scan Type           |STATIC, DYNAMIC, MANUAL, or SCA                                       |
|CVSS                |CVSS score (prefers v3 for SCA)                                       |
|Severity            |Numeric severity 0–5                                                  |
|Resolution Status   |Resolution status from the platform                                   |
|Resolution          |Resolution type                                                       |

### JSON — `veracode_findings_api_raw_<timestamp>.json`

Raw API response data for all findings, saved for debugging.

## How It Works

1. Fetches all application profiles via the Applications API (paginated)
1. For each application, runs findings API calls:
- **Policy scan** — always fetched (no `context` parameter)
- **Sandboxes** — fetched per sandbox using `?context={sandbox_guid}` if `--include-sandbox` is set
- **SCA** — always fetched in a dedicated separate pass, as required by the Veracode API
1. Normalizes fields across scan types and calculates derived values (e.g. days to resolve)
1. Writes results to CSV and raw JSON

## Severity Mapping

|Numeric|Label        |
|-------|-------------|
|5      |Very High    |
|4      |High         |
|3      |Medium       |
|2      |Low          |
|1      |Very Low     |
|0      |Informational|

## Troubleshooting

**401 / 403** — Check credentials file format and that your account has the Results API or Reviewer role.

**0 applications returned** — Verify your account has access to application profiles and you’re using the correct API region.

**404 on specific applications** — Normal; the app likely has no scans yet or your account lacks permission for that profile. The script skips and continues.

**429 Too Many Requests** — Increase `--sleep` (e.g. `--sleep 1.5`). Avoid running multiple instances simultaneously.

**Missing fields in CSV** — CVE ID is SCA-only. Sandbox Name is blank for policy scan findings. Fixed Date requires the finding to be CLOSED or FIXED.

## API References

- [Findings REST API](https://docs.veracode.com/r/c_findings_v2_intro)
- [Applications REST API](https://docs.veracode.com/r/c_apps_intro)
- [Development Sandbox REST API](https://docs.veracode.com/r/c_rest_sandbox_intro)
- [API Authentication](https://docs.veracode.com/r/t_install_api_authen)
