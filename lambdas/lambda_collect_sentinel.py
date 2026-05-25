import boto3
import json
import requests
from datetime import datetime, timezone
import logging
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------
def get_secrets():
    """
    Retrieve Azure AD credentials and Log Analytics workspace ID
    from Secrets Manager.
 
    Expected keys:
      client_id     — Azure AD application (service principal) ID
      client_secret — Azure AD application secret
      tenant_id     — Azure AD tenant (organisation) ID
      workspace_id  — Log Analytics workspace to query
    """
    client = boto3.client('secretsmanager')
    secret = client.get_secret_value(SecretId='security-pipeline/sentinel')
    return json.loads(secret['SecretString'])
 
# ---------------------------------------------------------------------------
# Azure AD — bearer token
# ---------------------------------------------------------------------------
def get_bearer_token(tenant_id, client_id, client_secret):
    """
    Exchange client credentials for a bearer token from Azure AD.
 
    Why form-encoded and not JSON:
      The OAuth2 token endpoint is a standards-based endpoint that
      expects application/x-www-form-urlencoded. Sending JSON returns
      a 400 Bad Request. This is different from the Log Analytics query
      endpoint which expects JSON.
 
    Why this specific scope:
      The scope tells Azure AD which API we want access to.
      https://api.loganalytics.io/.default = Log Analytics API access.
      Wrong scope = token works for auth but returns 403 on the actual query.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
 
    body = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://api.loganalytics.io/.default"
        # scope points to Log Analytics — not management.azure.com
        # Defender Lambda uses a different scope for a different API
    }
 
    # data= sends form-encoded. json= would send JSON and cause a 400 error.
    response = requests.post(url, data=body, timeout=30)
    response.raise_for_status()
 
    return response.json()["access_token"]
 
# ---------------------------------------------------------------------------
# Log Analytics — KQL query
# ---------------------------------------------------------------------------
def query_sentinel(workspace_id, token):
    """
    Query the Log Analytics workspace for Sentinel security alerts
    from the last 24 hours.
 
    Why Log Analytics and not a Sentinel API directly:
      Sentinel has no separate query API. It stores all data (alerts,
      incidents, logs) inside a Log Analytics workspace. You query
      Log Analytics to get Sentinel data.
 
    Why AlertSeverity and not Severity:
      Sentinel findings have both fields. AlertSeverity reliably contains
      High/Medium/Low/Critical across all alert providers. The Severity
      field is inconsistent depending on which provider generated the alert.
 
    Why StartTime and EndTime:
      StartTime = when the threat activity actually began.
      TimeGenerated = when Sentinel detected and logged it.
      MTTD = TimeGenerated - StartTime.
      Without both fields we cannot calculate detection delay.
    """
    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
 
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
        # Content-Type is required — tells the API the body is JSON
    }
 
    kql_query = """
    SecurityAlert
    | where TimeGenerated >= ago(24h)
    | project
        SystemAlertId,
        AlertName,
        AlertSeverity,
        TimeGenerated,
        Status,
        ProviderName,
        StartTime,
        EndTime
    """
    # SecurityAlert is the Log Analytics table where Sentinel writes all alerts
    # ago(24h) filters at Azure side — we only receive last 24h, no chunking needed
    # | project = SELECT in SQL — only return the columns we actually need
 
    body = {"query": kql_query}
 
    # json= sends JSON body — correct for Log Analytics API
    response = requests.post(url, headers=headers, json=body, timeout=60)
    response.raise_for_status()
 
    return parse_log_analytics_response(response.json())
 
# ---------------------------------------------------------------------------
# Parse Log Analytics response format
# ---------------------------------------------------------------------------
def parse_log_analytics_response(response_data):
    """
    Log Analytics does not return a simple list of dicts.
    It returns rows and columns separately:
 
    {
      "tables": [{
        "columns": [{"name": "SystemAlertId"}, {"name": "AlertName"}, ...],
        "rows":    [["id-123", "Brute Force", ...], ["id-456", "Malware", ...]]
      }]
    }
 
    We zip each row with the column names to produce a list of dicts.
    dict(zip(columns, row)) pairs column name with value at the same index.
 
    This same function is reused in the Defender Lambda because
    Azure Resource Graph returns the same rows/columns format.
    """
    results = []
    table   = response_data["tables"][0]
 
    # Build ordered list of column names
    columns = [col["name"] for col in table["columns"]]
 
    # Zip each row with column names → one dict per alert
    for row in table["rows"]:
        alert = dict(zip(columns, row))
        results.append(alert)
 
    logger.info(f"Parsed {len(results)} alerts from Log Analytics response")
    return results
 
# ---------------------------------------------------------------------------
# S3 — save results
# ---------------------------------------------------------------------------
def save_to_s3(alerts, bucket, date_str):
    """
    Write all alerts to a single S3 file.
 
    Why no chunking (unlike Wiz Lambda):
      Sentinel returns last 24h of alerts only — typically 50-200 records.
      Wiz returns the entire vulnerability database (10,000+ records).
      50-200 records fits easily in Lambda memory. One S3 write is sufficient.
 
    S3 path uses year/month/day partitioning so AWS Athena can query
    historical data efficiently without scanning the entire bucket.
    """
    s3 = boto3.client('s3')
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    key = f"raw/{year}/{month}/{day}/sentinel/alerts.json"
 
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(alerts),
        ContentType='application/json'
    )
    logger.info(f"Saved {len(alerts)} Sentinel alerts to s3://{bucket}/{key}")
 
# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    try:
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        bucket   = event['bucket']
 
        # 1. Get credentials from Secrets Manager
        secrets = get_secrets()
 
        # 2. Get bearer token from Azure AD
        #    Uses Log Analytics scope — different from Defender Lambda
        token = get_bearer_token(
            secrets['tenant_id'],
            secrets['client_id'],
            secrets['client_secret']
        )
        logger.info("Bearer token obtained from Azure AD")
 
        # 3. Query Log Analytics for Sentinel alerts
        alerts = query_sentinel(secrets['workspace_id'], token)
        logger.info(f"Retrieved {len(alerts)} alerts from Sentinel")
 
        # 4. Save to S3
        save_to_s3(alerts, bucket, date_str)
 
        year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
        return {
            "source":      "sentinel",
            "status":      "success",
            "alert_count": len(alerts),
            "date":        date_str,
            "s3_key":      f"raw/{year}/{month}/{day}/sentinel/alerts.json"
        }
 
    except Exception as e:
        logger.error(f"Sentinel Lambda failed: {str(e)}")
        raise  # Re-raise so Step Functions Catch block triggers SNS notification
 
