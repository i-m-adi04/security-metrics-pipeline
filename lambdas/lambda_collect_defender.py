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
    Retrieve Azure AD credentials and subscription ID from Secrets Manager.
 
    Expected keys:
      client_id       — Azure AD application (service principal) ID
      client_secret   — Azure AD application secret
      tenant_id       — Azure AD tenant (organisation) ID
      subscription_id — Azure subscription to scan for security findings
 
    Why subscription_id and not workspace_id (like Sentinel Lambda):
      Sentinel queries a Log Analytics workspace — a specific logging
      container identified by workspace_id.
      Defender queries Azure Resource Graph — a database of every resource
      across an entire Azure subscription. The unit is the subscription,
      not a workspace. subscription_id is the Azure equivalent of an
      AWS Account ID.
    """
    client = boto3.client('secretsmanager')
    secret = client.get_secret_value(SecretId='security-pipeline/defender')
    return json.loads(secret['SecretString'])
 
# ---------------------------------------------------------------------------
# Azure AD — bearer token
# ---------------------------------------------------------------------------
def get_bearer_token(tenant_id, client_id, client_secret):
    """
    Exchange client credentials for a bearer token from Azure AD.
 
    Why the scope is different from Sentinel Lambda:
      Sentinel scope: https://api.loganalytics.io/.default
      Defender scope: https://management.azure.com/.default
 
      Same client_id, client_secret, and tenant_id — but the scope tells
      Azure AD which API we want access to. Different API = different scope
      = different token. A Sentinel token will be rejected by the
      Resource Graph API and vice versa.
 
    Why form-encoded and not JSON:
      OAuth2 token endpoints expect application/x-www-form-urlencoded.
      Sending JSON returns a 400 Bad Request. The query endpoint (below)
      uses JSON — the two endpoints have different content types.
    """
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
 
    body = {
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://management.azure.com/.default"
        # management.azure.com scope = access to Azure Resource Graph API
        # This is different from the Log Analytics scope used in Sentinel Lambda
    }
 
    # data= sends form-encoded — required for OAuth2 token endpoints
    response = requests.post(url, data=body, timeout=30)
    response.raise_for_status()
 
    return response.json()["access_token"]
 
# ---------------------------------------------------------------------------
# Azure Resource Graph — KQL query
# ---------------------------------------------------------------------------
def query_defender(subscription_id, token):
    """
    Query Azure Resource Graph for Defender for Cloud security assessments.
 
    Why Resource Graph and not Log Analytics (like Sentinel):
      Log Analytics stores time-series log data — events, alerts, incidents
      that happened over time. Good for: what threats occurred today.
 
      Resource Graph stores the current state of every Azure resource and
      its security posture. Good for: what is misconfigured or exposed
      right now across all resources.
 
      Defender for Cloud writes security recommendations and compliance
      assessments to Resource Graph — not Log Analytics. Querying the
      wrong API returns no Defender data at all.
 
    Why securityresources table:
      Resource Graph has many tables. securityresources is the specific
      table where Defender writes all security assessments.
      type == microsoft.security/assessments filters to Defender findings
      only — without this you get every Azure resource type in the table.
 
    Why status.code != Healthy:
      We only want problems. Healthy = resource is compliant, no action
      needed. Without this filter you receive thousands of passing checks
      alongside real findings — the CISO report becomes unreadable.
 
    Why the bearer token goes in the header and not the body:
      Azure REST APIs use Bearer token authentication in the Authorization
      header. The token proves identity. The body contains only the query.
      This is the same pattern as Sentinel Lambda — Authorization header
      is standard for all Azure APIs.
    """
    url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources"
 
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }
 
    kql_query = """
    securityresources
    | where type == "microsoft.security/assessments"
    | where properties.status.code != "Healthy"
    | project
        findingId   = id,
        resourceId  = properties.resourceDetails.id,
        severity    = properties.metadata.severity,
        displayName = properties.displayName,
        status      = properties.status.code,
        category    = properties.metadata.categories,
        createdAt   = properties.timeGenerated
    """
    # KQL syntax is the same as Sentinel — same language, different tables
    # | project renames columns using = syntax (aliasing)
    # properties.x accesses nested JSON fields within Resource Graph records
 
    body = {
        "subscriptions": [subscription_id],
        "query":         kql_query
    }
    # subscriptions is a list — supports querying multiple subscriptions
    # in one call if the organisation has dev/staging/prod subscriptions
 
    # json= sends JSON body — correct for Resource Graph API
    response = requests.post(url, headers=headers, json=body, timeout=60)
    response.raise_for_status()
 
    return parse_resource_graph_response(response.json())
 
# ---------------------------------------------------------------------------
# Parse Resource Graph response format
# ---------------------------------------------------------------------------
def parse_resource_graph_response(response_data):
    """
    Azure Resource Graph returns the same rows/columns format as
    Log Analytics — separate column definitions and row value arrays.
 
    {
      "data": {
        "columns": [{"name": "findingId"}, {"name": "severity"}, ...],
        "rows":    [["id-123", "High", ...], ["id-456", "Critical", ...]]
      }
    }
 
    We zip each row with column names to produce a list of dicts.
    This is the same logic as parse_log_analytics_response in Sentinel Lambda.
    Both Azure APIs return the same structure — write once, reuse the pattern.
    """
    results = []
 
    # Resource Graph wraps results in "data" not "tables"
    data    = response_data.get("data", {})
    columns = [col["name"] for col in data.get("columns", [])]
    rows    = data.get("rows", [])
 
    for row in rows:
        finding = dict(zip(columns, row))
        results.append(finding)
 
    logger.info(f"Parsed {len(results)} Defender findings from Resource Graph response")
    return results
 
# ---------------------------------------------------------------------------
# S3 — save results
# ---------------------------------------------------------------------------
def save_to_s3(findings, bucket, date_str):
    """
    Write all findings to a single S3 file.
 
    Why no chunking (unlike Wiz Lambda):
      Defender returns security recommendations and misconfigurations
      filtered to non-healthy resources only. Typical volume is
      100-1000 records per subscription — well within Lambda memory.
      No chunking or checkpointing needed.
 
    S3 path partitioned by year/month/day for efficient Athena queries.
    Consistent path structure across all four sources — the Aggregation
    Lambda knows exactly where to look for each source's data.
    """
    s3 = boto3.client('s3')
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    key = f"raw/{year}/{month}/{day}/defender/findings.json"
 
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(findings),
        ContentType='application/json'
    )
    logger.info(f"Saved {len(findings)} Defender findings to s3://{bucket}/{key}")
 
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
        #    Uses management.azure.com scope — different from Sentinel Lambda
        #    which uses api.loganalytics.io scope
        token = get_bearer_token(
            secrets['tenant_id'],
            secrets['client_id'],
            secrets['client_secret']
        )
        logger.info("Bearer token obtained from Azure AD")
 
        # 3. Query Azure Resource Graph for Defender findings
        findings = query_defender(secrets['subscription_id'], token)
        logger.info(f"Retrieved {len(findings)} findings from Defender for Cloud")
 
        # 4. Save to S3
        save_to_s3(findings, bucket, date_str)
 
        year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
        return {
            "source":        "defender",
            "status":        "success",
            "finding_count": len(findings),
            "date":          date_str,
            "s3_key":        f"raw/{year}/{month}/{day}/defender/findings.json"
        }
 
    except Exception as e:
        logger.error(f"Defender Lambda failed: {str(e)}")
        raise  # Re-raise so Step Functions Catch block triggers SNS notification
 
