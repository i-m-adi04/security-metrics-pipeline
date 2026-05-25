import boto3
import json
from datetime import datetime, timezone
import logging
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
# ---------------------------------------------------------------------------
# Why no Secrets Manager in this Lambda
# ---------------------------------------------------------------------------
# Security Hub is an AWS service. This Lambda runs inside AWS with an
# IAM execution role attached. AWS automatically authenticates boto3
# using that role — no credentials needed anywhere in the code.
#
# AWS equivalent mental model:
#   An EC2 instance with an IAM role attached never needs
#   aws_access_key_id in its code. Same principle here.
#
# Sentinel and Defender Lambdas need Secrets Manager because they call
# external Azure APIs that don't know about AWS IAM.
# ---------------------------------------------------------------------------
 
# ---------------------------------------------------------------------------
# Collect findings using boto3 paginator
# ---------------------------------------------------------------------------
def collect_security_hub_findings():
    """
    Retrieve all active Security Hub findings from the last 24 hours.
 
    Why boto3 paginator and not a manual loop:
      Security Hub returns max 100 findings per API call. If there are
      800 findings, that is 8 separate API calls needed. Without a
      paginator you must manually track NextToken and loop yourself.
      The boto3 paginator handles NextToken internally — you just
      iterate over pages. Half the code, no risk of missing a page.
 
    Why RecordState ACTIVE filter:
      Security Hub keeps closed and suppressed findings forever in its
      database. Without this filter you retrieve every finding ever
      recorded, not just current active issues. The CISO would see
      5,000 findings when only 200 are actually active and need attention.
 
    Why CreatedAt filter for last 24 hours:
      We only want findings created today. Historical findings are
      already in S3 from previous pipeline runs. Collecting them again
      would duplicate data and inflate all metrics.
    """
    client = boto3.client('securityhub')
 
    today_start = datetime.now(timezone.utc).strftime('%Y-%m-%dT00:00:00Z')
    today_end   = datetime.now(timezone.utc).strftime('%Y-%m-%dT23:59:59Z')
 
    filters = {
        "CreatedAt": [{
            "Start":     today_start,
            "End":       today_end,
            "DateRange": {"Value": 1, "Unit": "DAYS"}
        }],
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]
    }
 
    paginator    = client.get_paginator('get_findings')
    all_findings = []
 
    for page in paginator.paginate(Filters=filters):
        # extend not append — adds each finding individually into the flat list
        # append would add the entire page as one item, creating a list of lists
        all_findings.extend(page['Findings'])
        logger.info(f"Collected {len(all_findings)} findings so far...")
 
    logger.info(f"Total findings collected: {len(all_findings)}")
    return all_findings
 
# ---------------------------------------------------------------------------
# Extract only the fields we need
# ---------------------------------------------------------------------------
def extract_fields(findings):
    """
    Security Hub findings have 50+ fields per record. We only need
    the fields required to calculate our 6 metrics. Extracting only
    what we need keeps S3 file sizes small and speeds up the
    Aggregation Lambda which reads and processes this data.
 
    Field mapping and why each is needed:
 
      id              — unique finding ID, needed to match findings
                        across days when calculating MTTR
      severity        — Severity.Label contains HIGH/CRITICAL/MEDIUM/LOW
                        needed for critical+high count metric
      created_at      — when the finding was first created in Security Hub
                        used as the start time for MTTR calculation
      first_observed  — FirstObservedAt = when threat activity was first seen
                        used as the start time for MTTD calculation
                        different from created_at — the tool may take time
                        to process and log an event after it is observed
      updated_at      — last time this finding was modified
                        used as resolved_at only when workflow_state = RESOLVED
      workflow_state  — WorkflowState.Status = NEW / NOTIFIED / RESOLVED
                        tells us whether this finding has been resolved
      record_state    — ACTIVE or ARCHIVED — finding's overall state
      product_name    — which tool generated this finding
                        Security Hub aggregates GuardDuty, Inspector, Macie
                        the Aggregation Lambda needs to know the sub-source
      resource_type   — what kind of AWS resource had the finding
                        EC2, S3, IAM etc — used in top-10 category metric
 
    Why .get() instead of direct key access:
      Security Hub findings are not always consistent. Older findings
      may be missing some fields. .get() returns None on missing fields
      instead of raising a KeyError and crashing the entire Lambda.
 
    Why nested .get() for Severity and WorkflowState:
      These are nested dicts. finding.get('Severity', {}).get('Label')
      means: if Severity is missing, use an empty dict as default so
      the second .get() does not crash on NoneType.
    """
    extracted = []
 
    for finding in findings:
        extracted.append({
            "id": finding.get('Id'),
            "title": finding.get('Title'),
 
            # Severity is a nested dict: {"Label": "HIGH", "Normalized": 70}
            "severity": finding.get('Severity', {}).get('Label'),
 
            # Timestamps — all in ISO 8601 format
            "created_at":     finding.get('CreatedAt'),
            "first_observed": finding.get('FirstObservedAt'),
            "updated_at":     finding.get('UpdatedAt'),
 
            # WorkflowState is a nested dict: {"Status": "RESOLVED"}
            # Only treat updated_at as resolved_at when status is RESOLVED
            # updated_at changes on every modification — comments, status
            # changes, reassignments — not just resolution. Using it
            # unconditionally as resolved_at would give wrong MTTR values.
            "workflow_state": finding.get('WorkflowState', {}).get('Status'),
            "record_state":   finding.get('RecordState'),
 
            # Source identification
            "product_name": finding.get('ProductName'),
 
            # Resources is a list — take the first resource's type
            # Default [{}] ensures [0] never crashes on an empty list
            "resource_type": finding.get('Resources', [{}])[0].get('Type')
        })
 
    logger.info(f"Extracted fields from {len(extracted)} findings")
    return extracted
 
# ---------------------------------------------------------------------------
# S3 — save results
# ---------------------------------------------------------------------------
def save_to_s3(findings, bucket, date_str):
    """
    Write all extracted findings to a single S3 file.
 
    Why no chunking (unlike Wiz Lambda):
      Security Hub is filtered to last 24 hours of active findings.
      Typical volume is 100-500 records — well within Lambda memory.
      Wiz returns the entire vulnerability database (10,000+ records)
      which requires chunking. Security Hub does not.
 
    S3 path partitioned by year/month/day for efficient Athena queries.
    """
    s3 = boto3.client('s3')
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    key = f"raw/{year}/{month}/{day}/securityhub/findings.json"
 
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(findings),
        ContentType='application/json'
    )
    logger.info(f"Saved {len(findings)} findings to s3://{bucket}/{key}")
 
# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    try:
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        bucket   = event['bucket']
 
        # 1. Collect findings via paginator — no credentials needed
        #    IAM execution role handles authentication automatically
        raw_findings = collect_security_hub_findings()
 
        # 2. Extract only the fields needed for metric calculation
        extracted_findings = extract_fields(raw_findings)
 
        # 3. Save to S3
        save_to_s3(extracted_findings, bucket, date_str)
 
        year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
        return {
            "source":        "securityhub",
            "status":        "success",
            "finding_count": len(extracted_findings),
            "date":          date_str,
            "s3_key":        f"raw/{year}/{month}/{day}/securityhub/findings.json"
        }
 
    except Exception as e:
        logger.error(f"Security Hub Lambda failed: {str(e)}")
        raise  # Re-raise so Step Functions Catch block triggers SNS notification
