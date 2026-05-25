import boto3
import json
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal
import logging
  
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
s3       = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
 
# ---------------------------------------------------------------------------
# Step 1 — Check which sources arrived in S3
# ---------------------------------------------------------------------------
def s3_key_exists(bucket, key):
    """Check if an S3 file exists without downloading it."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:
        return False
 
 
def check_available_sources(bucket, date_str):
    """
    Check S3 to see which of the four collectors completed successfully.
 
    Returns a dict like:
      {"sentinel": True, "securityhub": True, "defender": False, "wiz": True}
 
    Why we check S3 and not the Step Functions execution result:
      Step Functions marks a branch as succeeded even when the collector
      failed gracefully (Type: Succeed in the Catch block). Checking S3
      directly tells us definitively whether data actually arrived.
 
    Wiz validation is all-or-nothing:
      Wiz chunks are validated differently from the other three sources.
      Single-file sources either exist or they don't — no partial state.
      Wiz can have partial data (some chunks written, others missing)
      which looks complete but produces wrong metrics. We check the
      manifest file and verify every chunk is present before accepting
      any Wiz data. If anything is missing, Wiz is excluded entirely.
 
    Why Wiz partial data is more dangerous than other partial data:
      Sentinel/Security Hub/Defender write one file. Either it is there
      (complete) or it is not (excluded). No in-between state possible.
      Wiz writes many chunk files. 15 of 23 chunks present looks like
      data but represents only 65% of findings. MTTR, critical counts,
      and remediation rate all become wrong in ways that are not obvious
      to the CISO reading the report.
    """
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    base = f"raw/{year}/{month}/{day}"
 
    available = {
        "sentinel":    False,
        "securityhub": False,
        "defender":    False,
        "wiz":         False
    }
 
    # Check single-file sources — simple existence check
    single_file_sources = {
        "sentinel":    f"{base}/sentinel/alerts.json",
        "securityhub": f"{base}/securityhub/findings.json",
        "defender":    f"{base}/defender/findings.json"
    }
 
    for source, key in single_file_sources.items():
        if s3_key_exists(bucket, key):
            available[source] = True
            logger.info(f"{source}: data found in S3")
        else:
            logger.warning(f"{source}: data NOT found in S3 — will be excluded")
 
    # Check Wiz — manifest first, then verify every chunk
    manifest_key = f"{base}/wiz/manifest.json"
    try:
        manifest_obj = s3.get_object(Bucket=bucket, Key=manifest_key)
        manifest     = json.loads(manifest_obj['Body'].read())
 
        if manifest.get('status') == 'complete':
            total_chunks = manifest['total_chunks']
            logger.info(f"Wiz manifest found — expecting {total_chunks} chunks")
 
            # Verify every single chunk is present
            all_chunks_present = all(
                s3_key_exists(bucket, f"{base}/wiz/chunk_{i:04d}.json")
                for i in range(total_chunks)
            )
 
            if all_chunks_present:
                available['wiz'] = True
                logger.info(f"Wiz: all {total_chunks} chunks verified — data accepted")
            else:
                logger.warning("Wiz: one or more chunks missing — excluding Wiz entirely")
        else:
            logger.warning("Wiz: manifest status is not complete — excluding Wiz entirely")
 
    except Exception:
        logger.warning("Wiz: manifest not found — excluding Wiz entirely")
 
    return available
 
# ---------------------------------------------------------------------------
# Step 2 — Load data from available sources
# ---------------------------------------------------------------------------
def load_source_data(bucket, date_str, available):
    """
    Load raw findings from S3 for all available sources.
 
    Why empty list and not None for unavailable sources:
      Every downstream function uses len() and loops over source data.
      An empty list works correctly — len([]) = 0, looping over [] = nothing.
      None would crash with TypeError on every len() and loop call.
      Empty list = no data. None = error. Always use empty list as default.
 
    Wiz loading combines all chunks into one flat list:
      Each chunk file is a list of findings. We extend (not append) the
      master list with each chunk. extend adds each finding individually.
      append would add the entire chunk as one item, creating a list of
      lists instead of a flat list of findings.
    """
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    base = f"raw/{year}/{month}/{day}"
    data = {}
 
    # Load single-file sources
    source_keys = {
        "sentinel":    f"{base}/sentinel/alerts.json",
        "securityhub": f"{base}/securityhub/findings.json",
        "defender":    f"{base}/defender/findings.json"
    }
 
    for source, key in source_keys.items():
        if available[source]:
            obj          = s3.get_object(Bucket=bucket, Key=key)
            data[source] = json.loads(obj['Body'].read())
            logger.info(f"Loaded {len(data[source])} records from {source}")
        else:
            data[source] = []  # Empty list — not None
 
    # Load Wiz — combine all chunks into one flat list
    if available['wiz']:
        manifest_obj = s3.get_object(Bucket=bucket, Key=f"{base}/wiz/manifest.json")
        manifest     = json.loads(manifest_obj['Body'].read())
        total_chunks = manifest['total_chunks']
 
        wiz_findings = []
        for i in range(total_chunks):
            chunk_obj  = s3.get_object(Bucket=bucket, Key=f"{base}/wiz/chunk_{i:04d}.json")
            chunk_data = json.loads(chunk_obj['Body'].read())
            wiz_findings.extend(chunk_data)  # extend not append — flat list
 
        data['wiz'] = wiz_findings
        logger.info(f"Loaded {len(wiz_findings)} Wiz findings from {total_chunks} chunks")
    else:
        data['wiz'] = []  # Empty list — not None
 
    return data
 
# ---------------------------------------------------------------------------
# Step 3 — Normalize all sources to one standard schema
# ---------------------------------------------------------------------------
def normalize_severity(value):
    """
    Convert any severity value from any source into one of four
    standard values: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN.
 
    Why normalize before calculating metrics:
      Each source uses different field names and different value formats.
      Sentinel:      AlertSeverity = "High"
      Security Hub:  Severity.Label = "HIGH"
      Wiz:           severity = "high"
      Defender:      severity = "High"
 
      Without normalisation, counting CRITICAL + HIGH findings requires
      four separate if/else branches for each source in every metric
      calculation. Normalising first means all metric code is simple and
      source-agnostic.
 
    Why str(value).lower() before the mapping lookup:
      Converts any capitalisation variant to lowercase before lookup.
      "High", "HIGH", "high" all become "high" before mapping.
 
    Why warning and informational are mapped:
      Some sources use non-standard severity labels. Mapping them to our
      standard prevents valid findings from being lost to UNKNOWN status
      and disappearing from metric counts.
    """
    if not value:
        return "UNKNOWN"
 
    mapping = {
        "critical":      "CRITICAL",
        "high":          "HIGH",
        "medium":        "MEDIUM",
        "low":           "LOW",
        "warning":       "MEDIUM",       # Defender sometimes uses this
        "informational": "LOW",          # Security Hub sometimes uses this
        "informative":   "LOW"
    }
    return mapping.get(str(value).lower(), "UNKNOWN")
 
 
def normalize_all_sources(data):
    """
    Convert findings from all four sources into one unified schema.
 
    After normalisation every finding has the same fields regardless
    of which tool produced it. All downstream metric calculations work
    on this unified list — no source-specific logic anywhere in metrics.
 
    Key field decisions:
 
      detected_at vs created_at:
        detected_at = when the tool first observed the threat activity
        created_at  = when the finding record was created in the tool
        These are different. A tool may observe activity at 2am but not
        create the finding record until 2:15am after processing.
        MTTD uses detected_at. MTTR uses created_at.
 
      resolved_at logic for Security Hub:
        updated_at changes on every modification — comments, status
        changes, reassignments. We only set resolved_at when
        workflow_state is explicitly RESOLVED. Using updated_at
        unconditionally would give wrong (too-short) MTTR values.
 
      source field:
        Tells the Aggregation Lambda and CISO dashboard which tool
        each finding came from. Essential for per-source breakdowns.
    """
    normalized = []
 
    # Sentinel findings
    for finding in data['sentinel']:
        normalized.append({
            "id":          finding.get('SystemAlertId'),
            "severity":    normalize_severity(finding.get('AlertSeverity')),
            "created_at":  finding.get('TimeGenerated'),
            "detected_at": finding.get('TimeGenerated'),
            "resolved_at": None,  # Sentinel alerts do not carry a resolved timestamp
            "status":      finding.get('Status'),
            "source":      "sentinel",
            "category":    finding.get('AlertName')
        })
 
    # Security Hub findings
    for finding in data['securityhub']:
        # Only use updated_at as resolved_at when finding is explicitly RESOLVED
        # updated_at changes on every modification, not just resolution
        is_resolved  = finding.get('workflow_state') == 'RESOLVED'
        resolved_at  = finding.get('updated_at') if is_resolved else None
 
        normalized.append({
            "id":          finding.get('id'),
            "severity":    normalize_severity(finding.get('severity')),
            "created_at":  finding.get('created_at'),
            "detected_at": finding.get('first_observed'),
            "resolved_at": resolved_at,
            "status":      finding.get('workflow_state'),
            "source":      "securityhub",
            "category":    finding.get('title')
        })
 
    # Defender findings
    for finding in data['defender']:
        normalized.append({
            "id":          finding.get('findingId'),
            "severity":    normalize_severity(finding.get('severity')),
            "created_at":  finding.get('createdAt'),
            "detected_at": finding.get('createdAt'),
            "resolved_at": None,  # Defender assessments reflect current state, no resolved_at
            "status":      finding.get('status'),
            "source":      "defender",
            "category":    finding.get('displayName')
        })
 
    # Wiz findings
    for finding in data['wiz']:
        normalized.append({
            "id":          finding.get('id'),
            "severity":    normalize_severity(finding.get('severity')),
            "created_at":  finding.get('createdAt'),
            "detected_at": finding.get('firstDetectedAt'),
            "resolved_at": finding.get('resolvedAt'),
            "status":      finding.get('status'),
            "source":      "wiz",
            "category":    finding.get('type')
        })
 
    logger.info(f"Normalized {len(normalized)} total findings from all sources")
    return normalized
 
# ---------------------------------------------------------------------------
# Step 4 — Calculate the 6 metrics
# ---------------------------------------------------------------------------
def parse_timestamp(ts):
    """
    Parse an ISO 8601 timestamp string into a timezone-aware datetime.
 
    Why replace Z with +00:00:
      Azure timestamps end in Z (UTC indicator): "2026-05-25T06:00:00Z"
      Python's datetime.fromisoformat() does not understand Z.
      It requires the explicit offset format: "2026-05-25T06:00:00+00:00"
      Without this replacement, every Azure timestamp causes a ValueError.
    """
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return None
 
 
def calculate_metrics(findings, date_str):
    """
    Calculate all 6 security metrics from the normalized findings list.
 
    Metric 1 — Critical and High count:
      Simple filter on normalized severity field.
      Normalisation already happened — no source-specific logic here.
 
    Metric 2 — MTTD (Mean Time to Detect):
      MTTD = detected_at - created_at (in minutes)
      detected_at = when tool created the finding
      created_at  = when threat activity first started
      Measures delay between threat starting and tool detecting it.
      Why skip negative deltas: clock skew between AWS and Azure systems
      can produce timestamps slightly out of order. Negative MTTD is
      meaningless — skip it rather than corrupt the average.
 
    Metric 3 — MTTR (Mean Time to Respond):
      MTTR = resolved_at - created_at (in minutes)
      Filter by resolved_at not created_at — critical design decision.
      Filtering by created_at produces open ticket bias: only tickets
      created AND resolved in the same day are counted, which excludes
      all slow resolutions. MTTR looks artificially fast.
      Filtering by resolved_at captures all tickets closed today
      regardless of when they were opened — full resolution time.
 
    Metric 4 — Auto-remediation rate:
      Percentage of findings resolved automatically by tooling
      (not by a human engineer manually closing a ticket).
      Different sources use different status labels for auto-resolution —
      we check all known variants.
 
    Metric 5 — Top 10 finding categories:
      Python Counter counts occurrences of each category string.
      most_common(10) returns the 10 highest-frequency categories.
      Tells the CISO where to focus engineering hardening effort.
 
    Metric 6 — Overall remediation rate:
      Percentage of all findings that are in a resolved/closed state.
      Multiple status labels checked — each source uses different terms
      for the same concept (resolved, closed, passed all mean fixed).
    """
 
    # --- Metric 1: Critical + High count ---
    critical_high = [
        f for f in findings
        if f['severity'] in ('CRITICAL', 'HIGH')
    ]
 
    # --- Metric 2: MTTD ---
    mttd_samples = []
    for f in findings:
        created  = parse_timestamp(f.get('created_at'))
        detected = parse_timestamp(f.get('detected_at'))
        if created and detected:
            delta_minutes = (created - detected).total_seconds() / 60
            if delta_minutes >= 0:  # Skip negative deltas from clock skew
                mttd_samples.append(delta_minutes)
 
    mttd = (sum(mttd_samples) / len(mttd_samples)) if mttd_samples else None
    # None means no data available — not zero. Zero would mean instant detection
    # which is a completely different (and misleading) meaning.
 
    # --- Metric 3: MTTR ---
    mttr_samples = []
    for f in findings:
        created  = parse_timestamp(f.get('created_at'))
        resolved = parse_timestamp(f.get('resolved_at'))
        if created and resolved:
            delta_minutes = (resolved - created).total_seconds() / 60
            if delta_minutes >= 0:  # Skip negative deltas
                mttr_samples.append(delta_minutes)
 
    mttr = (sum(mttr_samples) / len(mttr_samples)) if mttr_samples else None
 
    # --- Metric 4: Auto-remediation rate ---
    auto_resolved_statuses = {
        'auto_resolved',
        'autoremediated',
        'resolved_automatically',
        'auto-remediated'
    }
    auto_remediated = [
        f for f in findings
        if str(f.get('status', '')).lower() in auto_resolved_statuses
    ]
    auto_rate = (len(auto_remediated) / len(findings) * 100) if findings else 0
 
    # --- Metric 5: Top 10 categories ---
    categories = [f['category'] for f in findings if f.get('category')]
    top_10     = Counter(categories).most_common(10)
 
    # --- Metric 6: Overall remediation rate ---
    resolved_statuses = {'resolved', 'closed', 'passed', 'fixed', 'remediated'}
    resolved = [
        f for f in findings
        if str(f.get('status', '')).lower() in resolved_statuses
    ]
    remediation_rate = (len(resolved) / len(findings) * 100) if findings else 0
 
    return {
        "date":                  date_str,
        "total_findings":        len(findings),
        "critical_high_count":   len(critical_high),
        "mttd_minutes":          round(mttd, 2) if mttd is not None else None,
        "mttr_minutes":          round(mttr, 2) if mttr is not None else None,
        "auto_remediation_rate": round(auto_rate, 2),
        "top_10_categories":     [{"category": k, "count": v} for k, v in top_10],
        "remediation_rate":      round(remediation_rate, 2),
        "source_breakdown": {
            source: len([f for f in findings if f['source'] == source])
            for source in ['sentinel', 'securityhub', 'defender', 'wiz']
        }
    }
 
# ---------------------------------------------------------------------------
# Step 5 — Store metrics to DynamoDB and S3
# ---------------------------------------------------------------------------
def store_metrics(metrics, available, bucket, date_str):
    """
    Store calculated metrics in DynamoDB (fast queries) and
    S3 (audit trail and historical analysis).
 
    Why both DynamoDB and S3:
      DynamoDB: fast, structured, ideal for dashboard queries.
        "Show last 30 days of MTTR trend" = one range query, instant.
        Not suited for raw detailed data — expensive at scale.
      S3: cheap, durable, queryable via Athena.
        "Why did MTTR spike on May 5?" = Athena query on raw data.
        Not suited for fast key lookups — full scan without partitioning.
      Each solves a problem the other cannot.
 
    DynamoDB primary key design:
      PK: date        → "2026-05-25"
      SK: report_type → "COMPLETE" or "PARTIAL"
      Same date can have two records — partial report published early,
      complete report published later when missing source arrives.
      PK alone (date only) cannot store two records for the same date.
      COMPLETE + PARTIAL sort key makes both retrievable independently.
 
    Why Decimal and not float for DynamoDB:
      DynamoDB does not accept Python float type — it raises a TypeError.
      Must convert via string: Decimal(str(value))
      Decimal(value) directly causes floating point precision errors.
      Decimal(str(value)) is the correct pattern.
 
    TTL (expires_at):
      DynamoDB TTL auto-deletes records after the specified Unix timestamp.
      We set 365 days. No manual cleanup ever needed.
      expires_at must be a Unix timestamp integer — not an ISO string.
    """
    sources_included = [s for s, v in available.items() if v]
    sources_missing  = [s for s, v in available.items() if not v]
    report_type      = "COMPLETE" if not sources_missing else "PARTIAL"
 
    # --- DynamoDB ---
    table = dynamodb.Table('security-metrics')
 
    def to_decimal(val):
        """Convert float to Decimal for DynamoDB. Returns None if val is None."""
        return Decimal(str(val)) if val is not None else None
 
    item = {
        "date":                  date_str,
        "report_type":           report_type,
        "total_findings":        metrics['total_findings'],
        "critical_high_count":   metrics['critical_high_count'],
        "mttd_minutes":          to_decimal(metrics['mttd_minutes']),
        "mttr_minutes":          to_decimal(metrics['mttr_minutes']),
        "auto_remediation_rate": to_decimal(metrics['auto_remediation_rate']),
        "remediation_rate":      to_decimal(metrics['remediation_rate']),
        "top_10_categories":     metrics['top_10_categories'],
        "source_breakdown":      metrics['source_breakdown'],
        "sources_included":      sources_included,
        "sources_missing":       sources_missing,
        "created_at":            datetime.now(timezone.utc).isoformat(),
        # TTL: Unix timestamp integer — DynamoDB auto-deletes after 365 days
        "expires_at":            int(datetime.now(timezone.utc).timestamp()) + (365 * 24 * 60 * 60)
    }
 
    table.put_item(Item=item)
    logger.info(f"Stored {report_type} report to DynamoDB for {date_str}")
 
    # --- S3 audit trail ---
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    s3_key = f"metrics/{year}/{month}/{day}/{report_type.lower()}_report.json"
 
    s3.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=json.dumps(metrics, default=str),  # default=str handles Decimal and datetime
        ContentType='application/json'
    )
    logger.info(f"Stored {report_type} report to s3://{bucket}/{s3_key}")
 
    return report_type, sources_missing
 
# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    try:
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        bucket   = event['bucket']
 
        # Step 1 — Check which sources arrived in S3
        available = check_available_sources(bucket, date_str)
        logger.info(f"Available sources: {available}")
 
        # Step 2 — Load data from available sources
        data = load_source_data(bucket, date_str, available)
 
        # Step 3 — Normalize all sources to one schema
        findings = normalize_all_sources(data)
        logger.info(f"Total normalized findings: {len(findings)}")
 
        # Step 4 — Calculate 6 metrics
        metrics = calculate_metrics(findings, date_str)
        logger.info(f"Metrics calculated: {json.dumps(metrics, default=str)}")
 
        # Step 5 — Store to DynamoDB and S3
        report_type, sources_missing = store_metrics(
            metrics, available, bucket, date_str
        )
 
        return {
            "status":           "success",
            "report_type":      report_type,
            "sources_included": [s for s, v in available.items() if v],
            "sources_missing":  sources_missing,
            "total_findings":   metrics['total_findings'],
            "critical_high":    metrics['critical_high_count'],
            "mttd_minutes":     metrics['mttd_minutes'],
            "mttr_minutes":     metrics['mttr_minutes'],
            "date":             date_str
        }
 
    except Exception as e:
        logger.error(f"Aggregation Lambda failed: {str(e)}")
        raise  # Re-raise so Step Functions Catch block triggers SNS notification
