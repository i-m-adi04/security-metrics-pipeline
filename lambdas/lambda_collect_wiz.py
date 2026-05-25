import boto3
import json
import requests
from datetime import datetime, timezone
import logging
 
logger = logging.getLogger()
logger.setLevel(logging.INFO)
 
# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
CHUNK_SIZE = 500          # findings per S3 chunk
MAX_RETRIES = 3           # retries on 429 / 5xx errors
RETRY_WAIT = [10, 30, 60] # seconds to wait between retries
 
# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------
def get_secrets():
    """Retrieve Wiz API credentials from Secrets Manager."""
    client = boto3.client('secretsmanager')
    secret = client.get_secret_value(SecretId='security-pipeline/wiz')
    return json.loads(secret['SecretString'])
    # Expected keys: api_key, api_url
 
# ---------------------------------------------------------------------------
# Checkpoint helpers (DynamoDB)
# ---------------------------------------------------------------------------
def get_checkpoint(date_str):
    """
    Check DynamoDB for a saved cursor from a previous run.
    Returns the cursor string if found, or None if this is a fresh run.
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('security-pipeline-checkpoints')
    try:
        response = table.get_item(Key={'date': date_str, 'source': 'wiz'})
        item = response.get('Item')
        if item:
            logger.info(f"Resuming from checkpoint — cursor: {item['cursor']}, "
                        f"chunks_written: {item['chunks_written']}")
            return item['cursor'], int(item['chunks_written'])
    except Exception as e:
        logger.warning(f"Could not read checkpoint: {str(e)}")
    return None, 0
 
 
def save_checkpoint(date_str, cursor, chunks_written):
    """
    Save current position to DynamoDB so a restarted Lambda can resume.
    Overwrites any previous checkpoint for the same date.
    """
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('security-pipeline-checkpoints')
    table.put_item(Item={
        'date':           date_str,
        'source':         'wiz',
        'cursor':         cursor,
        'chunks_written': chunks_written,
        'updated_at':     datetime.now(timezone.utc).isoformat()
    })
 
 
def delete_checkpoint(date_str):
    """Remove checkpoint after a successful full collection."""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table('security-pipeline-checkpoints')
    try:
        table.delete_item(Key={'date': date_str, 'source': 'wiz'})
    except Exception as e:
        logger.warning(f"Could not delete checkpoint: {str(e)}")
 
# ---------------------------------------------------------------------------
# Wiz API — bearer token
# ---------------------------------------------------------------------------
def get_wiz_token(api_key, api_url):
    """
    Exchange the API key for a short-lived bearer token.
    Wiz uses OAuth2 client credentials flow.
    """
    token_url = f"{api_url}/oauth/token"
    body = {
        "grant_type":    "client_credentials",
        "client_id":     api_key,
        "client_secret": api_key,
        "audience":      "wiz-api"
    }
    # Wiz token endpoint expects JSON, not form-encoded
    response = requests.post(token_url, json=body, timeout=30)
    response.raise_for_status()
    return response.json()["access_token"]
 
# ---------------------------------------------------------------------------
# Wiz API — paginated findings
# ---------------------------------------------------------------------------
def fetch_page(api_url, token, cursor=None):
    """
    Fetch one page of findings from the Wiz API.
    Uses GraphQL — Wiz's query language for findings.
    Returns (findings_list, next_cursor_or_None).
 
    Retries on 429 (rate limit) and 5xx (server error).
    Does NOT retry on 401/403 (auth errors — retrying wastes quota).
    """
    query = """
    query GetFindings($first: Int, $after: String) {
      issues(first: $first, after: $after, filterBy: {status: [OPEN]}) {
        nodes {
          id
          type
          severity
          status
          createdAt
          firstDetectedAt
          resolvedAt
          entitySnapshot {
            id
            type
            name
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
    """
 
    variables = {"first": CHUNK_SIZE}
    if cursor:
        variables["after"] = cursor
 
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }
 
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(
                f"{api_url}/graphql",
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=60
            )
 
            # Do NOT retry auth errors — they won't fix themselves on retry
            if response.status_code in (401, 403):
                logger.error(f"Auth error {response.status_code} — check API key")
                response.raise_for_status()
 
            # Retry on rate limit or server errors
            if response.status_code == 429 or response.status_code >= 500:
                wait = RETRY_WAIT[min(attempt, len(RETRY_WAIT) - 1)]
                logger.warning(f"HTTP {response.status_code} — waiting {wait}s before retry")
                import time
                time.sleep(wait)
                continue
 
            response.raise_for_status()
            data = response.json()
            issues = data["data"]["issues"]
            findings = issues["nodes"]
            page_info = issues["pageInfo"]
 
            next_cursor = page_info["endCursor"] if page_info["hasNextPage"] else None
            return findings, next_cursor
 
        except requests.exceptions.RequestException as e:
            if attempt == MAX_RETRIES - 1:
                raise
            logger.warning(f"Request error on attempt {attempt + 1}: {str(e)}")
 
    return [], None
 
# ---------------------------------------------------------------------------
# S3 helpers
# ---------------------------------------------------------------------------
def flush_chunk(findings_buffer, bucket, date_str, chunk_index):
    """Write one chunk of findings to S3."""
    s3 = boto3.client('s3')
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    key = f"raw/{year}/{month}/{day}/wiz/chunk_{chunk_index:04d}.json"
 
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(findings_buffer),
        ContentType='application/json'
    )
    logger.info(f"Flushed chunk {chunk_index:04d} — {len(findings_buffer)} findings → s3://{bucket}/{key}")
 
 
def write_manifest(bucket, date_str, total_chunks, total_findings):
    """
    Write a manifest file confirming all chunks completed successfully.
    The Aggregation Lambda checks this before using any Wiz data.
    If this file is missing, Wiz data is excluded entirely — prevents
    partial data from silently skewing all metrics.
    """
    s3 = boto3.client('s3')
    year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
    key = f"raw/{year}/{month}/{day}/wiz/manifest.json"
 
    manifest = {
        "status":         "complete",
        "total_chunks":   total_chunks,
        "total_findings": total_findings,
        "completed_at":   datetime.now(timezone.utc).isoformat()
    }
 
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(manifest),
        ContentType='application/json'
    )
    logger.info(f"Manifest written — {total_chunks} chunks, {total_findings} total findings")
 
# ---------------------------------------------------------------------------
# Main collection loop
# ---------------------------------------------------------------------------
def collect_wiz_findings(api_url, token, bucket, date_str, start_cursor, start_chunk):
    """
    Main pagination loop. Fetches pages from Wiz, buffers findings,
    and flushes to S3 every CHUNK_SIZE findings.
 
    Saves a DynamoDB checkpoint after every flush so a Lambda restart
    can resume from the last saved position — not from the beginning.
    """
    buffer        = []
    chunk_index   = start_chunk
    total_findings = 0
    cursor        = start_cursor
 
    while True:
        findings, next_cursor = fetch_page(api_url, token, cursor)
 
        if not findings:
            break
 
        buffer.extend(findings)
        total_findings += len(findings)
 
        # Flush to S3 and save checkpoint every CHUNK_SIZE findings
        if len(buffer) >= CHUNK_SIZE:
            flush_chunk(buffer[:CHUNK_SIZE], bucket, date_str, chunk_index)
            save_checkpoint(date_str, cursor, chunk_index + 1)
            buffer = buffer[CHUNK_SIZE:]
            chunk_index += 1
 
        logger.info(f"Collected {total_findings} findings so far...")
 
        if not next_cursor:
            break  # No more pages
        cursor = next_cursor
 
    # Flush any remaining findings in the buffer
    if buffer:
        flush_chunk(buffer, bucket, date_str, chunk_index)
        chunk_index += 1
        total_findings += len(buffer)
 
    return chunk_index, total_findings
 
# ---------------------------------------------------------------------------
# Lambda handler
# ---------------------------------------------------------------------------
def lambda_handler(event, context):
    try:
        date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
        bucket   = event['bucket']
 
        # 1. Get credentials
        secrets = get_secrets()
        api_key = secrets['api_key']
        api_url = secrets['api_url']
 
        # 2. Get bearer token
        token = get_wiz_token(api_key, api_url)
 
        # 3. Check for a saved checkpoint (Lambda may be resuming after timeout)
        start_cursor, start_chunk = get_checkpoint(date_str)
        if start_cursor:
            logger.info(f"Resuming collection from chunk {start_chunk}")
        else:
            logger.info("Starting fresh collection")
 
        # 4. Collect all findings with pagination and checkpointing
        total_chunks, total_findings = collect_wiz_findings(
            api_url, token, bucket, date_str, start_cursor, start_chunk
        )
 
        # 5. Write manifest confirming all chunks are complete
        write_manifest(bucket, date_str, total_chunks, total_findings)
 
        # 6. Clean up checkpoint — collection is complete
        delete_checkpoint(date_str)
 
        year, month, day = date_str[:4], date_str[5:7], date_str[8:10]
        return {
            "source":         "wiz",
            "status":         "success",
            "finding_count":  total_findings,
            "total_chunks":   total_chunks,
            "date":           date_str,
            "s3_prefix":      f"raw/{year}/{month}/{day}/wiz/"
        }
 
    except Exception as e:
        logger.error(f"Wiz Lambda failed: {str(e)}")
        raise  # Re-raise so Step Functions Catch block triggers SNS notification
 
