Automated Security Metrics Pipeline
A fully serverless pipeline that collects security findings from four tools daily, calculates key security metrics, and delivers executive reports to the CISO dashboard — automatically, every morning.

What we were trying to achieve
Large organisations use multiple security tools simultaneously. Our environment uses Wiz (cloud vulnerabilities), Microsoft Sentinel (threat alerts), Microsoft Defender for Cloud (misconfigurations), and AWS Security Hub (cloud security posture). Each tool has its own dashboard, its own format, and its own numbers. A CISO sitting in a leadership meeting cannot meaningfully answer "how secure are we?" when the answer requires logging into four separate tools and manually combining data.
The goal was simple: one automated report, every morning, before the leadership meeting, combining data from all four tools into six business-relevant metrics.
The six metrics we calculate:

Critical and high severity alert count
Mean Time to Detect (MTTD) — how long between a threat starting and us spotting it
Mean Time to Respond (MTTR) — how long between detection and resolution
Auto-remediation rate — what percentage of issues fixed themselves automatically
Top 10 recurring issue categories — where to focus engineering effort
Overall remediation rate — what percentage of issues are getting resolved


How it works (non-technical)
Every morning at 6 AM, an automated scheduler starts the pipeline. It sends four workers out simultaneously — one to each security tool — to collect that day's findings. This happens in parallel so the total collection time is only as long as the slowest worker, not the sum of all four.
Once all workers finish, a fifth process combines everything, calculates the six metrics, and stores the results in two places: a fast-query database for the live dashboard, and a long-term archive for historical analysis and audit purposes.
If everything works, a complete report is ready within 30 minutes. If one tool is unavailable, the pipeline publishes a partial report immediately (clearly labeled as incomplete) and retries the missing source every two hours. When the missing data arrives, it publishes an updated complete report and sends a notification.

Technology choices and why
AWS Step Functions (orchestration)
The pipeline needs to coordinate four independent workers, handle failures gracefully, and retry on errors — without any of this requiring human intervention. Step Functions is a serverless workflow service that handles all of this natively. The alternative was running everything on a virtual machine with a scheduled script, but that approach has no built-in retry logic, no fault isolation, and requires paying for the machine even when it's idle. Step Functions costs nothing when not running.
AWS Lambda (workers)
Each collector is a small, independent function that runs only when called. No servers to manage, no always-on infrastructure. Each function lives and dies independently — if one crashes, the others continue unaffected. This is the fault isolation design: a Wiz API outage does not affect Security Hub collection.
Amazon S3 (raw data storage)
Every finding from every tool is saved to S3 in its raw form before any processing. This serves two purposes. First, it creates an audit trail — if a question arises six months later about what was happening on a specific date, the raw data is there. Second, it allows the AWS analytics service (Athena) to query historical data directly, enabling trend analysis across any time period.
Amazon DynamoDB (metrics storage)
The calculated daily metrics are stored in DynamoDB, a fast key-value database. The dashboard retrieves the last 30 days of MTTR in a single query that returns in milliseconds. Data older than one year is automatically deleted, keeping costs predictable.
AWS Secrets Manager (credential storage)
The pipeline needs credentials to access the three external tools (Wiz, Sentinel, Defender). These are stored in Secrets Manager, an encrypted vault, rather than inside the code. This means rotating credentials requires changing one value in one place, not editing and redeploying code.

Problems we encountered and how we solved them
Problem 1: Wiz returns too much data for a single function call
Wiz holds the entire vulnerability history of an organisation — potentially 10,000+ findings. Loading all of this into memory at once causes the Lambda function to run out of memory and crash. Worse, Lambda functions have a 15-minute maximum runtime, and collecting 10,000+ findings takes longer than that.
Solution: We process Wiz findings in batches of 500. After each batch, we save our progress (specifically, a "cursor" — the position in the list where we stopped) to DynamoDB. If the function runs out of time, it is automatically restarted and picks up exactly where it left off. This is the same principle as a download manager that resumes an interrupted download rather than starting from scratch.
We also write a "manifest" file at the very end confirming that all batches completed successfully. The aggregation step checks this manifest before using any Wiz data. If the manifest is missing or incomplete, Wiz data is excluded entirely rather than using partial data that could skew the metrics.
Problem 2: The four tools use different data formats
Sentinel calls severity "AlertSeverity" and uses values like "High". Security Hub calls it "Severity.Label" and uses "HIGH". Wiz uses "severity" and "high". Before we can count anything, we need all four speaking the same language.
Solution: A normalisation step converts all findings into one standard format before any calculation happens. Severity becomes one of four values: CRITICAL, HIGH, MEDIUM, LOW. Every other field is mapped to a standard name. After normalisation, the metric calculations have no knowledge of which tool a finding came from — they just see uniform data.
Problem 3: MTTR (Mean Time to Respond) was giving misleading results
The naive approach to calculating MTTR is: look at all tickets created in the last 24 hours, find the ones that are now closed, and average the time between creation and closure. This sounds reasonable but produces systematically wrong results. It only captures tickets that were both created and resolved within a single day — which means only the fastest resolutions. Slow tickets are invisible. The CISO sees an artificially fast MTTR and believes the team is performing better than it is.
Solution: Filter by resolution date, not creation date. Look at all tickets resolved in the last 24 hours, regardless of when they were created, and calculate the full time from creation to resolution. This correctly captures the complete resolution time including tickets that took days or weeks to close.
Problem 4: One source failing should not cancel the entire report
If a Step Functions branch fails and we treat that as a pipeline failure, we lose all the data collected by the other three branches. The CISO gets no report at all — which is worse than a partial report.
Solution: Each collector branch has a "catch" handler. If it fails, the branch marks itself as gracefully completed (rather than failed), sends a notification to the security team, and passes a "missing" flag to the aggregation step. The aggregation step produces a partial report, clearly labeled with which sources are included and which are missing. A recovery job retries the missing source on a schedule. This way, a Wiz API outage produces a partial Sentinel + Defender + Security Hub report, not zero report.

Repository structure
/lambdas
  lambda_collect_wiz.py           — Wiz REST API, pagination, checkpointing
  lambda_collect_sentinel.py      — Azure Log Analytics API, KQL queries
  lambda_collect_securityhub.py   — AWS Security Hub, boto3 paginator
  lambda_collect_defender.py      — Azure Resource Graph API, KQL queries
  lambda_aggregate_metrics.py     — normalisation, metric calculation, reporting

/stepfunctions
  state_machine.json              — Step Functions state machine definition

/docs
  architecture_diagram.png        — pipeline architecture diagram
 
