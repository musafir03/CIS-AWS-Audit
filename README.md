# CIS AWS Foundations Benchmark v7.0.0 — Automated Audit

A single AWS Lambda function that audits an AWS account against all five domains of the **CIS Amazon Web Services Foundations Benchmark v7.0.0**:

| Domain | Controls | CIS Section |
|--------|----------|-------------|
| Identity and Access Management | 2.1.1 – 2.21 | Section 2 |
| Storage | 3.1.1 – 3.3.1 | Section 3 |
| Logging | 4.1 – 4.10 | Section 4 |
| Monitoring | 5.1 – 5.16 | Section 5 |
| Networking | 6.1.1 – 6.8 | Section 6 |

**Total: ~70 controls** evaluated automatically via AWS API calls.

---

## What the Script Does

The Lambda function connects to various AWS services using `boto3`, evaluates each CIS control, and returns a structured JSON report containing:

- **Per-control findings** with Control ID, Domain, Control Name, Status, Summary, Affected resource(s), and raw API Evidence
- **Overall summary** — count of PASS, FAIL, N/A, MANUAL_REVIEW, ERROR
- **Per-domain breakdown** — same counts grouped by each of the 5 domains
- **Account metadata** — account ID, regions checked, scan timestamp

### Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Control requirement is satisfied |
| `FAIL` | Control requirement is NOT satisfied (security finding) |
| `N/A` | No resources of the assessed type exist (vacuous pass) |
| `MANUAL_REVIEW` | Cannot be fully evaluated via API — human review needed |
| `ERROR` | The check itself could not run (permission issue, API failure) |

### What's NOT in the Lambda

The Lambda outputs raw audit findings. It does **not** include:

- **Severity ratings** (High / Medium / Low)
- **Risk descriptions**
- **Remediation recommendations**
- **CIS reference numbers**

These are metadata fields that belong in a reporting/enrichment layer. When you feed the Lambda's JSON output to any LLM (ChatGPT, Claude, etc.), it can map each control to its severity and recommendation based on the CIS Benchmark document.

---

## Prerequisites

- An AWS account with permissions to create Lambda functions and IAM roles
- AWS CLI configured (`aws configure`) or access to the AWS Console
- Python 3.9+ runtime (Lambda supports 3.9, 3.10, 3.11, 3.12, 3.13)

---

## Step-by-Step Setup

### 1. Create the IAM Execution Role

The Lambda needs an IAM role with specific permissions to audit your account.

#### 1a. Create the role

Go to **IAM → Roles → Create role**:
- Trusted entity: **AWS service → Lambda**
- Role name: `cis-audit-lambda-role`

Or via CLI:

```bash
aws iam create-role \
  --role-name cis-audit-lambda-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'
```

#### 1b. Attach the SecurityAudit managed policy

This covers most of the read-only permissions the script needs:

```bash
aws iam attach-role-policy \
  --role-name cis-audit-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

#### 1c. Attach basic Lambda execution policy (for CloudWatch Logs)

```bash
aws iam attach-role-policy \
  --role-name cis-audit-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

#### 1d. Create and attach the custom policy for additional permissions

The `SecurityAudit` policy doesn't cover everything. Create a custom policy for the remaining permissions:

```bash
aws iam put-role-policy \
  --role-name cis-audit-lambda-role \
  --policy-name cis-audit-extra-permissions \
  --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CISAuditExtraPermissions",
      "Effect": "Allow",
      "Action": [
        "accessanalyzer:ListAnalyzers",
        "accessanalyzer:ListFindings",
        "securityhub:DescribeHub",
        "s3control:GetPublicAccessBlock",
        "organizations:DescribeOrganization",
        "organizations:ListRoots",
        "organizations:ListOrganizationalUnitsForParent",
        "organizations:ListAccountsForParent",
        "organizations:ListPoliciesForTarget",
        "organizations:ListDelegatedAdministrators",
        "organizations:DescribeResourcePolicy",
        "account:GetContactInformation",
        "account:GetAlternateContact",
        "iam:ListOrganizationsFeatures",
        "iam:ListVirtualMFADevices",
        "iam:ListSAMLProviders",
        "sso-admin:ListInstances",
        "cloudtrail:LookupEvents",
        "s3:GetBucketPolicy",
        "s3:GetBucketVersioning",
        "macie2:GetMacieSession",
        "macie2:ListClassificationJobs",
        "rds:DescribeDBInstances",
        "cloudfront:ListDistributions",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "apigateway:GET",
        "sns:ListTopics",
        "sns:GetTopicAttributes",
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "kms:ListKeys",
        "kms:GetKeyPolicy",
        "lambda:ListFunctions",
        "lambda:GetPolicy",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeRouteTables",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcs",
        "ec2:DescribeInstances"
      ],
      "Resource": "*"
    }
  ]
}'
```

> **Note on Organizations permissions:** Controls 2.1.1–2.1.6 query AWS Organizations APIs. These only return real data when the Lambda runs in the **management account** (or a delegated admin account). From a member account, these controls gracefully degrade to `N/A` or `MANUAL_REVIEW` — they won't fail the run.

### 2. Create the Lambda Function

#### Option A: AWS Console

1. Go to **Lambda → Create function**
2. Settings:
   - Function name: `cis-audit-merge`
   - Runtime: **Python 3.12**
   - Architecture: **x86_64**
   - Execution role: **Use an existing role → `cis-audit-lambda-role`**
3. Click **Create function**
4. In the **Code** tab, replace the default code with the contents of `lambda_function.py`
5. Click **Deploy**
6. Go to **Configuration → General configuration → Edit**:
   - Memory: **256 MB** (128 MB is fine for smaller accounts)
   - Timeout: **10 minutes** (600 seconds) — the script scans all regions, so it needs time
   - Ephemeral storage: **512 MB** (default is fine)

#### Option B: AWS CLI

```bash
# Zip the function
zip cis-audit.zip lambda_function.py

# Create the function
aws lambda create-function \
  --function-name cis-audit-merge \
  --runtime python3.12 \
  --handler lambda_function.lambda_handler \
  --role arn:aws:iam::<YOUR_ACCOUNT_ID>:role/cis-audit-lambda-role \
  --zip-file fileb://cis-audit.zip \
  --timeout 600 \
  --memory-size 256 \
  --region ap-south-1
```

Replace `<YOUR_ACCOUNT_ID>` with your 12-digit AWS account ID.

### 3. Configure Environment Variables (Optional)

| Variable | Purpose | Default |
|----------|---------|---------|
| `REGIONS_OVERRIDE` | Comma-separated list of regions to scan (e.g., `ap-south-1,us-east-1`) | All enabled regions in the account |

Set this if you want to limit the scan to specific regions (faster execution):

```bash
aws lambda update-function-configuration \
  --function-name cis-audit-merge \
  --environment "Variables={REGIONS_OVERRIDE=ap-south-1,us-east-1}"
```

---

## How to Run

### Run from AWS Console

1. Go to **Lambda → cis-audit-merge → Test**
2. Create a test event with an empty JSON payload:
   ```json
   {}
   ```
3. Click **Test**
4. The response will contain the full JSON audit report

### Run from AWS CLI

```bash
aws lambda invoke \
  --function-name cis-audit-merge \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  output.json

# View the report
cat output.json | python3 -m json.tool
```

### Run a Single Domain

Pass a `domain` key to run only one of the five domains (useful for parallel execution or debugging):

```bash
# Run only IAM controls
aws lambda invoke \
  --function-name cis-audit-merge \
  --payload '{"domain": "IAM"}' \
  --cli-binary-format raw-in-base64-out \
  output.json
```

Valid domain values: `IAM`, `STORAGE`, `LOGGING`, `MONITORING`, `NETWORKING`

### Run Locally (for testing)

You can also run the script locally if you have AWS credentials configured:

```bash
python3 lambda_function.py
```

This calls `lambda_handler({}, None)` and prints the JSON report to stdout.

---

## Output Format

The Lambda returns a JSON object:

```json
{
  "benchmark": "CIS AWS Foundations Benchmark v7.0.0",
  "account_id": "123456789012",
  "scanned_at": "2026-11-17T09:30:00+00:00",
  "regions_checked": ["ap-south-1", "us-east-1", "..."],
  "total_controls": 70,
  "summary": {
    "PASS": 41,
    "FAIL": 12,
    "MANUAL_REVIEW": 9,
    "N/A": 5,
    "ERROR": 3
  },
  "domain_summaries": {
    "Identity and Access Management": {"PASS": 15, "FAIL": 5, "...": "..."},
    "Storage": {"PASS": 7, "FAIL": 2, "...": "..."},
    "...": "..."
  },
  "findings": [
    {
      "Control ID": "2.4",
      "Domain": "Identity and Access Management",
      "Control Name": "Ensure no 'root' user account access key exists",
      "Status": "PASS",
      "Summary": "No access keys exist for the root account.",
      "Affected": "-",
      "Evidence": {
        "api_call": "iam:GetAccountSummary",
        "timestamp": "2026-11-17T09:30:01+00:00",
        "raw_result": "AccountAccessKeysPresent=0"
      }
    }
  ]
}
```

---

## Controls Covered

### Domain 1: Identity and Access Management (21 controls)

| Control ID | Control Name |
|------------|-------------|
| 2.1.1 | Ensure centralized root access in AWS Organizations |
| 2.1.2 | Ensure authorization guardrails for all AWS Organization accounts |
| 2.1.3 | Ensure Organizations management account is not used for workloads |
| 2.1.4 | Ensure Organizational Units are structured by environment and sensitivity |
| 2.1.5 | Ensure delegated admin manages AWS Organizations policies |
| 2.1.6 | Ensure delegated admins manage AWS Organizations-integrated services |
| 2.2 | Maintain current AWS account contact details |
| 2.3 | Ensure security contact information is registered |
| 2.4 | Ensure no 'root' user account access key exists |
| 2.5 | Ensure MFA is enabled for the 'root' user account |
| 2.6 | Ensure hardware MFA is enabled for the 'root' user account |
| 2.7 | Eliminate use of the 'root' user for administrative and daily tasks |
| 2.8 | Ensure IAM password policy requires minimum length of 14 or greater |
| 2.9 | Ensure IAM password policy prevents password reuse |
| 2.10 | Ensure MFA is enabled for all IAM users with a console password |
| 2.11 | Ensure credentials unused for 45 days or more are disabled |
| 2.12 | Ensure access keys are rotated every 90 days or less |
| 2.13 | Ensure IAM users receive permissions only through groups |
| 2.14 | Ensure IAM policies that allow full "*:*" admin privileges are not attached |
| 2.15 | Ensure a support role has been created to manage incidents with AWS Support |
| 2.16 | Ensure IAM instance roles are used for AWS resource access from instances |
| 2.17 | Ensure all expired SSL/TLS certificates stored in IAM are removed |
| 2.18 | Ensure IAM External Access Analyzer is enabled for all regions |
| 2.19 | Ensure IAM users are managed centrally via identity federation |
| 2.20 | Ensure access to AWSCloudShellFullAccess is restricted |
| 2.21 | Ensure AWS resource policies do not allow unrestricted access |

### Domain 2: Storage (9 controls)

| Control ID | Control Name |
|------------|-------------|
| 3.1.1 | Ensure S3 Bucket Policy is set to deny HTTP requests |
| 3.1.2 | Ensure MFA Delete is enabled on S3 buckets |
| 3.1.3 | Ensure all data in Amazon S3 has been discovered, classified, and secured |
| 3.1.4 | Ensure S3 is configured with 'Block Public Access' enabled |
| 3.2.1 | Ensure encryption-at-rest is enabled for RDS instances |
| 3.2.2 | Ensure Auto Minor Version Upgrade is enabled for RDS instances |
| 3.2.3 | Ensure RDS instances are not publicly accessible |
| 3.2.4 | Ensure Multi-AZ deployments are used for Amazon RDS |
| 3.3.1 | Ensure encryption is enabled for EFS file systems |

### Domain 3: Logging (10 controls)

| Control ID | Control Name |
|------------|-------------|
| 4.1 | Ensure CloudTrail is enabled in all regions |
| 4.2 | Ensure CloudTrail log file validation is enabled |
| 4.3 | Ensure AWS Config is enabled in all regions |
| 4.4 | Ensure server access logging is enabled on the CloudTrail S3 bucket |
| 4.5 | Ensure CloudTrail logs are encrypted at rest using KMS CMKs |
| 4.6 | Ensure rotation for customer-created symmetric CMKs is enabled |
| 4.7 | Ensure VPC flow logging is enabled in all VPCs |
| 4.8 | Ensure object-level logging for write events is enabled for S3 buckets |
| 4.9 | Ensure object-level logging for read events is enabled for S3 buckets |
| 4.10 | Ensure all AWS-managed web front-end services have access logging enabled |

### Domain 4: Monitoring (16 controls)

| Control ID | Control Name |
|------------|-------------|
| 5.1 | Ensure unauthorized API calls are monitored |
| 5.2 | Ensure management console sign-in without MFA is monitored |
| 5.3 | Ensure usage of the 'root' account is monitored |
| 5.4 | Ensure IAM policy changes are monitored |
| 5.5 | Ensure CloudTrail configuration changes are monitored |
| 5.6 | Ensure AWS Management Console authentication failures are monitored |
| 5.7 | Ensure disabling or scheduled deletion of customer-created CMKs is monitored |
| 5.8 | Ensure S3 bucket policy changes are monitored |
| 5.9 | Ensure AWS Config configuration changes are monitored |
| 5.10 | Ensure security group changes are monitored |
| 5.11 | Ensure NACL changes are monitored |
| 5.12 | Ensure changes to network gateways are monitored |
| 5.13 | Ensure route table changes are monitored |
| 5.14 | Ensure VPC changes are monitored |
| 5.15 | Ensure AWS Organizations changes are monitored |
| 5.16 | Ensure AWS Security Hub is enabled |

### Domain 5: Networking (9 controls)

| Control ID | Control Name |
|------------|-------------|
| 6.1.1 | Ensure EBS volume encryption is enabled in all regions |
| 6.1.2 | Ensure CIFS access is restricted to trusted networks |
| 6.2 | Ensure no NACLs allow ingress from 0.0.0.0/0 to admin ports |
| 6.3 | Ensure no security groups allow ingress from 0.0.0.0/0 to admin ports |
| 6.4 | Ensure no security groups allow ingress from ::/0 to admin ports |
| 6.5 | Ensure the default security group of every VPC restricts all traffic |
| 6.6 | Ensure routing tables for VPC peering are "least access" |
| 6.7 | Ensure EC2 Metadata Service only allows IMDSv2 |
| 6.8 | Ensure VPC Endpoints are used for access to AWS Services |

---

## Troubleshooting

### Lambda times out
Increase the timeout to **15 minutes** (900 seconds), or set `REGIONS_OVERRIDE` to scan fewer regions.

### "AccessDenied" errors in findings
The execution role is missing permissions. Check the custom policy in Step 1d. Some Organizations-related controls (2.1.x) require the Lambda to run from the management account.

### Controls return ERROR status
Check CloudWatch Logs for the Lambda (Log group: `/aws/lambda/cis-audit-merge`). Common causes are missing permissions or API throttling.

### Response payload too large
Lambda has a 6 MB response limit. For accounts with many resources, the evidence field can grow large. The script already truncates raw evidence to 500 characters per finding.

---

## License

This tool is provided as-is for internal audit purposes. The CIS Benchmarks are copyrighted by the Center for Internet Security — refer to [cisecurity.org](https://www.cisecurity.org/) for the official benchmark document.
