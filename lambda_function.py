"""
CIS AWS Foundations Benchmark v7.0.0 - All Domains (Unified)
==============================================================

Single AWS Lambda function that audits an AWS account against ALL five domains
of the CIS AWS Foundations Benchmark v7.0.0:

    Domain 1 - Identity and Access Management  (Controls 2.1.1 - 2.21)
    Domain 2 - Storage                         (Controls 3.1.1 - 3.3.1)
    Domain 3 - Logging                         (Controls 4.1  - 4.10)
    Domain 4 - Monitoring                      (Controls 5.1  - 5.16)
    Domain 5 - Networking                      (Controls 6.1.1 - 6.8)

Output shape (matches the "Security Findings" report table used downstream):
    Control ID | Domain | Control Name | Status | Summary | Affected

Status values:
    PASS              - control requirement is satisfied
    FAIL              - control requirement is NOT satisfied (finding)
    N/A               - no resources of the assessed type exist
    MANUAL_REVIEW     - cannot be evaluated purely via API
    ERROR             - the check itself could not run

Required IAM permissions:
    Attach the AWS-managed policy "SecurityAudit" to the execution role.
    Additionally needed (not in SecurityAudit):
        accessanalyzer:ListAnalyzers
        accessanalyzer:ListFindings
        securityhub:DescribeHub
        s3control:GetPublicAccessBlock

    Added for the Tier 1/2/3 automation of former MANUAL_REVIEW controls
    (2.1.1-2.1.6, 2.2, 2.3, 2.6, 2.7, 2.19-2.21, 3.1.2, 3.1.3, 3.2.4, 4.10,
    6.6, 6.8) — none of these are covered by SecurityAudit, so they must be
    granted via a separate inline/customer-managed policy:
        organizations:DescribeOrganization
        organizations:ListRoots
        organizations:ListOrganizationalUnitsForParent
        organizations:ListAccountsForParent
        organizations:ListPoliciesForTarget
        organizations:ListDelegatedAdministrators
        organizations:DescribeResourcePolicy
        account:GetContactInformation
        account:GetAlternateContact
        iam:ListOrganizationsFeatures
        iam:ListVirtualMFADevices
        iam:ListSAMLProviders
        iam:ListEntitiesForPolicy          (already covered by SecurityAudit,
                                             listed here for completeness)
        sso-admin:ListInstances
        cloudtrail:LookupEvents
        s3:GetBucketPolicy
        s3:GetBucketVersioning
        macie2:GetMacieSession
        macie2:ListClassificationJobs
        rds:DescribeDBInstances
        cloudfront:ListDistributions
        elasticloadbalancing:DescribeLoadBalancers
        elasticloadbalancing:DescribeLoadBalancerAttributes
        apigateway:GET
        sns:ListTopics
        sns:GetTopicAttributes
        sqs:ListQueues
        sqs:GetQueueAttributes
        kms:ListKeys
        kms:GetKeyPolicy
        lambda:ListFunctions
        lambda:GetPolicy
        ec2:DescribeVpcPeeringConnections
        ec2:DescribeRouteTables
        ec2:DescribeVpcEndpoints
        ec2:DescribeVpcs
        ec2:DescribeInstances              (already covered by SecurityAudit)

    NOTE: organizations:*, account:GetAlternateContact and
    organizations:DescribeResourcePolicy only return real data when this
    Lambda runs in (or is granted delegated-admin/trusted-access from) the
    Organizations management account. From a member account, these checks
    degrade gracefully to N/A or MANUAL_REVIEW rather than failing the run.

Environment variables (all optional):
    REGIONS_OVERRIDE   comma-separated list of regions to check for
                        region-scoped controls. Defaults to all enabled regions.
"""

import boto3
import botocore
import csv
import io
import json
import os
import time
from datetime import datetime, timezone


# ===========================================================================
# Shared helpers
# ===========================================================================

def _now():
    return datetime.now(timezone.utc)


def _days_since(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        if dt in ("N/A", "no_information", "not_supported"):
            return None
        dt = dt.strip().replace("Z", "+00:00")
        try:
            dt = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S+00:00").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (_now() - dt).days


def _finding(control_id, domain, control_name, status, summary, affected=None, evidence=None):
    result = {
        "Control ID": control_id,
        "Domain": domain,
        "Control Name": control_name,
        "Status": status,
        "Summary": summary,
        "Affected": affected if affected else "-",
    }
    if evidence:
        result["Evidence"] = evidence
    return result


def _evidence(api_call, raw_result):
    return {
        "api_call": api_call,
        "timestamp": _now().isoformat(),
        "raw_result": str(raw_result)[:500],
    }


def _enabled_regions(session, override=None):
    if override:
        return [r.strip() for r in override.split(",") if r.strip()]
    ec2 = session.client("ec2")
    resp = ec2.describe_regions(AllRegions=False)
    return sorted(r["RegionName"] for r in resp["Regions"])


def _get_credential_report(iam):
    for _ in range(6):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(2)
    report = iam.get_credential_report()
    csv_body = report["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(csv_body))
    return list(reader)


# ===========================================================================
# Domain 1: Identity and Access Management
# ===========================================================================

D_IAM = "Identity and Access Management"

# --- Formerly-manual controls, now automated or evidence-assisted ---
# Tier 1 (full automation -> real PASS/FAIL/N/A): 2.1.1, 2.1.5, 2.1.6, 2.6,
#   2.7, 2.20 (plus 3.1.2/3.1.3/3.2.4, 4.10, 6.6 in their own domains below).
# Tier 2 (partial automation -> flags likely issues, evidence attached):
#   2.1.2, 2.1.3, 2.3, 2.19, 2.21 (plus 6.8 in the networking domain).
# Tier 3 (evidence only, human decides): 2.1.4, 2.2.

TRUSTED_SECURITY_SERVICES = [
    "cloudtrail.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "config.amazonaws.com",
    "access-analyzer.amazonaws.com",
]


def _org_client(session):
    # Organizations is a global service; the API is only served from us-east-1.
    return session.client("organizations", region_name="us-east-1")


def check_2_1_1(session):
    cid, name = "2.1.1", "Ensure centralized root access in AWS Organizations"
    api = "iam:ListOrganizationsFeatures"
    try:
        iam = session.client("iam")
        features = iam.list_organizations_features().get("EnabledFeatures", [])
        ev = _evidence(api, f"EnabledFeatures={features}")
        if "RootCredentialsManagement" in features:
            return _finding(cid, D_IAM, name, "PASS",
                             "Centralized root access management is enabled for the organization.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         "Centralized root access management is not enabled for the organization.",
                         "organization root settings", evidence=ev)
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_1_2(session):
    cid, name = "2.1.2", "Ensure authorization guardrails for all AWS Organization accounts"
    api = "organizations:ListRoots, organizations:ListPoliciesForTarget"
    try:
        org = _org_client(session)
        roots = org.list_roots().get("Roots", [])
        if not roots:
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "No organization roots found"))
        root_id = roots[0]["Id"]
        policies = org.list_policies_for_target(TargetId=root_id, Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
        names = [p["Name"] for p in policies]
        non_default = [n for n in names if n != "FullAWSAccess"]
        ev = _evidence(api, f"SCPs attached at org root: {names}")
        if non_default:
            return _finding(cid, D_IAM, name, "PASS",
                             f"Custom Service Control Policies are attached at the organization root: {', '.join(non_default)}.",
                             evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         "Only the default 'FullAWSAccess' policy is attached at the organization root; "
                         "no baseline guardrail SCPs are enforced.",
                         "organization root", evidence=ev)
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        if code == "AccessDeniedException":
            return _finding(cid, D_IAM, name, "MANUAL_REVIEW",
                             "This account cannot query Organizations policies directly (requires management or "
                             "delegated admin access). Verify SCPs manually from the management account.",
                             evidence=_evidence(api, f"AccessDenied: {e}"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_1_3(session, regions):
    cid, name = "2.1.3", "Ensure Organizations management account is not used for workloads"
    api = "organizations:DescribeOrganization, sts:GetCallerIdentity, lambda:ListFunctions, ec2:DescribeInstances, rds:DescribeDBInstances"
    try:
        org = _org_client(session)
        mgmt_account_id = org.describe_organization()["Organization"].get("MasterAccountId")
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))

    try:
        this_account_id = session.client("sts").get_caller_identity()["Account"]
    except Exception:
        this_account_id = None

    if this_account_id != mgmt_account_id:
        return _finding(cid, D_IAM, name, "N/A", "This account is not the Organizations management account.",
                         evidence=_evidence(api, f"This account={this_account_id}, management account={mgmt_account_id}"))

    lambdas, instances, dbs = [], [], []
    try:
        paginator = session.client("lambda").get_paginator("list_functions")
        for page in paginator.paginate():
            lambdas.extend(f["FunctionName"] for f in page["Functions"])
    except Exception:
        pass
    for region in regions:
        try:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
                for res in page["Reservations"]:
                    instances.extend(f"{i['InstanceId']} ({region})" for i in res["Instances"])
        except Exception:
            pass
        try:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                dbs.extend(f"{d['DBInstanceIdentifier']} ({region})" for d in page["DBInstances"])
        except Exception:
            pass

    total = len(lambdas) + len(instances) + len(dbs)
    ev = _evidence(api, f"Lambdas={len(lambdas)}, EC2={len(instances)}, RDS={len(dbs)} in management account")
    if total == 0:
        return _finding(cid, D_IAM, name, "PASS",
                         "No Lambda functions, EC2 instances, or RDS databases were found in the management account.",
                         evidence=ev)
    affected = "; ".join((lambdas[:10] + instances[:10] + dbs[:10]))
    return _finding(cid, D_IAM, name, "MANUAL_REVIEW",
                     f"The management account contains {total} resource(s) ({len(lambdas)} Lambda, {len(instances)} EC2, "
                     f"{len(dbs)} RDS). Confirm with the account owner whether these are workloads or acceptable "
                     f"governance/security tooling.",
                     affected, evidence=ev)


def check_2_1_4(session):
    cid, name = "2.1.4", "Ensure Organizational Units are structured by environment and sensitivity"
    api = "organizations:ListRoots, organizations:ListOrganizationalUnitsForParent, organizations:ListAccountsForParent"
    guidance = "Verify the OU structure separates accounts by environment (prod/non-prod) and data sensitivity."
    try:
        org = _org_client(session)
        roots = org.list_roots().get("Roots", [])
        if not roots:
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "No organization roots found"))
        root_id = roots[0]["Id"]
        tree_lines = [f"Root: {roots[0].get('Name', root_id)}"]

        def walk(parent_id, depth):
            ous = org.list_organizational_units_for_parent(ParentId=parent_id).get("OrganizationalUnits", [])
            accounts = org.list_accounts_for_parent(ParentId=parent_id).get("Accounts", [])
            for a in accounts:
                tree_lines.append("  " * (depth + 1) + f"Account: {a.get('Name')} ({a.get('Id')})")
            for ou in ous:
                tree_lines.append("  " * depth + f"OU: {ou.get('Name')} ({ou.get('Id')})")
                if depth < 3:
                    walk(ou["Id"], depth + 1)

        walk(root_id, 1)
        tree_str = "\n".join(tree_lines[:60])
        return _finding(cid, D_IAM, name, "MANUAL_REVIEW", guidance,
                         f"{len(tree_lines) - 1} OU/account entries (see evidence)",
                         evidence=_evidence(api, tree_str))
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        if code == "AccessDeniedException":
            return _finding(cid, D_IAM, name, "MANUAL_REVIEW", guidance,
                             evidence=_evidence(api, f"AccessDenied — cannot list OU structure from this account: {e}"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_1_5(session):
    cid, name = "2.1.5", "Ensure delegated admin manages AWS Organizations policies"
    api = "organizations:DescribeResourcePolicy"
    try:
        org = _org_client(session)
        org.describe_resource_policy()
        return _finding(cid, D_IAM, name, "PASS",
                         "An Organizations resource policy exists, indicating delegated management is configured.",
                         evidence=_evidence(api, "Resource policy found"))
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        if code == "ResourcePolicyNotFoundException":
            return _finding(cid, D_IAM, name, "FAIL",
                             "No Organizations resource policy is configured; policies are not being managed via "
                             "a delegated mechanism.", "organization",
                             evidence=_evidence(api, "No resource policy configured"))
        if code == "AccessDeniedException":
            return _finding(cid, D_IAM, name, "MANUAL_REVIEW",
                             "This account cannot query the Organizations resource policy directly. Verify from "
                             "the management account whether SCP/RCP management is delegated.",
                             evidence=_evidence(api, f"AccessDenied: {e}"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_1_6(session):
    cid, name = "2.1.6", "Ensure delegated admins manage AWS Organizations-integrated services"
    api = "organizations:ListDelegatedAdministrators"
    try:
        org = _org_client(session)
        delegated = set()
        for svc in TRUSTED_SECURITY_SERVICES:
            try:
                if org.list_delegated_administrators(ServicePrincipal=svc).get("DelegatedAdministrators"):
                    delegated.add(svc)
            except botocore.exceptions.ClientError:
                continue
        ev = _evidence(api, f"Delegated for: {sorted(delegated)} out of {TRUSTED_SECURITY_SERVICES}")
        if delegated:
            return _finding(cid, D_IAM, name, "PASS",
                             f"Delegated administrator(s) manage {len(delegated)} of {len(TRUSTED_SECURITY_SERVICES)} "
                             f"key org-integrated security services.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         "No delegated administrator is registered for any key org-integrated security service "
                         "(CloudTrail, GuardDuty, Security Hub, Config, Access Analyzer); these are administered "
                         "from the management account.", "organization", evidence=ev)
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AWSOrganizationsNotInUseException":
            return _finding(cid, D_IAM, name, "N/A", "This account is not part of an AWS Organization.",
                             evidence=_evidence(api, "Not in an AWS Organization"))
        if code == "AccessDeniedException":
            return _finding(cid, D_IAM, name, "MANUAL_REVIEW",
                             "This account cannot query delegated administrators directly. Verify from the "
                             "management account.", evidence=_evidence(api, f"AccessDenied: {e}"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


_PERSONAL_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "ymail.com", "hotmail.com", "outlook.com",
    "aol.com", "icloud.com", "live.com", "proton.me", "protonmail.com",
}


def _mask_email(addr):
    # Contact details in 2.2/2.3 can include personal addresses; this report
    # is emailed outside the company, so we never put the raw address in the
    # output — only enough to identify the provider/domain for review.
    if not addr or "@" not in addr:
        return addr or "-"
    local, _, domain = addr.partition("@")
    if len(local) <= 2:
        masked_local = (local[0] + "*") if local else "*"
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


def _mask_phone(phone):
    if not phone:
        return "-"
    digits = "".join(ch for ch in str(phone) if ch.isdigit())
    if not digits or set(digits) == {"0"}:
        return "(placeholder/invalid number)"
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def _email_domain(addr):
    return addr.partition("@")[2].lower() if addr and "@" in addr else ""


def check_2_2(session):
    cid, name = "2.2", "Maintain current AWS account contact details"
    api = "account:GetContactInformation, account:GetAlternateContact"
    guidance = ("Verify the account's primary, billing, operations and security contact details are current "
                "in Account Settings.")
    try:
        acct = session.client("account")
        primary, primary_err = {}, None
        try:
            # NOTE: GetContactInformation's response has no EmailAddress field
            # (name/phone/address only) — the account's email is the root
            # sign-in email, not retrievable via this API.
            primary = acct.get_contact_information().get("ContactInformation", {})
        except botocore.exceptions.ClientError as e:
            primary_err = e.response["Error"]["Code"]
        except Exception as e:
            primary_err = str(e)

        alt_summary = {}
        for t in ("BILLING", "OPERATIONS", "SECURITY"):
            try:
                c = acct.get_alternate_contact(AlternateContactType=t).get("AlternateContact", {})
                alt_summary[t] = f"{c.get('Name', '-')} <{_mask_email(c.get('EmailAddress', ''))}>"
            except botocore.exceptions.ClientError as e:
                code = e.response["Error"]["Code"]
                alt_summary[t] = "not set" if code == "ResourceNotFoundException" else f"could not read ({code})"

        unset = [t for t, v in alt_summary.items() if v == "not set"]
        unreadable = [t for t, v in alt_summary.items() if v.startswith("could not read")]
        primary_phone_masked = _mask_phone(primary.get("PhoneNumber", ""))
        placeholder_phone = primary_phone_masked == "(placeholder/invalid number)"
        primary_line = (f"Primary contact: could not read ({primary_err})" if primary_err
                         else f"Primary contact: {primary.get('FullName', '-')}, Phone: {primary_phone_masked}")
        ev_text = f"{primary_line}; Alternate contacts: {alt_summary}"
        summary = guidance
        if unset:
            summary += f" Currently not set: {', '.join(unset)} alternate contact."
        if unreadable:
            summary += f" Could not read: {', '.join(unreadable)} alternate contact."
        if placeholder_phone:
            summary += " Primary contact phone looks like a placeholder/invalid number."
        affected = f"Primary: {('could not read' if primary_err else primary.get('FullName', '-'))}"
        return _finding(cid, D_IAM, name, "MANUAL_REVIEW", summary, affected, evidence=_evidence(api, ev_text))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_3(session):
    cid, name = "2.3", "Ensure security contact information is registered"
    api = "account:GetAlternateContact"
    try:
        c = session.client("account").get_alternate_contact(AlternateContactType="SECURITY").get("AlternateContact", {})
        email = c.get("EmailAddress", "")
        domain = _email_domain(email)
        masked_email = _mask_email(email)
        masked_phone = _mask_phone(c.get("PhoneNumber", ""))
        flag = ""
        if domain in _PERSONAL_EMAIL_DOMAINS:
            flag = f" It uses a personal/free email domain ({domain}) rather than a team mailbox."
        summary = f"A security alternate contact is registered ({masked_email}).{flag}"
        ev_text = f"Name={c.get('Name', '-')}, Email domain={domain or '-'}, Phone={masked_phone}"
        return _finding(cid, D_IAM, name, "PASS", summary, masked_email, evidence=_evidence(api, ev_text))
    except botocore.exceptions.ClientError as e:
        if e.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return _finding(cid, D_IAM, name, "FAIL", "No security alternate contact is registered for this account.",
                             "account alternate contacts", evidence=_evidence(api, "No security contact configured"))
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_6(iam):
    cid, name = "2.6", "Ensure hardware MFA is enabled for the 'root' user account"
    api = "iam:GetAccountSummary, iam:ListVirtualMFADevices"
    try:
        if iam.get_account_summary()["SummaryMap"].get("AccountMFAEnabled", 0) != 1:
            return _finding(cid, D_IAM, name, "FAIL", "MFA is not enabled on the root account at all.",
                             "root user", evidence=_evidence(api, "AccountMFAEnabled=0"))
        root_has_virtual = False
        paginator = iam.get_paginator("list_virtual_mfa_devices")
        for page in paginator.paginate(AssignmentStatus="Assigned"):
            for dev in page["VirtualMFADevices"]:
                if dev.get("User", {}).get("Arn", "").endswith(":root"):
                    root_has_virtual = True
        ev = _evidence(api, f"root uses virtual MFA={root_has_virtual}")
        if root_has_virtual:
            return _finding(cid, D_IAM, name, "FAIL",
                             "Root's MFA device is a virtual MFA app, not a hardware (or FIDO2) device.",
                             "root user", evidence=ev)
        return _finding(cid, D_IAM, name, "PASS",
                         "Root has MFA enabled and it is not a virtual MFA device (hardware/FIDO2 assumed).",
                         evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_7(session, regions):
    cid, name = "2.7", "Eliminate use of the 'root' user for administrative and daily tasks"
    api = "cloudtrail:LookupEvents"
    # NOTE: lookup_events is region-scoped (it only returns the Event History
    # for the region the client is created in), and the Username LookupAttribute
    # is not a reliable proxy for root activity across all event types. Instead,
    # we scan each checked region's event history and inspect the raw
    # CloudTrailEvent's userIdentity.type == "Root", which is the authoritative
    # signal, bounded to a few pages per region to control execution time.
    try:
        from datetime import timedelta
        start = _now() - timedelta(days=90)
        per_region_hits = {}
        sample_events = []
        for region in regions:
            try:
                ct = session.client("cloudtrail", region_name=region)
                paginator = ct.get_paginator("lookup_events")
                found_in_region = 0
                pages_seen = 0
                for page in paginator.paginate(StartTime=start, EndTime=_now()):
                    pages_seen += 1
                    for e in page.get("Events", []):
                        try:
                            detail = json.loads(e.get("CloudTrailEvent", "{}"))
                        except Exception:
                            detail = {}
                        if detail.get("userIdentity", {}).get("type") == "Root":
                            found_in_region += 1
                            if len(sample_events) < 10:
                                sample_events.append(f"{e.get('EventName', '?')} ({region}, {e.get('EventTime')})")
                    if found_in_region or pages_seen >= 4:
                        break
                if found_in_region:
                    per_region_hits[region] = found_in_region
            except Exception:
                continue
        ev = _evidence(api, f"Root events found in: {per_region_hits}" if per_region_hits
                       else f"No root events found across {len(regions)} checked region(s)")
        if not per_region_hits:
            return _finding(cid, D_IAM, name, "PASS",
                             "No root user activity found in CloudTrail over the last 90 days across checked regions.",
                             evidence=ev)
        breakdown = ", ".join(f"{r}: {c}+ event(s)" for r, c in per_region_hits.items())
        return _finding(cid, D_IAM, name, "FAIL",
                         f"Root user activity was found in CloudTrail within the last 90 days in "
                         f"{len(per_region_hits)} region(s) ({breakdown}).",
                         "; ".join(sample_events[:10]), evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_2_19(session, cred_report):
    cid, name = "2.19", "Ensure IAM users are managed centrally via identity federation or AWS Organizations"
    api = "iam:GetCredentialReport, sso-admin:ListInstances, iam:ListSAMLProviders"
    console_users = [r["user"] for r in (cred_report or [])
                      if r["user"] != "<root_account>" and r.get("password_enabled") == "true"]
    sso_enabled, saml_count = False, 0
    try:
        sso_enabled = len(session.client("sso-admin").list_instances().get("Instances", [])) > 0
    except Exception:
        pass
    try:
        saml_count = len(session.client("iam").list_saml_providers().get("SAMLProviderList", []))
    except Exception:
        pass
    ev = _evidence(api, f"console users={len(console_users)}, IAM Identity Center enabled={sso_enabled}, SAML providers={saml_count}")
    affected = ", ".join(console_users[:20]) + (" ..." if len(console_users) > 20 else "") if console_users else "-"
    if sso_enabled or saml_count > 0:
        status = "PASS" if not console_users else "MANUAL_REVIEW"
        summary = (f"Identity federation is configured (IAM Identity Center={sso_enabled}, SAML providers={saml_count}); "
                   f"{len(console_users)} native IAM user(s) still have console passwords.")
    else:
        status = "MANUAL_REVIEW" if not console_users else "FAIL"
        summary = f"No IAM Identity Center or SAML federation detected; {len(console_users)} native IAM user(s) have console passwords."
    return _finding(cid, D_IAM, name, status, summary, affected, evidence=ev)


def check_2_20(iam):
    cid, name = "2.20", "Ensure access to AWSCloudShellFullAccess is restricted"
    api = "iam:ListEntitiesForPolicy"
    policy_arn = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
    try:
        entities = iam.list_entities_for_policy(PolicyArn=policy_arn)
        users = [u["UserName"] for u in entities.get("PolicyUsers", [])]
        groups = [g["GroupName"] for g in entities.get("PolicyGroups", [])]
        roles = [r["RoleName"] for r in entities.get("PolicyRoles", [])]
        total = users + groups + roles
        ev = _evidence(api, f"Users={users}, Groups={groups}, Roles={roles}")
        if not total:
            return _finding(cid, D_IAM, name, "PASS",
                             "AWSCloudShellFullAccess is not attached to any user, group, or role.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"AWSCloudShellFullAccess is attached to {len(total)} identit(y/ies); verify this access is required.",
                         ", ".join(total[:20]), evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def _policy_statements(policy_doc):
    stmts = policy_doc.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else stmts


def _has_wildcard_principal(stmt):
    if stmt.get("Effect") != "Allow":
        return False
    principal = stmt.get("Principal")
    is_wildcard = principal == "*" or (isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"]))
    return is_wildcard and "Condition" not in stmt


def check_2_21(session, regions):
    cid, name = "2.21", "Ensure AWS resource policies do not allow unrestricted access using \"Principal\": \"*\""
    api = ("s3:GetBucketPolicy, sns:GetTopicAttributes, sqs:GetQueueAttributes, kms:GetKeyPolicy, "
           "lambda:GetPolicy, accessanalyzer:ListFindings")
    offenders, checked = [], 0

    try:
        s3 = session.client("s3")
        for b in s3.list_buckets().get("Buckets", []):
            checked += 1
            try:
                doc = json.loads(s3.get_bucket_policy(Bucket=b["Name"])["Policy"])
                if any(_has_wildcard_principal(s) for s in _policy_statements(doc)):
                    offenders.append(f"s3:{b['Name']}")
            except botocore.exceptions.ClientError:
                continue
    except Exception:
        pass

    for region in regions:
        try:
            sns = session.client("sns", region_name=region)
            paginator = sns.get_paginator("list_topics")
            for page in paginator.paginate():
                for t in page["Topics"]:
                    checked += 1
                    try:
                        attrs = sns.get_topic_attributes(TopicArn=t["TopicArn"])["Attributes"]
                        doc = json.loads(attrs.get("Policy", "{}"))
                        if any(_has_wildcard_principal(s) for s in _policy_statements(doc)):
                            offenders.append(f"sns:{t['TopicArn']}")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            sqs = session.client("sqs", region_name=region)
            for url in sqs.list_queues().get("QueueUrls", []):
                checked += 1
                try:
                    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["Policy"])["Attributes"]
                    doc = json.loads(attrs.get("Policy", "{}"))
                    if any(_has_wildcard_principal(s) for s in _policy_statements(doc)):
                        offenders.append(f"sqs:{url}")
                except Exception:
                    continue
        except Exception:
            pass
        try:
            kms = session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for k in page["Keys"]:
                    checked += 1
                    try:
                        doc = json.loads(kms.get_key_policy(KeyId=k["KeyId"], PolicyName="default")["Policy"])
                        if any(_has_wildcard_principal(s) for s in _policy_statements(doc)):
                            offenders.append(f"kms:{k['KeyId']} ({region})")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            lam = session.client("lambda", region_name=region)
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate():
                for fn in page["Functions"]:
                    checked += 1
                    try:
                        doc = json.loads(lam.get_policy(FunctionName=fn["FunctionName"])["Policy"])
                        if any(_has_wildcard_principal(s) for s in _policy_statements(doc)):
                            offenders.append(f"lambda:{fn['FunctionName']} ({region})")
                    except botocore.exceptions.ClientError:
                        continue
        except Exception:
            pass

    aa_findings = 0
    try:
        aa = session.client("accessanalyzer", region_name=regions[0] if regions else "us-east-1")
        analyzers = (aa.list_analyzers(type="ACCOUNT").get("analyzers", [])
                     + aa.list_analyzers(type="ORGANIZATION").get("analyzers", []))
        for analyzer in analyzers:
            paginator = aa.get_paginator("list_findings")
            for page in paginator.paginate(analyzerArn=analyzer["arn"], filter={"isPublic": {"eq": ["true"]}}):
                aa_findings += len(page.get("findings", []))
    except Exception:
        pass

    ev = _evidence(api, f"Checked {checked} resource(s); {len(offenders)} wildcard-principal polic(y/ies); "
                        f"{aa_findings} Access Analyzer public finding(s)")
    if not offenders and aa_findings == 0:
        return _finding(cid, D_IAM, name, "PASS",
                         "No S3/SNS/SQS/KMS/Lambda resource policy grants Principal \"*\" without a condition, "
                         "and Access Analyzer reports no public findings.", evidence=ev)
    affected = ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else "") if offenders else "-"
    return _finding(cid, D_IAM, name, "FAIL",
                     f"{len(offenders)} resource polic(y/ies) grant Principal \"*\" without a condition, and "
                     f"Access Analyzer reports {aa_findings} public finding(s).", affected, evidence=ev)


def check_2_4(iam):
    cid, name = "2.4", "Ensure no 'root' user account access key exists"
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        keys_present = summary.get("AccountAccessKeysPresent", 0)
        ev = _evidence("iam:GetAccountSummary", f"AccountAccessKeysPresent={keys_present}")
        if keys_present == 0:
            return _finding(cid, D_IAM, name, "PASS", "No access keys exist for the root account.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         "The root account has at least one active access key.",
                         "root user", evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_5(iam):
    cid, name = "2.5", "Ensure MFA is enabled for the 'root' user account"
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0)
        ev = _evidence("iam:GetAccountSummary", f"AccountMFAEnabled={mfa_enabled}")
        if mfa_enabled == 1:
            return _finding(cid, D_IAM, name, "PASS", "MFA is enabled on the root account.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL", "MFA is NOT enabled on the root account.", "root user", evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_8(iam):
    cid, name = "2.8", "Ensure IAM password policy requires minimum length of 14 or greater"
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        min_len = policy.get("MinimumPasswordLength", 0)
        ev = _evidence("iam:GetAccountPasswordPolicy", f"MinimumPasswordLength={min_len}")
        if min_len >= 14:
            return _finding(cid, D_IAM, name, "PASS", f"Minimum password length is {min_len}.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL", f"Minimum password length is only {min_len} (requires >= 14).",
                         "account password policy", evidence=ev)
    except iam.exceptions.NoSuchEntityException:
        return _finding(cid, D_IAM, name, "FAIL", "No account password policy is configured.",
                         "account password policy",
                         evidence=_evidence("iam:GetAccountPasswordPolicy", "No password policy configured"))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_9(iam):
    cid, name = "2.9", "Ensure IAM password policy prevents password reuse"
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        reuse = policy.get("PasswordReusePrevention", 0)
        ev = _evidence("iam:GetAccountPasswordPolicy", f"PasswordReusePrevention={reuse}")
        if reuse >= 24:
            return _finding(cid, D_IAM, name, "PASS", f"Password reuse prevention is set to {reuse}.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"Password reuse prevention is {reuse} (CIS recommends >= 24).",
                         "account password policy", evidence=ev)
    except iam.exceptions.NoSuchEntityException:
        return _finding(cid, D_IAM, name, "FAIL", "No account password policy is configured.",
                         "account password policy",
                         evidence=_evidence("iam:GetAccountPasswordPolicy", "No password policy configured"))
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_10(cred_report):
    cid, name = "2.10", "Ensure multi-factor authentication (MFA) is enabled for all IAM users with a console password"
    offenders = []
    for row in cred_report:
        if row["user"] == "<root_account>":
            continue
        if row.get("password_enabled") == "true" and row.get("mfa_active") == "false":
            offenders.append(row["user"])
    real_users = [r for r in cred_report if r["user"] != "<root_account>"]
    ev = _evidence("iam:GetCredentialReport",
                   f"{len(real_users)} IAM user(s) evaluated, {len(offenders)} without MFA")
    if not offenders:
        return _finding(cid, D_IAM, name, "PASS", "All console users have MFA enabled.", evidence=ev)
    return _finding(cid, D_IAM, name, "FAIL",
                     f"{len(offenders)} IAM user(s) with a console password do not have MFA enabled.",
                     ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                     evidence=ev)


def check_2_11(cred_report):
    cid, name = "2.11", "Ensure credentials unused for 45 days or more are disabled"
    offenders = []
    for row in cred_report:
        if row["user"] == "<root_account>":
            continue
        user = row["user"]
        if row.get("password_enabled") == "true":
            days = _days_since(row.get("password_last_used"))
            created_days = _days_since(row.get("user_creation_time"))
            if days is not None and days >= 45:
                offenders.append(f"{user} (password unused {days}d)")
            elif days is None and created_days is not None and created_days >= 45:
                offenders.append(f"{user} (password never used, created {created_days}d ago)")
        for idx in ("1", "2"):
            active = row.get(f"access_key_{idx}_active")
            if active == "true":
                last_used = row.get(f"access_key_{idx}_last_used_date")
                days = _days_since(last_used)
                created_days = _days_since(row.get(f"access_key_{idx}_last_rotated"))
                if days is not None and days >= 45:
                    offenders.append(f"{user} (access key {idx} unused {days}d)")
                elif days is None and created_days is not None and created_days >= 45:
                    offenders.append(f"{user} (access key {idx} never used, created {created_days}d ago)")
    real_users = [r for r in cred_report if r["user"] != "<root_account>"]
    ev = _evidence("iam:GetCredentialReport",
                   f"{len(real_users)} IAM user(s) evaluated, {len(offenders)} unused credentials found")
    if not offenders:
        return _finding(cid, D_IAM, name, "PASS", "No credentials unused for 45+ days were found.", evidence=ev)
    return _finding(cid, D_IAM, name, "FAIL",
                     f"{len(offenders)} credential(s) unused for 45+ days and still enabled.",
                     "; ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                     evidence=ev)


def check_2_12(iam):
    cid, name = "2.12", "Ensure access keys are rotated every 90 days or less"
    offenders = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
                for k in keys:
                    if k["Status"] != "Active":
                        continue
                    age = _days_since(k["CreateDate"])
                    if age is not None and age > 90:
                        offenders.append(f"{user['UserName']} (key age {age}d)")
        ev = _evidence("iam:ListUsers, iam:ListAccessKeys",
                       f"Checked all IAM users; {len(offenders)} key(s) older than 90 days")
        if not offenders:
            return _finding(cid, D_IAM, name, "PASS", "All active access keys are 90 days old or newer.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(offenders)} active access key(s) older than 90 days.",
                         "; ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_13(iam):
    cid, name = "2.13", "Ensure IAM users receive permissions only through groups"
    offenders = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                uname = user["UserName"]
                attached = iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                inline = iam.list_user_policies(UserName=uname)["PolicyNames"]
                if attached or inline:
                    offenders.append(uname)
        ev = _evidence("iam:ListUsers, iam:ListAttachedUserPolicies, iam:ListUserPolicies",
                       f"Checked all IAM users; {len(offenders)} with direct policy attachments")
        if not offenders:
            return _finding(cid, D_IAM, name, "PASS", "No IAM users have policies attached directly.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(offenders)} IAM user(s) have policies attached directly instead of via a group.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_14(iam):
    cid, name = "2.14", "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached"
    offenders = []
    try:
        paginator = iam.get_paginator("list_policies")
        for page in paginator.paginate(Scope="Local", OnlyAttached=True):
            for pol in page["Policies"]:
                version = iam.get_policy_version(
                    PolicyArn=pol["Arn"], VersionId=pol["DefaultVersionId"]
                )["PolicyVersion"]
                doc = version["Document"]
                stmts = doc["Statement"]
                if isinstance(stmts, dict):
                    stmts = [stmts]
                for s in stmts:
                    if s.get("Effect") != "Allow":
                        continue
                    actions = s.get("Action", [])
                    resources = s.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in actions and "*" in resources:
                        offenders.append(pol["PolicyName"])
                        break
        ev = _evidence("iam:ListPolicies(Scope=Local,OnlyAttached=True), iam:GetPolicyVersion",
                       f"Checked attached customer-managed policies; {len(offenders)} grant full admin")
        if not offenders:
            return _finding(cid, D_IAM, name, "PASS",
                             "No attached customer-managed policy grants full \"*:*\" access.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(offenders)} attached policy(ies) grant full administrative (*:*) access.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_15(iam):
    cid, name = "2.15", "Ensure a support role has been created to manage incidents with AWS Support"
    try:
        support_policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
        entities = iam.list_entities_for_policy(
            PolicyArn=support_policy_arn, EntityFilter="Role"
        )
        roles = entities.get("PolicyRoles", [])
        ev = _evidence("iam:ListEntitiesForPolicy(AWSSupportAccess)",
                       f"{len(roles)} role(s) have AWSSupportAccess attached")
        if roles:
            return _finding(cid, D_IAM, name, "PASS",
                             "AWSSupportAccess is attached to at least one role.",
                             ", ".join(r["RoleName"] for r in roles), evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         "AWSSupportAccess is not attached to any IAM role.", evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_16(session, regions):
    cid, name = "2.16", "Ensure IAM instance roles are used for AWS resource access from instances"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        checked_any = True
                        if "IamInstanceProfile" not in inst:
                            offenders.append(f"{inst['InstanceId']} ({region})")
        if not checked_any:
            return _finding(cid, D_IAM, name, "N/A", "No EC2 instances found in any checked region.",
                             evidence=_evidence("ec2:DescribeInstances", "No EC2 instances found"))
        ev = _evidence("ec2:DescribeInstances",
                       f"Checked {len(regions)} region(s); {len(offenders)} instance(s) without instance profile")
        if not offenders:
            return _finding(cid, D_IAM, name, "PASS", "All EC2 instances have an IAM instance profile attached.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(offenders)} EC2 instance(s) have no IAM instance profile attached.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_17(iam):
    cid, name = "2.17", "Ensure that all expired SSL/TLS certificates stored in AWS IAM are removed"
    offenders = []
    total_certs = 0
    try:
        paginator = iam.get_paginator("list_server_certificates")
        for page in paginator.paginate():
            for cert in page["ServerCertificateMetadataList"]:
                total_certs += 1
                if cert["Expiration"] < _now():
                    offenders.append(cert["ServerCertificateName"])
        ev = _evidence("iam:ListServerCertificates",
                        f"{total_certs} IAM server certificate(s) found, {len(offenders)} expired")
        if total_certs == 0:
            return _finding(cid, D_IAM, name, "N/A", "No IAM server certificates exist to assess.", evidence=ev)
        if not offenders:
            return _finding(cid, D_IAM, name, "PASS", "No expired SSL/TLS certificates are stored in IAM.", evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(offenders)} expired SSL/TLS certificate(s) still stored in IAM.",
                         ", ".join(offenders), evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_2_18(session, regions):
    cid, name = "2.18", "Ensure that IAM External Access Analyzer is enabled for all regions"
    missing = []
    try:
        for region in regions:
            aa = session.client("accessanalyzer", region_name=region)
            analyzers = aa.list_analyzers()["analyzers"]
            active = [a for a in analyzers if a["status"] == "ACTIVE"]
            if not active:
                missing.append(region)
        ev = _evidence("accessanalyzer:ListAnalyzers",
                       f"Checked {len(regions)} region(s); {len(missing)} without active analyzer")
        if not missing:
            return _finding(cid, D_IAM, name, "PASS",
                             f"An active external Access Analyzer exists in all {len(regions)} checked region(s).",
                             evidence=ev)
        return _finding(cid, D_IAM, name, "FAIL",
                         f"{len(missing)} region(s) have no active external Access Analyzer.",
                         ", ".join(missing), evidence=ev)
    except Exception as e:
        return _finding(cid, D_IAM, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def run_iam_domain(session, iam, regions):
    findings = []

    findings.append(check_2_4(iam))
    findings.append(check_2_5(iam))
    findings.append(check_2_8(iam))
    findings.append(check_2_9(iam))

    try:
        cred_report = _get_credential_report(iam)
    except Exception as e:
        cred_report = None
        findings.append(_finding("2.10", D_IAM,
                                  "Ensure multi-factor authentication (MFA) is enabled for all IAM users with a console password",
                                  "ERROR", f"Could not generate/read credential report: {e}",
                                  evidence=_evidence("Error", str(e))))
        findings.append(_finding("2.11", D_IAM, "Ensure credentials unused for 45 days or more are disabled",
                                  "ERROR", f"Could not generate/read credential report: {e}",
                                  evidence=_evidence("Error", str(e))))

    if cred_report is not None:
        try:
            findings.append(check_2_10(cred_report))
        except Exception as e:
            findings.append(_finding("2.10", D_IAM,
                                      "Ensure multi-factor authentication (MFA) is enabled for all IAM users with a console password",
                                      "ERROR", f"Could not evaluate: {e}",
                                      evidence=_evidence("Error", str(e))))
        try:
            findings.append(check_2_11(cred_report))
        except Exception as e:
            findings.append(_finding("2.11", D_IAM, "Ensure credentials unused for 45 days or more are disabled",
                                      "ERROR", f"Could not evaluate: {e}",
                                      evidence=_evidence("Error", str(e))))

    findings.append(check_2_12(iam))
    findings.append(check_2_13(iam))
    findings.append(check_2_14(iam))
    findings.append(check_2_15(iam))
    findings.append(check_2_16(session, regions))
    findings.append(check_2_17(iam))
    findings.append(check_2_18(session, regions))
    findings.append(check_2_20(iam))
    findings.append(check_2_6(iam))

    findings.append(check_2_1_1(session))
    findings.append(check_2_1_2(session))
    findings.append(check_2_1_3(session, regions))
    findings.append(check_2_1_4(session))
    findings.append(check_2_1_5(session))
    findings.append(check_2_1_6(session))
    findings.append(check_2_2(session))
    findings.append(check_2_3(session))
    findings.append(check_2_7(session, regions))
    findings.append(check_2_19(session, cred_report))
    findings.append(check_2_21(session, regions))

    return findings


# ===========================================================================
# Domain 2: Storage
# ===========================================================================

D_STORAGE = "Storage"

# 3.1.2, 3.1.3, 3.2.4 are Tier 1 (full automation) — see check_3_1_2, check_3_1_3,
# check_3_2_4 below (previously generic MANUAL_REVIEW controls).


def check_3_1_2(s3):
    cid, name = "3.1.2", "Ensure MFA Delete is enabled on S3 buckets"
    api = "s3:ListBuckets, s3:GetBucketVersioning"
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not list S3 buckets: {e}", evidence=_evidence(api, str(e)))
    if not buckets:
        return _finding(cid, D_STORAGE, name, "N/A", "No S3 buckets exist in this account.",
                         evidence=_evidence(api, "No S3 buckets exist"))
    offenders = []
    for b in buckets:
        try:
            v = s3.get_bucket_versioning(Bucket=b["Name"])
            if v.get("MFADelete") != "Enabled":
                offenders.append(b["Name"])
        except Exception:
            offenders.append(f"{b['Name']} (could not verify)")
    ev = _evidence(api, f"{len(buckets)} bucket(s) checked; {len(offenders)} without MFA Delete")
    if not offenders:
        return _finding(cid, D_STORAGE, name, "PASS", "All S3 buckets have MFA Delete enabled.", evidence=ev)
    return _finding(cid, D_STORAGE, name, "FAIL",
                     f"{len(offenders)} bucket(s) do not have MFA Delete enabled.",
                     ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)


def check_3_1_3(session, regions):
    cid, name = "3.1.3", "Ensure all data in Amazon S3 has been discovered, classified, and secured when necessary"
    api = "macie2:GetMacieSession, macie2:ListClassificationJobs"
    missing, checked_any = [], False
    for region in regions:
        try:
            macie = session.client("macie2", region_name=region)
            try:
                status = macie.get_macie_session().get("status")
            except botocore.exceptions.ClientError as e:
                if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
                    missing.append(f"{region} (Macie not enabled)")
                    checked_any = True
                    continue
                raise
            checked_any = True
            if status != "ENABLED":
                missing.append(f"{region} (Macie not enabled)")
                continue
            if not macie.list_classification_jobs().get("items", []):
                missing.append(f"{region} (no classification job)")
        except Exception:
            continue
    ev = _evidence(api, f"Checked {len(regions)} region(s); {len(missing)} without active Macie classification")
    if not checked_any:
        return _finding(cid, D_STORAGE, name, "ERROR", "Could not query Macie in any region.", evidence=ev)
    if not missing:
        return _finding(cid, D_STORAGE, name, "PASS",
                         "Macie is enabled with an active classification job in all checked regions.", evidence=ev)
    return _finding(cid, D_STORAGE, name, "FAIL",
                     f"{len(missing)} region(s) do not have an active Macie classification job.",
                     ", ".join(missing[:20]), evidence=ev)


def check_3_2_4(session, regions):
    cid, name = "3.2.4", "Ensure Multi-AZ deployments are used for enhanced availability in Amazon RDS"
    api = "rds:DescribeDBInstances"
    offenders, checked_any = [], False
    try:
        for region in regions:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    checked_any = True
                    if not db.get("MultiAZ", False):
                        offenders.append(f"{db['DBInstanceIdentifier']} ({region})")
        if not checked_any:
            return _finding(cid, D_STORAGE, name, "N/A", "No RDS instances found in any checked region.",
                             evidence=_evidence(api, f"Checked {len(regions)} region(s); no RDS instances"))
        ev = _evidence(api, f"Checked {len(regions)} region(s); {len(offenders)} without Multi-AZ")
        if not offenders:
            return _finding(cid, D_STORAGE, name, "PASS", "All RDS instances have Multi-AZ enabled.", evidence=ev)
        return _finding(cid, D_STORAGE, name, "FAIL",
                         f"{len(offenders)} RDS instance(s) do not have Multi-AZ enabled.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def _bucket_denies_insecure_transport(policy_doc):
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if s.get("Effect") != "Deny":
            continue
        cond = s.get("Condition", {})
        bool_cond = cond.get("Bool", {})
        for key, val in bool_cond.items():
            if key.lower() == "aws:securetransport":
                val_str = str(val).lower() if not isinstance(val, list) else str(val[0]).lower()
                if val_str == "false":
                    return True
    return False


def check_3_1_1(s3):
    cid, name = "3.1.1", "Ensure S3 Bucket Policy is set to deny HTTP requests"
    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not list S3 buckets: {e}",
                        evidence=_evidence("s3:ListBuckets", f"Error: {e}"))
    if not buckets:
        return _finding(cid, D_STORAGE, name, "N/A", "No S3 buckets exist in this account.",
                        evidence=_evidence("s3:ListBuckets", "No S3 buckets exist"))
    offenders = []
    for b in buckets:
        bucket = b["Name"]
        try:
            policy_str = s3.get_bucket_policy(Bucket=bucket)["Policy"]
            policy_doc = json.loads(policy_str)
            if not _bucket_denies_insecure_transport(policy_doc):
                offenders.append(bucket)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchBucketPolicy":
                offenders.append(bucket)
            else:
                offenders.append(f"{bucket} (could not verify: {code or e})")
        except Exception as e:
            offenders.append(f"{bucket} (could not verify: {e})")
    ev = _evidence("s3:ListBuckets, s3:GetBucketPolicy",
                   f"{len(buckets)} bucket(s) checked; {len(offenders)} missing deny-HTTP policy")
    if not offenders:
        return _finding(cid, D_STORAGE, name, "PASS", "All S3 buckets have a policy denying non-HTTPS requests.",
                        evidence=ev)
    return _finding(cid, D_STORAGE, name, "FAIL",
                     f"{len(offenders)} bucket(s) do not have a policy denying insecure (HTTP) transport.",
                     ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                     evidence=ev)


def check_3_1_4(session, s3):
    cid, name = "3.1.4", "Ensure that S3 is configured with 'Block Public Access' enabled"
    account_level_ok = False
    try:
        s3control = session.client("s3control")
        account_id = session.client("sts").get_caller_identity()["Account"]
        acct_cfg = s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        account_level_ok = all([
            acct_cfg.get("BlockPublicAcls", False),
            acct_cfg.get("IgnorePublicAcls", False),
            acct_cfg.get("BlockPublicPolicy", False),
            acct_cfg.get("RestrictPublicBuckets", False),
        ])
    except Exception:
        account_level_ok = False
    if account_level_ok:
        return _finding(cid, D_STORAGE, name, "PASS",
                         "Account-level S3 Block Public Access is fully enabled for all four settings.",
                         evidence=_evidence("s3control:GetPublicAccessBlock",
                                            "Account-level Block Public Access: all 4 settings enabled"))
    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not list S3 buckets: {e}",
                        evidence=_evidence("s3:ListBuckets", f"Error: {e}"))
    if not buckets:
        return _finding(cid, D_STORAGE, name, "N/A",
                         "No S3 buckets exist. Account-level Block Public Access is not fully enabled.",
                        evidence=_evidence("s3control:GetPublicAccessBlock, s3:ListBuckets",
                                           "Account-level not fully enabled; no buckets exist"))
    offenders = []
    for b in buckets:
        bucket = b["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
            ok = all([
                cfg.get("BlockPublicAcls", False),
                cfg.get("IgnorePublicAcls", False),
                cfg.get("BlockPublicPolicy", False),
                cfg.get("RestrictPublicBuckets", False),
            ])
            if not ok:
                offenders.append(bucket)
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchPublicAccessBlockConfiguration":
                offenders.append(bucket)
            else:
                offenders.append(f"{bucket} (could not verify: {code or e})")
        except Exception as e:
            offenders.append(f"{bucket} (could not verify: {e})")
    ev = _evidence("s3control:GetPublicAccessBlock, s3:GetPublicAccessBlock",
                   f"Account-level not fully enabled; {len(buckets)} bucket(s) checked; {len(offenders)} lacking full Block Public Access")
    if not offenders:
        return _finding(cid, D_STORAGE, name, "PASS", "All S3 buckets have Block Public Access fully enabled.",
                        evidence=ev)
    return _finding(cid, D_STORAGE, name, "FAIL",
                     f"Account-level Block Public Access is not fully enabled, and {len(offenders)} bucket(s) "
                     f"also lack full bucket-level Block Public Access.",
                     ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                     evidence=ev)


def check_3_2_1(session, regions):
    cid, name = "3.2.1", "Ensure that encryption-at-rest is enabled for RDS instances"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    checked_any = True
                    if not db.get("StorageEncrypted", False):
                        offenders.append(f"{db['DBInstanceIdentifier']} ({region})")
        if not checked_any:
            return _finding(cid, D_STORAGE, name, "N/A", "No RDS instances found in any checked region.",
                            evidence=_evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); no RDS instances"))
        ev = _evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); {len(offenders)} without encryption")
        if not offenders:
            return _finding(cid, D_STORAGE, name, "PASS", "All RDS instances have storage encryption enabled.", evidence=ev)
        return _finding(cid, D_STORAGE, name, "FAIL",
                         f"{len(offenders)} RDS instance(s) do not have storage encryption enabled.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("rds:DescribeDBInstances", f"Error: {e}"))


def check_3_2_2(session, regions):
    cid, name = "3.2.2", "Ensure the Auto Minor Version Upgrade feature is enabled for RDS instances"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    checked_any = True
                    if not db.get("AutoMinorVersionUpgrade", False):
                        offenders.append(f"{db['DBInstanceIdentifier']} ({region})")
        if not checked_any:
            return _finding(cid, D_STORAGE, name, "N/A", "No RDS instances found in any checked region.",
                            evidence=_evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); no RDS instances"))
        ev = _evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); {len(offenders)} without auto minor upgrade")
        if not offenders:
            return _finding(cid, D_STORAGE, name, "PASS", "All RDS instances have Auto Minor Version Upgrade enabled.", evidence=ev)
        return _finding(cid, D_STORAGE, name, "FAIL",
                         f"{len(offenders)} RDS instance(s) do not have Auto Minor Version Upgrade enabled.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("rds:DescribeDBInstances", f"Error: {e}"))


def check_3_2_3(session, regions):
    cid, name = "3.2.3", "Ensure that RDS instances are not publicly accessible"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            rds = session.client("rds", region_name=region)
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    checked_any = True
                    if db.get("PubliclyAccessible", False):
                        offenders.append(f"{db['DBInstanceIdentifier']} ({region})")
        if not checked_any:
            return _finding(cid, D_STORAGE, name, "N/A", "No RDS instances found in any checked region.",
                            evidence=_evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); no RDS instances"))
        ev = _evidence("rds:DescribeDBInstances", f"Checked {len(regions)} region(s); {len(offenders)} publicly accessible")
        if not offenders:
            return _finding(cid, D_STORAGE, name, "PASS", "No RDS instances are publicly accessible.", evidence=ev)
        return _finding(cid, D_STORAGE, name, "FAIL",
                         f"{len(offenders)} RDS instance(s) are publicly accessible.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("rds:DescribeDBInstances", f"Error: {e}"))


def check_3_3_1(session, regions):
    cid, name = "3.3.1", "Ensure that encryption is enabled for EFS file systems"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            efs = session.client("efs", region_name=region)
            paginator = efs.get_paginator("describe_file_systems")
            for page in paginator.paginate():
                for fs in page["FileSystems"]:
                    checked_any = True
                    if not fs.get("Encrypted", False):
                        offenders.append(f"{fs['FileSystemId']} ({region})")
        if not checked_any:
            return _finding(cid, D_STORAGE, name, "N/A", "No EFS file systems found in any checked region.",
                            evidence=_evidence("efs:DescribeFileSystems", f"Checked {len(regions)} region(s); no EFS"))
        ev = _evidence("efs:DescribeFileSystems", f"Checked {len(regions)} region(s); {len(offenders)} without encryption")
        if not offenders:
            return _finding(cid, D_STORAGE, name, "PASS", "All EFS file systems have encryption at rest enabled.", evidence=ev)
        return _finding(cid, D_STORAGE, name, "FAIL",
                         f"{len(offenders)} EFS file system(s) do not have encryption enabled.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_STORAGE, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("efs:DescribeFileSystems", f"Error: {e}"))


def run_storage_domain(session, regions):
    s3 = session.client("s3")
    findings = []
    findings.append(check_3_1_1(s3))
    findings.append(check_3_1_4(session, s3))
    findings.append(check_3_2_1(session, regions))
    findings.append(check_3_2_2(session, regions))
    findings.append(check_3_2_3(session, regions))
    findings.append(check_3_3_1(session, regions))
    findings.append(check_3_1_2(s3))
    findings.append(check_3_1_3(session, regions))
    findings.append(check_3_2_4(session, regions))
    return findings


# ===========================================================================
# Domain 3: Logging
# ===========================================================================

D_LOGGING = "Logging"

# 4.10 is Tier 1 (full automation) — see check_4_10 below (previously a
# generic MANUAL_REVIEW control).


def check_4_10(session, regions):
    cid, name = "4.10", "Ensure all AWS-managed web front-end services have access logging enabled"
    api = "cloudfront:ListDistributions, elasticloadbalancing:DescribeLoadBalancers, elasticloadbalancing:DescribeLoadBalancerAttributes, apigateway:GET"
    offenders, checked_any = [], False

    try:
        paginator = session.client("cloudfront").get_paginator("list_distributions")
        for page in paginator.paginate():
            items = (page.get("DistributionList") or {}).get("Items") or []
            for dist in items:
                checked_any = True
                if not dist.get("Logging", {}).get("Enabled", False):
                    offenders.append(f"cloudfront:{dist['Id']}")
    except Exception:
        pass

    for region in regions:
        try:
            elbv2 = session.client("elbv2", region_name=region)
            paginator = elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    checked_any = True
                    attrs = elbv2.describe_load_balancer_attributes(LoadBalancerArn=lb["LoadBalancerArn"])["Attributes"]
                    enabled = next((a["Value"] for a in attrs if a["Key"] == "access_logs.s3.enabled"), "false")
                    if enabled != "true":
                        offenders.append(f"elb:{lb['LoadBalancerName']} ({region})")
        except Exception:
            pass
        try:
            apigw = session.client("apigateway", region_name=region)
            paginator = apigw.get_paginator("get_rest_apis")
            for page in paginator.paginate():
                for api_def in page["items"]:
                    for stage in apigw.get_stages(restApiId=api_def["id"]).get("item", []):
                        checked_any = True
                        if not stage.get("accessLogSettings", {}).get("destinationArn"):
                            offenders.append(f"apigateway:{api_def['id']}/{stage['stageName']} ({region})")
        except Exception:
            pass

    if not checked_any:
        return _finding(cid, D_LOGGING, name, "N/A",
                         "No CloudFront distributions, load balancers, or API Gateway stages found.",
                         evidence=_evidence(api, "No front-end web services found"))
    ev = _evidence(api, f"{len(offenders)} front-end service(s) without access logging")
    if not offenders:
        return _finding(cid, D_LOGGING, name, "PASS",
                         "All CloudFront distributions, load balancers, and API Gateway stages have access logging enabled.",
                         evidence=ev)
    return _finding(cid, D_LOGGING, name, "FAIL",
                     f"{len(offenders)} front-end service(s) do not have access logging enabled.",
                     ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)


def _get_all_trails(session):
    ct = session.client("cloudtrail")
    return ct.describe_trails(includeShadowTrails=True).get("trailList", [])


def _trail_is_logging(session, trail):
    try:
        ct = session.client("cloudtrail", region_name=trail.get("HomeRegion"))
        status = ct.get_trail_status(Name=trail["TrailARN"])
        return status.get("IsLogging", False)
    except Exception:
        return False


def check_4_1(session, trails):
    cid, name = "4.1", "Ensure CloudTrail is enabled in all regions"
    api = "cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus"
    if not trails:
        return _finding(cid, D_LOGGING, name, "FAIL", "No CloudTrail trails exist in this account.",
                         evidence=_evidence(api, "0 trail(s) found"))
    for t in trails:
        if t.get("IsMultiRegionTrail") and _trail_is_logging(session, t):
            return _finding(cid, D_LOGGING, name, "PASS",
                             f"Multi-region trail '{t['Name']}' exists and is actively logging.",
                             evidence=_evidence(api, f"multi-region active trail: {t['Name']}"))
    return _finding(cid, D_LOGGING, name, "FAIL",
                     "No multi-region CloudTrail trail is actively logging.",
                     ", ".join(t["Name"] for t in trails),
                     evidence=_evidence(api, "multi-region active trail: none"))


def check_4_2(trails):
    cid, name = "4.2", "Ensure CloudTrail log file validation is enabled"
    if not trails:
        return _finding(cid, D_LOGGING, name, "FAIL", "No CloudTrail trails exist in this account.",
                         evidence=_evidence("cloudtrail:DescribeTrails", "0 trail(s)"))
    offenders = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled", False)]
    if not offenders:
        return _finding(cid, D_LOGGING, name, "PASS", "Log file validation is enabled on all trails.",
                         evidence=_evidence("cloudtrail:DescribeTrails", f"{len(trails)} trail(s); 0 without validation"))
    return _finding(cid, D_LOGGING, name, "FAIL",
                     f"{len(offenders)} trail(s) do not have log file validation enabled.",
                     ", ".join(offenders),
                     evidence=_evidence("cloudtrail:DescribeTrails", f"{len(offenders)} without validation"))


def check_4_3(session, regions):
    cid, name = "4.3", "Ensure AWS Config is enabled in all regions"
    missing = []
    try:
        for region in regions:
            cfg = session.client("config", region_name=region)
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
            if not recorders:
                missing.append(f"{region} (no recorder)")
                continue
            statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
            recording = any(s.get("recording", False) for s in statuses)
            if not recording:
                missing.append(f"{region} (recorder not recording)")
        if not missing:
            return _finding(cid, D_LOGGING, name, "PASS", f"AWS Config is enabled and recording in all {len(regions)} checked region(s).",
                             evidence=_evidence("config:DescribeConfigurationRecorders", f"0 without active recorder"))
        return _finding(cid, D_LOGGING, name, "FAIL",
                         f"{len(missing)} region(s) do not have AWS Config actively recording.",
                         ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""),
                         evidence=_evidence("config:DescribeConfigurationRecorders", f"{len(missing)} without active recorder"))
    except Exception as e:
        return _finding(cid, D_LOGGING, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_4_4(session, trails):
    cid, name = "4.4", "Ensure that server access logging is enabled on the CloudTrail S3 bucket"
    if not trails:
        return _finding(cid, D_LOGGING, name, "FAIL", "No CloudTrail trails exist in this account.",
                         evidence=_evidence("s3:GetBucketLogging", "0 CloudTrail S3 bucket(s)"))
    s3 = session.client("s3")
    buckets = {t.get("S3BucketName") for t in trails if t.get("S3BucketName")}
    offenders = []
    for bucket in buckets:
        try:
            resp = s3.get_bucket_logging(Bucket=bucket)
            if "LoggingEnabled" not in resp:
                offenders.append(bucket)
        except Exception as e:
            offenders.append(f"{bucket} (could not verify: {e})")
    if not offenders:
        return _finding(cid, D_LOGGING, name, "PASS", "Server access logging is enabled on all CloudTrail S3 buckets.",
                         evidence=_evidence("s3:GetBucketLogging", f"{len(buckets)} bucket(s); 0 without logging"))
    return _finding(cid, D_LOGGING, name, "FAIL",
                     f"{len(offenders)} CloudTrail S3 bucket(s) do not have server access logging enabled.",
                     ", ".join(offenders),
                     evidence=_evidence("s3:GetBucketLogging", f"{len(offenders)} without logging"))


def check_4_5(trails):
    cid, name = "4.5", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"
    if not trails:
        return _finding(cid, D_LOGGING, name, "FAIL", "No CloudTrail trails exist in this account.",
                         evidence=_evidence("cloudtrail:DescribeTrails", "0 trail(s)"))
    offenders = [t["Name"] for t in trails if not t.get("KmsKeyId")]
    if not offenders:
        return _finding(cid, D_LOGGING, name, "PASS", "All CloudTrail trails are encrypted at rest with a KMS CMK.",
                         evidence=_evidence("cloudtrail:DescribeTrails", f"{len(trails)} trail(s); 0 without KMS"))
    return _finding(cid, D_LOGGING, name, "FAIL",
                     f"{len(offenders)} trail(s) are not encrypted with a KMS CMK.",
                     ", ".join(offenders),
                     evidence=_evidence("cloudtrail:DescribeTrails", f"{len(offenders)} without KMS"))


def check_4_6(session, regions):
    cid, name = "4.6", "Ensure rotation for customer-created symmetric CMKs is enabled"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            kms = session.client("kms", region_name=region)
            paginator = kms.get_paginator("list_keys")
            for page in paginator.paginate():
                for k in page["Keys"]:
                    key_id = k["KeyId"]
                    try:
                        meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    except Exception:
                        continue
                    if meta.get("KeyManager") != "CUSTOMER":
                        continue
                    if meta.get("KeySpec", meta.get("CustomerMasterKeySpec")) != "SYMMETRIC_DEFAULT":
                        continue
                    if meta.get("Origin") != "AWS_KMS":
                        continue
                    if meta.get("KeyState") not in ("Enabled",):
                        continue
                    checked_any = True
                    try:
                        rotation = kms.get_key_rotation_status(KeyId=key_id)
                        if not rotation.get("KeyRotationEnabled", False):
                            offenders.append(f"{key_id} ({region})")
                    except Exception as e:
                        offenders.append(f"{key_id} ({region}, could not verify: {e})")
        if not checked_any:
            return _finding(cid, D_LOGGING, name, "N/A", "No customer-managed symmetric CMKs found.",
                             evidence=_evidence("kms:ListKeys", "No customer-managed symmetric CMKs"))
        if not offenders:
            return _finding(cid, D_LOGGING, name, "PASS", "Automatic rotation is enabled for all customer-managed symmetric CMKs.",
                             evidence=_evidence("kms:ListKeys", f"0 CMK(s) without rotation"))
        return _finding(cid, D_LOGGING, name, "FAIL",
                         f"{len(offenders)} customer-managed symmetric CMK(s) do not have rotation enabled.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=_evidence("kms:ListKeys", f"{len(offenders)} CMK(s) without rotation"))
    except Exception as e:
        return _finding(cid, D_LOGGING, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def check_4_7(session, regions):
    cid, name = "4.7", "Ensure VPC flow logging is enabled in all VPCs"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            for vpc in vpcs:
                checked_any = True
                vpc_id = vpc["VpcId"]
                flow_logs = ec2.describe_flow_logs(
                    Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
                ).get("FlowLogs", [])
                active = [f for f in flow_logs if f.get("FlowLogStatus") == "ACTIVE"]
                if not active:
                    offenders.append(f"{vpc_id} ({region})")
        if not checked_any:
            return _finding(cid, D_LOGGING, name, "N/A", "No VPCs found in any checked region.",
                             evidence=_evidence("ec2:DescribeVpcs", "No VPCs found"))
        if not offenders:
            return _finding(cid, D_LOGGING, name, "PASS", "All VPCs have an active flow log.",
                             evidence=_evidence("ec2:DescribeFlowLogs", f"0 VPC(s) without flow logs"))
        return _finding(cid, D_LOGGING, name, "FAIL",
                         f"{len(offenders)} VPC(s) do not have an active flow log.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""),
                         evidence=_evidence("ec2:DescribeFlowLogs", f"{len(offenders)} VPC(s) without flow logs"))
    except Exception as e:
        return _finding(cid, D_LOGGING, name, "ERROR", f"Could not evaluate: {e}",
                         evidence=_evidence("Error", str(e)))


def _trail_has_s3_object_logging(session, trail, direction):
    try:
        ct = session.client("cloudtrail", region_name=trail.get("HomeRegion"))
        resp = ct.get_event_selectors(TrailName=trail["TrailARN"])
    except Exception:
        return False
    for sel in resp.get("EventSelectors", []):
        rw = sel.get("ReadWriteType", "All")
        if rw not in ("All", direction):
            continue
        for res in sel.get("DataResources", []):
            if res.get("Type") == "AWS::S3::Object":
                return True
    for sel in resp.get("AdvancedEventSelectors", []):
        field_matches = {fs["Field"]: fs for fs in sel.get("FieldSelectors", [])}
        cat = field_matches.get("eventCategory", {})
        if "Data" not in cat.get("Equals", []):
            continue
        resource_type = field_matches.get("resources.type", {})
        if "AWS::S3::Object" not in resource_type.get("Equals", []):
            continue
        rw_field = field_matches.get("readOnly", {})
        rw_equals = rw_field.get("Equals", [])
        wants_write = direction == "WriteOnly"
        if rw_equals:
            is_read_only = rw_equals[0] in ("true", True)
            if wants_write and is_read_only:
                continue
            if not wants_write and not is_read_only:
                continue
        return True
    return False


def check_4_8_4_9(session, trails):
    cid_w, name_w = "4.8", "Ensure that object-level logging for write events is enabled for S3 buckets"
    cid_r, name_r = "4.9", "Ensure that object-level logging for read events is enabled for S3 buckets"
    if not trails:
        return (_finding(cid_w, D_LOGGING, name_w, "FAIL", "No CloudTrail trails exist in this account.",
                          evidence=_evidence("cloudtrail:GetEventSelectors", "No trails")),
                _finding(cid_r, D_LOGGING, name_r, "FAIL", "No CloudTrail trails exist in this account.",
                          evidence=_evidence("cloudtrail:GetEventSelectors", "No trails")))
    write_ok = any(_trail_has_s3_object_logging(session, t, "WriteOnly") for t in trails)
    read_ok = any(_trail_has_s3_object_logging(session, t, "ReadOnly") for t in trails)
    write_finding = (_finding(cid_w, D_LOGGING, name_w, "PASS", "At least one trail logs S3 object-level write events.",
                               evidence=_evidence("cloudtrail:GetEventSelectors", "S3 write logging: PASS"))
                      if write_ok else
                      _finding(cid_w, D_LOGGING, name_w, "FAIL", "No trail logs S3 object-level write events.",
                               ", ".join(t["Name"] for t in trails),
                               evidence=_evidence("cloudtrail:GetEventSelectors", "S3 write logging: FAIL")))
    read_finding = (_finding(cid_r, D_LOGGING, name_r, "PASS", "At least one trail logs S3 object-level read events.",
                              evidence=_evidence("cloudtrail:GetEventSelectors", "S3 read logging: PASS"))
                     if read_ok else
                     _finding(cid_r, D_LOGGING, name_r, "FAIL", "No trail logs S3 object-level read events.",
                              ", ".join(t["Name"] for t in trails),
                              evidence=_evidence("cloudtrail:GetEventSelectors", "S3 read logging: FAIL")))
    return write_finding, read_finding


def run_logging_domain(session, regions):
    findings = []
    try:
        trails = _get_all_trails(session)
        trails_error = None
    except Exception as e:
        trails = []
        trails_error = str(e)
    if trails_error:
        for cid, cname in [
            ("4.1", "Ensure CloudTrail is enabled in all regions"),
            ("4.2", "Ensure CloudTrail log file validation is enabled"),
            ("4.4", "Ensure that server access logging is enabled on the CloudTrail S3 bucket"),
            ("4.5", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"),
            ("4.8", "Ensure that object-level logging for write events is enabled for S3 buckets"),
            ("4.9", "Ensure that object-level logging for read events is enabled for S3 buckets"),
        ]:
            findings.append(_finding(cid, D_LOGGING, cname, "ERROR", f"Could not list CloudTrail trails: {trails_error}",
                                      evidence=_evidence("Error", trails_error)))
    else:
        findings.append(check_4_1(session, trails))
        findings.append(check_4_2(trails))
        findings.append(check_4_4(session, trails))
        findings.append(check_4_5(trails))
        w, r = check_4_8_4_9(session, trails)
        findings.append(w)
        findings.append(r)
    findings.append(check_4_3(session, regions))
    findings.append(check_4_6(session, regions))
    findings.append(check_4_7(session, regions))
    findings.append(check_4_10(session, regions))
    return findings


# ===========================================================================
# Domain 4: Monitoring
# ===========================================================================

D_MONITORING = "Monitoring"

#   mode "any": the filter matches if it contains AT LEAST ONE of these
#               keywords (used when the keywords are alternative, independent
#               event names that each individually indicate the activity).
#   mode "all": the filter matches ONLY if it contains EVERY one of these
#               keywords (used when the keywords are generic/shared
#               substrings - e.g. "ConsoleLogin" or "userIdentity.type" -
#               that only uniquely identify this control's pattern when
#               required TOGETHER; with "any" these generic substrings also
#               match unrelated filters built for a different control,
#               producing false PASS results).
METRIC_FILTER_CONTROLS = [
    ("5.1", "Ensure unauthorized API calls are monitored",
     ["UnauthorizedOperation", "AccessDenied"], "any"),
    ("5.2", "Ensure management console sign-in without MFA is monitored",
     ["ConsoleLogin", "MFAUsed"], "all"),
    ("5.3", "Ensure usage of the 'root' account is monitored",
     ["userIdentity.type", "Root"], "all"),
    ("5.4", "Ensure IAM policy changes are monitored",
     ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy",
      "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
      "AttachRolePolicy", "DetachRolePolicy", "AttachUserPolicy", "DetachUserPolicy",
      "AttachGroupPolicy", "DetachGroupPolicy"], "any"),
    ("5.5", "Ensure CloudTrail configuration changes are monitored",
     ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"], "any"),
    ("5.6", "Ensure AWS Management Console authentication failures are monitored",
     ["ConsoleLogin", "Failed authentication"], "all"),
    ("5.7", "Ensure disabling or scheduled deletion of customer created CMKs is monitored",
     ["DisableKey", "ScheduleKeyDeletion"], "any"),
    ("5.8", "Ensure S3 bucket policy changes are monitored",
     ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors", "PutBucketLifecycle",
      "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors",
      "DeleteBucketLifecycle", "DeleteBucketReplication"], "any"),
    ("5.9", "Ensure AWS Config configuration changes are monitored",
     ["StopConfigurationRecorder", "DeleteDeliveryChannel", "PutDeliveryChannel",
      "PutConfigurationRecorder"], "any"),
    ("5.10", "Ensure security group changes are monitored",
     ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
      "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress",
      "CreateSecurityGroup", "DeleteSecurityGroup"], "any"),
    ("5.11", "Ensure Network Access Control List (NACL) changes are monitored",
     ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl",
      "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"], "any"),
    ("5.12", "Ensure changes to network gateways are monitored",
     ["CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway",
      "CreateInternetGateway", "DeleteInternetGateway", "DetachInternetGateway"], "any"),
    ("5.13", "Ensure route table changes are monitored",
     ["CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation",
      "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"], "any"),
    ("5.14", "Ensure VPC changes are monitored",
     ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection",
      "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection",
      "RejectVpcPeeringConnection", "EnableVpcClassicLink", "DisableVpcClassicLink"], "any"),
    ("5.15", "Ensure AWS Organizations changes are monitored",
     ["AcceptHandshake", "AttachPolicy", "CreateAccount", "CreateOrganizationalUnit",
      "DeclineHandshake", "DeleteOrganization", "DeleteOrganizationalUnit",
      "DetachPolicy", "DisablePolicyType", "EnablePolicyType",
      "InviteAccountToOrganization", "LeaveOrganization", "MoveAccount",
      "RemoveAccountFromOrganization", "UpdatePolicy", "UpdateOrganizationalUnit"], "any"),
]


def _get_cloudtrail_log_group(session):
    ct = session.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=True).get("trailList", [])
    for t in trails:
        log_group_arn = t.get("CloudWatchLogsLogGroupArn")
        if not log_group_arn:
            continue
        try:
            log_group_name = log_group_arn.split(":log-group:")[1].split(":")[0]
        except IndexError:
            continue
        region = t.get("HomeRegion")
        try:
            ct_region = session.client("cloudtrail", region_name=region)
            status = ct_region.get_trail_status(Name=t["TrailARN"])
            if status.get("IsLogging"):
                return log_group_name, region
        except Exception:
            continue
    return None, None


def _matching_filters(logs_client, log_group_name, keywords, mode="any"):
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        for page in paginator.paginate(logGroupName=log_group_name):
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                if mode == "all":
                    is_match = all(kw in pattern for kw in keywords)
                else:
                    is_match = any(kw in pattern for kw in keywords)
                if is_match:
                    yield mf
    except Exception:
        return


def _alarm_exists_for_metric(cloudwatch_client, metric_name, namespace):
    try:
        resp = cloudwatch_client.describe_alarms(AlarmTypes=["MetricAlarm"], MaxRecords=100)
        for alarm in resp.get("MetricAlarms", []):
            if alarm.get("MetricName") == metric_name and alarm.get("Namespace") == namespace:
                if alarm.get("AlarmActions"):
                    return True
        return False
    except Exception:
        return False


def check_metric_filter_controls(session, log_group_name, region):
    findings = []
    if not log_group_name:
        for cid, name, _, _mode in METRIC_FILTER_CONTROLS:
            findings.append(_finding(cid, D_MONITORING, name, "FAIL",
                                      "No CloudTrail trail is actively shipping logs to CloudWatch Logs.",
                                      evidence=_evidence("cloudtrail:DescribeTrails",
                                                         "No trail shipping to CloudWatch Logs")))
        return findings
    logs_client = session.client("logs", region_name=region)
    cloudwatch_client = session.client("cloudwatch", region_name=region)
    for cid, name, keywords, mode in METRIC_FILTER_CONTROLS:
        matches = list(_matching_filters(logs_client, log_group_name, keywords, mode))
        if not matches:
            findings.append(_finding(cid, D_MONITORING, name, "FAIL",
                                      f"No CloudWatch Logs metric filter on '{log_group_name}' matches this event pattern.",
                                      evidence=_evidence(f"logs:DescribeMetricFilters(logGroup={log_group_name})",
                                                         f"No filter matched keywords: {keywords[:3]}")))
            continue
        alarmed = False
        for mf in matches:
            for mt in mf.get("metricTransformations", []):
                if _alarm_exists_for_metric(cloudwatch_client, mt["metricName"], mt["metricNamespace"]):
                    alarmed = True
                    break
            if alarmed:
                break
        if alarmed:
            findings.append(_finding(cid, D_MONITORING, name, "PASS",
                                      "A matching metric filter exists with an alarm configured with a notification action.",
                                      evidence=_evidence("logs:DescribeMetricFilters, cloudwatch:DescribeAlarms",
                                                         "Filter and alarm found")))
        else:
            findings.append(_finding(cid, D_MONITORING, name, "FAIL",
                                      "A matching metric filter exists, but no CloudWatch alarm with a notification action is wired to it.",
                                      log_group_name,
                                      evidence=_evidence("logs:DescribeMetricFilters, cloudwatch:DescribeAlarms",
                                                         "Filter matched but no alarm with action")))
    return findings


def check_5_16(session, regions):
    cid, name = "5.16", "Ensure AWS Security Hub is enabled"
    missing = []
    try:
        for region in regions:
            sh = session.client("securityhub", region_name=region)
            try:
                sh.describe_hub()
            except (sh.exceptions.InvalidAccessException, sh.exceptions.ResourceNotFoundException):
                missing.append(region)
        if not missing:
            return _finding(cid, D_MONITORING, name, "PASS", f"Security Hub is enabled in all {len(regions)} checked region(s).",
                            evidence=_evidence("securityhub:DescribeHub", f"0 without Security Hub"))
        return _finding(cid, D_MONITORING, name, "FAIL",
                         f"Security Hub is not enabled in {len(missing)} region(s).",
                         ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""),
                         evidence=_evidence("securityhub:DescribeHub", f"{len(missing)} without Security Hub"))
    except Exception as e:
        return _finding(cid, D_MONITORING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("securityhub:DescribeHub", f"Error: {e}"))


def run_monitoring_domain(session, regions):
    findings = []
    try:
        log_group_name, log_group_region = _get_cloudtrail_log_group(session)
        findings.extend(check_metric_filter_controls(session, log_group_name, log_group_region))
    except Exception as e:
        for cid, name, _, _mode in METRIC_FILTER_CONTROLS:
            findings.append(_finding(cid, D_MONITORING, name, "ERROR", f"Could not evaluate: {e}",
                                      evidence=_evidence("Error", str(e))))
    findings.append(check_5_16(session, regions))
    return findings


# ===========================================================================
# Domain 5: Networking
# ===========================================================================

D_NETWORKING = "Networking"

ADMIN_PORTS = [22, 3389]
CIFS_PORT = 445

# 6.6 is Tier 1 (full automation), 6.8 is Tier 2 (partial automation, flags
# likely issues with evidence) — see check_6_6 / check_6_8 below (previously
# generic MANUAL_REVIEW controls).


def check_6_6(session, regions):
    cid, name = "6.6", "Ensure routing tables for VPC peering are \"least access\""
    api = "ec2:DescribeVpcPeeringConnections, ec2:DescribeRouteTables"
    offenders, checked_any = [], False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            peerings = ec2.describe_vpc_peering_connections(
                Filters=[{"Name": "status-code", "Values": ["active"]}]
            ).get("VpcPeeringConnections", [])
            if not peerings:
                continue
            checked_any = True
            peer_cidrs = {}
            for p in peerings:
                pcx_id = p["VpcPeeringConnectionId"]
                for side in ("AccepterVpcInfo", "RequesterVpcInfo"):
                    info = p.get(side, {})
                    cidr_blocks = info.get("CidrBlockSet") or ([{"CidrBlock": info["CidrBlock"]}] if info.get("CidrBlock") else [])
                    for cb in cidr_blocks:
                        if cb.get("CidrBlock"):
                            peer_cidrs.setdefault(pcx_id, set()).add(cb["CidrBlock"])
            for rt in ec2.describe_route_tables().get("RouteTables", []):
                for route in rt.get("Routes", []):
                    pcx_id = route.get("VpcPeeringConnectionId")
                    dest = route.get("DestinationCidrBlock")
                    if pcx_id and dest and dest in peer_cidrs.get(pcx_id, set()):
                        offenders.append(f"{rt['RouteTableId']} -> {pcx_id} (full VPC CIDR {dest}, {region})")
        if not checked_any:
            return _finding(cid, D_NETWORKING, name, "N/A",
                             "No active VPC peering connections found in any checked region.",
                             evidence=_evidence(api, "No VPC peering connections"))
        ev = _evidence(api, f"{len(offenders)} route(s) use the full peer VPC CIDR instead of a scoped-down range")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS",
                             "No route table routes a full peer VPC CIDR through a peering connection; routes appear scoped.",
                             evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} route(s) send the entire peer VPC's CIDR through a peering connection "
                         f"instead of a scoped-down range.",
                         "; ".join(offenders[:15]) + (" ..." if len(offenders) > 15 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def check_6_8(session, regions):
    cid, name = "6.8", "Ensure VPC Endpoints are used for access to AWS Services"
    api = ("ec2:DescribeVpcEndpoints, ec2:DescribeVpcs, ec2:DescribeInstances, "
           "rds:DescribeDBInstances, elasticloadbalancing:DescribeLoadBalancers")
    per_vpc, checked_any, any_workload = {}, False, False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            vpcs = ec2.describe_vpcs().get("Vpcs", [])
            endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])

            # A VPC with no EC2/RDS/ELB workload has nothing that would need a
            # VPC Endpoint, so an empty VPC is not itself a finding.
            workload_vpcs = set()
            try:
                paginator = ec2.get_paginator("describe_instances")
                for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]):
                    for res in page["Reservations"]:
                        for inst in res["Instances"]:
                            if inst.get("VpcId"):
                                workload_vpcs.add(inst["VpcId"])
            except Exception:
                pass
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        vpc_id = (db.get("DBSubnetGroup") or {}).get("VpcId")
                        if vpc_id:
                            workload_vpcs.add(vpc_id)
            except Exception:
                pass
            try:
                elbv2 = session.client("elbv2", region_name=region)
                paginator = elbv2.get_paginator("describe_load_balancers")
                for page in paginator.paginate():
                    for lb in page["LoadBalancers"]:
                        if lb.get("VpcId"):
                            workload_vpcs.add(lb["VpcId"])
            except Exception:
                pass

            for vpc in vpcs:
                checked_any = True
                vpc_id = vpc["VpcId"]
                has_workload = vpc_id in workload_vpcs
                any_workload = any_workload or has_workload
                per_vpc[f"{vpc_id} ({region})"] = {
                    "endpoints": [e["ServiceName"] for e in endpoints if e.get("VpcId") == vpc_id],
                    "has_workload": has_workload,
                }

        if not checked_any:
            return _finding(cid, D_NETWORKING, name, "N/A", "No VPCs found in any checked region.",
                             evidence=_evidence(api, "No VPCs found"))

        if not any_workload:
            return _finding(cid, D_NETWORKING, name, "N/A",
                             "No EC2/RDS/load-balancer workloads exist in any VPC across checked regions; "
                             "VPC Endpoints are not applicable.",
                             evidence=_evidence(api, f"{len(per_vpc)} VPC(s) checked across {len(regions)} "
                                                      f"region(s); 0 workloads found"))

        offenders = [v for v, d in per_vpc.items() if d["has_workload"] and not d["endpoints"]]
        ev = _evidence(api, "; ".join(f"{v}: workload={d['has_workload']}, {len(d['endpoints'])} endpoint(s)"
                                       for v, d in list(per_vpc.items())[:20]))
        if offenders:
            return _finding(cid, D_NETWORKING, name, "FAIL",
                             f"{len(offenders)} VPC(s) with workloads have no VPC Endpoints at all.",
                             ", ".join(offenders[:20]), evidence=ev)
        return _finding(cid, D_NETWORKING, name, "MANUAL_REVIEW",
                         "All VPCs with workloads have at least one VPC Endpoint. Confirm the endpoints present "
                         "cover every AWS service each workload depends on.", evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}", evidence=_evidence(api, str(e)))


def _permission_covers_port(perm, port):
    if perm.get("IpProtocol") == "-1":
        return True
    from_port = perm.get("FromPort")
    to_port = perm.get("ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


def _sg_open_to_world(sg, port, ipv6=False):
    for perm in sg.get("IpPermissions", []):
        if not _permission_covers_port(perm, port):
            continue
        if ipv6:
            for r in perm.get("Ipv6Ranges", []):
                if r.get("CidrIpv6") == "::/0":
                    return True
        else:
            for r in perm.get("IpRanges", []):
                if r.get("CidrIp") == "0.0.0.0/0":
                    return True
    return False


def _nacl_entry_covers_port(entry, port):
    if entry.get("Egress", False):
        return False
    if entry.get("RuleAction") != "allow":
        return False
    protocol = entry.get("Protocol")
    if protocol == "-1":
        covers_port = True
    else:
        pr = entry.get("PortRange")
        if not pr:
            return False
        covers_port = pr.get("From", 0) <= port <= pr.get("To", 65535)
    if not covers_port:
        return False
    if entry.get("CidrBlock") == "0.0.0.0/0":
        return True
    if entry.get("Ipv6CidrBlock") == "::/0":
        return True
    return False


def check_6_1_1(session, regions):
    cid, name = "6.1.1", "Ensure EBS volume encryption is enabled in all regions"
    missing = []
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            resp = ec2.get_ebs_encryption_by_default()
            if not resp.get("EbsEncryptionByDefault", False):
                missing.append(region)
        ev = _evidence("ec2:GetEbsEncryptionByDefault", f"{len(missing)} without EBS default encryption")
        if not missing:
            return _finding(cid, D_NETWORKING, name, "PASS", f"EBS encryption by default is enabled in all {len(regions)} checked region(s).", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(missing)} region(s) do not have EBS encryption by default enabled.",
                         ", ".join(missing[:20]) + (" ..." if len(missing) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:GetEbsEncryptionByDefault", str(e)))


def check_6_1_2(session, regions):
    cid, name = "6.1.2", "Ensure CIFS access is restricted to trusted networks to prevent unauthorized access"
    offenders = []
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    if _sg_open_to_world(sg, CIFS_PORT, ipv6=False) or _sg_open_to_world(sg, CIFS_PORT, ipv6=True):
                        offenders.append(f"{sg['GroupId']} ({region})")
        ev = _evidence("ec2:DescribeSecurityGroups", f"{len(offenders)} SG(s) allow unrestricted CIFS (port 445)")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "No security group allows unrestricted CIFS (port 445) access.", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} security group(s) allow unrestricted CIFS (port 445) access.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeSecurityGroups", str(e)))


def check_6_2(session, regions):
    cid, name = "6.2", "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports"
    offenders = []
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                for nacl in page["NetworkAcls"]:
                    for entry in nacl.get("Entries", []):
                        if any(_nacl_entry_covers_port(entry, p) for p in ADMIN_PORTS):
                            offenders.append(f"{nacl['NetworkAclId']} ({region})")
                            break
        ev = _evidence("ec2:DescribeNetworkAcls", f"{len(offenders)} NACL(s) allow unrestricted admin port ingress")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "No NACL allows unrestricted ingress to admin ports (22/3389).", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} NACL(s) allow unrestricted ingress to admin ports (22/3389).",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeNetworkAcls", str(e)))


def check_6_3(session, regions):
    cid, name = "6.3", "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports"
    offenders = []
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    if any(_sg_open_to_world(sg, p, ipv6=False) for p in ADMIN_PORTS):
                        offenders.append(f"{sg['GroupId']} ({region})")
        ev = _evidence("ec2:DescribeSecurityGroups", f"{len(offenders)} SG(s) allow 0.0.0.0/0 to admin ports")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "No security group allows unrestricted (0.0.0.0/0) ingress to admin ports.", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} security group(s) allow unrestricted (0.0.0.0/0) ingress to admin ports.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeSecurityGroups", str(e)))


def check_6_4(session, regions):
    cid, name = "6.4", "Ensure no security groups allow ingress from ::/0 to remote server administration ports"
    offenders = []
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    if any(_sg_open_to_world(sg, p, ipv6=True) for p in ADMIN_PORTS):
                        offenders.append(f"{sg['GroupId']} ({region})")
        ev = _evidence("ec2:DescribeSecurityGroups", f"{len(offenders)} SG(s) allow ::/0 to admin ports")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "No security group allows unrestricted (::/0) ingress to admin ports.", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} security group(s) allow unrestricted (::/0) ingress to admin ports.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeSecurityGroups", str(e)))


def check_6_5(session, regions):
    cid, name = "6.5", "Ensure the default security group of every VPC restricts all traffic"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
                for sg in page["SecurityGroups"]:
                    checked_any = True
                    if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                        offenders.append(f"{sg['GroupId']} (VPC {sg.get('VpcId', '-')}, {region})")
        if not checked_any:
            return _finding(cid, D_NETWORKING, name, "N/A", "No default security groups found.",
                            evidence=_evidence("ec2:DescribeSecurityGroups", "No default SGs"))
        ev = _evidence("ec2:DescribeSecurityGroups", f"{len(offenders)} default SG(s) have rules")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "All default security groups have no inbound or outbound rules.", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} default security group(s) still have inbound and/or outbound rules.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeSecurityGroups", str(e)))


def check_6_7(session, regions):
    cid, name = "6.7", "Ensure that the EC2 Metadata Service only allows IMDSv2"
    offenders = []
    checked_any = False
    try:
        for region in regions:
            ec2 = session.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ):
                for res in page["Reservations"]:
                    for inst in res["Instances"]:
                        checked_any = True
                        tokens = inst.get("MetadataOptions", {}).get("HttpTokens")
                        if tokens != "required":
                            offenders.append(f"{inst['InstanceId']} ({region})")
        if not checked_any:
            return _finding(cid, D_NETWORKING, name, "N/A", "No EC2 instances found in any checked region.",
                            evidence=_evidence("ec2:DescribeInstances", "No EC2 instances"))
        ev = _evidence("ec2:DescribeInstances", f"{len(offenders)} instance(s) not requiring IMDSv2")
        if not offenders:
            return _finding(cid, D_NETWORKING, name, "PASS", "All EC2 instances require IMDSv2 (HttpTokens=required).", evidence=ev)
        return _finding(cid, D_NETWORKING, name, "FAIL",
                         f"{len(offenders)} EC2 instance(s) do not require IMDSv2.",
                         ", ".join(offenders[:20]) + (" ..." if len(offenders) > 20 else ""), evidence=ev)
    except Exception as e:
        return _finding(cid, D_NETWORKING, name, "ERROR", f"Could not evaluate: {e}",
                        evidence=_evidence("ec2:DescribeInstances", str(e)))


def run_networking_domain(session, regions):
    findings = []
    findings.append(check_6_1_1(session, regions))
    findings.append(check_6_1_2(session, regions))
    findings.append(check_6_2(session, regions))
    findings.append(check_6_3(session, regions))
    findings.append(check_6_4(session, regions))
    findings.append(check_6_5(session, regions))
    findings.append(check_6_7(session, regions))
    findings.append(check_6_6(session, regions))
    findings.append(check_6_8(session, regions))
    return findings


# ===========================================================================
# Unified Handler
# ===========================================================================

_DOMAIN_RUNNERS = {
    "IAM": lambda session, iam, regions: run_iam_domain(session, iam, regions),
    "STORAGE": lambda session, iam, regions: run_storage_domain(session, regions),
    "LOGGING": lambda session, iam, regions: run_logging_domain(session, regions),
    "MONITORING": lambda session, iam, regions: run_monitoring_domain(session, regions),
    "NETWORKING": lambda session, iam, regions: run_networking_domain(session, regions),
}


def lambda_handler(event, context):
    session = boto3.Session()
    iam = session.client("iam")

    regions_override = os.environ.get("REGIONS_OVERRIDE")
    try:
        regions = _enabled_regions(session, regions_override)
    except Exception:
        regions = [session.region_name or "us-east-1"]

    # Optional: run only one domain, so n8n can invoke this same Lambda
    # in parallel (one call per domain) to stay under a short execution
    # time limit instead of scanning everything serially in one call.
    event = event or {}
    requested_domain = str(event.get("domain", "")).strip().upper()

    all_findings = []
    if requested_domain:
        runner = _DOMAIN_RUNNERS.get(requested_domain)
        if runner is None:
            return {
                "error": f"Unknown domain '{requested_domain}'. "
                         f"Valid values: {', '.join(_DOMAIN_RUNNERS.keys())}"
            }
        all_findings.extend(runner(session, iam, regions))
    else:
        # Run all five domains (original behavior, used when no "domain"
        # key is passed in the event)
        all_findings.extend(run_iam_domain(session, iam, regions))
        all_findings.extend(run_storage_domain(session, regions))
        all_findings.extend(run_logging_domain(session, regions))
        all_findings.extend(run_monitoring_domain(session, regions))
        all_findings.extend(run_networking_domain(session, regions))

    # Sort by control id
    def sort_key(f):
        return [int(p) for p in f["Control ID"].split(".")]
    all_findings.sort(key=sort_key)

    summary_counts = {
        "PASS": sum(1 for f in all_findings if f["Status"] == "PASS"),
        "FAIL": sum(1 for f in all_findings if f["Status"] == "FAIL"),
        "MANUAL_REVIEW": sum(1 for f in all_findings if f["Status"] == "MANUAL_REVIEW"),
        "N/A": sum(1 for f in all_findings if f["Status"] == "N/A"),
        "ERROR": sum(1 for f in all_findings if f["Status"] == "ERROR"),
    }

    # Per-domain breakdown
    domain_summaries = {}
    for f in all_findings:
        d = f["Domain"]
        if d not in domain_summaries:
            domain_summaries[d] = {"PASS": 0, "FAIL": 0, "MANUAL_REVIEW": 0, "N/A": 0, "ERROR": 0}
        domain_summaries[d][f["Status"]] = domain_summaries[d].get(f["Status"], 0) + 1

    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
    except Exception:
        account_id = "unknown"

    result = {
        "benchmark": "CIS AWS Foundations Benchmark v7.0.0",
        "account_id": account_id,
        "scanned_at": _now().isoformat(),
        "regions_checked": regions,
        "total_controls": len(all_findings),
        "summary": summary_counts,
        "domain_summaries": domain_summaries,
        "findings": all_findings,
    }

    return result


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2, default=str))
