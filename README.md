# AegisFlow — Automated Cloud Incident Response & Forensic Pipeline

A serverless, event-driven incident response pipeline for AWS. When a security
alert fires (e.g. AWS GuardDuty detecting a compromised EC2 instance), AegisFlow
automatically contains the threat, preserves forensic evidence, and notifies the
security team — without waiting on manual triage.

## Architecture

```
Alert (simulated GuardDuty finding)
        |
        v
   Tines webhook (SOAR orchestration)
        |
        v
   AWS Lambda: incident_response.py
        |
        +--> Swap EC2 security group to isolated/quarantine (containment)
        +--> Tag instance "Under-Investigation"
        +--> Create forensic EBS snapshot (evidence preservation)
        |
        v
   Tines: Send to Slack (real-time notification)
```

## What it does

1. **Isolation** — swaps the compromised instance's security group to a
   zero-rule quarantine group, cutting off all inbound/outbound network access
   at the cloud control-plane level (an attacker with root on the host can't
   override this).
2. **Evidence collection** — automatically snapshots the instance's root EBS
   volume before any further action is taken, so forensic evidence is
   preserved even if the instance is later terminated.
3. **Notification** — posts a real-time incident summary to Slack via Tines,
   including the instance ID, finding type, and containment action taken.

## Stack

- **Terraform** — infrastructure as code (VPC, security groups, EC2, Lambda, IAM)
- **AWS Lambda (Python / boto3)** — containment + evidence collection logic
- **Tines** — SOAR orchestration and Slack notification
- **Least-privilege IAM** — the Lambda's execution role can only do exactly
  what it needs (modify security groups, describe instances/volumes, create
  snapshots, write logs) — no broad `ec2:*`, no S3, no IAM access.

## Project structure

```
terraform/
  main.tf        # VPC, subnet, security groups, mock victim EC2 instance
  variables.tf   # Region, project name, instance type, webhook secret
  lambda.tf      # IAM role/policy, Lambda function, public Function URL
  outputs.tf     # Instance ID, IPs, security group IDs, function URL
lambda/
  incident_response.py   # Containment + evidence collection logic
```

## Setup

1. `cd terraform && terraform init && terraform apply`
2. Note the outputs (`victim_instance_id`, `victim_public_ip`, security group IDs)
3. Simulate an alert by invoking the Lambda directly, or via a Tines webhook
   wired to the Lambda's output
4. Watch the instance get isolated and a forensic snapshot appear in
   EC2 → Elastic Block Store → Snapshots
5. `terraform destroy` when done to avoid ongoing AWS charges

## Known limitations / roadmap

- **Trigger is currently simulated** — a production version would wire AWS
  GuardDuty findings through EventBridge to fire this automatically, instead
  of a manual invoke.
- **Memory acquisition is not implemented.** EC2 has no built-in hypervisor-level
  memory-dump API; a production version would need an agent (e.g. LiME)
  pre-installed on protected instances.
- **Forensic timeline step launches but mounting isn't fully reliable yet.**
  The temporary forensic instance does launch, attach the snapshot, upload a
  report to S3, and self-terminate -- but on some runs the snapshot volume
  gets auto-mounted by the OS at boot before the script's own mount attempt,
  causing the timeline to come back empty. The self-mount-detection fix is
  in place but not yet verified working end-to-end; next step is confirming
  the actual mount point AWS assigns and adjusting detection accordingly.
- **No automated timeline analysis via a full tool like Plaso/log2timeline.**
  Current extraction targets a specific set of high-value log files (auth
  log, web server log) rather than a full disk timeline -- a deliberate
  scope decision for reliability over completeness.
- **No approval-gated auto-termination yet** — planned as an interactive
  Slack/Tines approval step.

## Why containment, not termination

The pipeline isolates the instance rather than destroying it. This preserves
the ability to investigate further, avoids losing evidence, and keeps a human
in the loop before any destructive action — full auto-termination without
review is a common and risky shortcut in incident response automation.
