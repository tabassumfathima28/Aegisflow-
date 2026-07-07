"""
AegisFlow - Incident Response Lambda

Purpose: When triggered with a compromised instance ID, this function:
  1. Swaps the instance's security group to an isolated/quarantine group
     (this cuts off all network access -- containment).
  2. Tags the instance as "Under-Investigation" so humans know its status.
  3. Finds the instance's root EBS volume and takes a forensic snapshot
     of it (evidence collection, so nothing is lost even after the
     instance is eventually terminated).

This function can be invoked two ways:

  A) Direct invoke (e.g. `aws lambda invoke` or the AWS console test button).
     The event IS the payload directly:
     {
       "instance_id": "i-0123456789abcdef0",
       "isolated_sg_id": "sg-9876543210"
     }

  B) Via its public Function URL (e.g. from Tines or any HTTP client).
     AWS wraps the request, so the event looks like:
     {
       "headers": { "x-aegisflow-token": "your-secret-here", ... },
       "body": "{\"instance_id\": \"...\", \"isolated_sg_id\": \"...\"}"
     }
     In this case, the caller MUST include the header
     `X-AegisFlow-Token` matching the WEBHOOK_SECRET environment
     variable, or the request is rejected. This is a simple shared-secret
     check standing in for full AWS request signing -- it keeps the
     public URL from being callable by randoms on the internet.
"""

import base64
import json
import os

import boto3

ec2 = boto3.client("ec2")

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET")
FORENSIC_AMI_ID = os.environ.get("FORENSIC_AMI_ID")
FORENSIC_SUBNET_ID = os.environ.get("FORENSIC_SUBNET_ID")
FORENSIC_SG_ID = os.environ.get("FORENSIC_SG_ID")
FORENSIC_INSTANCE_PROFILE = os.environ.get("FORENSIC_INSTANCE_PROFILE")
FORENSIC_BUCKET = os.environ.get("FORENSIC_BUCKET")
FORENSIC_REGION = os.environ.get("AWS_REGION_FOR_FORENSIC", "us-east-1")


# This script runs INSIDE the temporary forensic instance (not the Lambda).
# It waits for the attached snapshot-volume to show up, mounts it read-only,
# pulls timestamped entries out of the logs that actually have timestamps
# (auth log, web server log) into a single chronological timeline.txt, grabs
# a few extra non-timestamped artifacts as supporting context (accounts,
# cron jobs, bash history), uploads everything to S3, then shuts itself down
# -- which AWS turns into a full termination (see instance_initiated_shutdown
# _behavior in forensic.tf), so nothing keeps running or billing afterward.
_FORENSIC_USER_DATA_TEMPLATE = """#!/bin/bash
exec > /tmp/aegisflow-forensic.log 2>&1
echo "[AegisFlow-Forensic] Starting analysis for __INSTANCE_ID__"

# Give the attached snapshot-volume a moment to become visible to the OS.
sleep 15

ROOT_DISK=$(lsblk -no PKNAME "$(findmnt -n -o SOURCE / | sed 's/[0-9]*$//')" 2>/dev/null)
FORENSIC_DEV=""
for dev in $(lsblk -dno NAME); do
  if [ "$dev" != "$ROOT_DISK" ] && ! echo "$ROOT_DISK" | grep -q "$dev"; then
    FORENSIC_DEV="/dev/$dev"
  fi
done

mkdir -p /mnt/forensic

# The OS sometimes auto-mounts an attached volume on its own (udev/systemd)
# before we get to it -- if so, just use wherever it landed instead of
# fighting for /mnt/forensic.
EXISTING_MOUNT=$(findmnt -n -o TARGET "$FORENSIC_DEV" 2>/dev/null | head -1)
if [ -z "$EXISTING_MOUNT" ] && [ -b "${FORENSIC_DEV}p1" ]; then
  EXISTING_MOUNT=$(findmnt -n -o TARGET "${FORENSIC_DEV}p1" 2>/dev/null | head -1)
fi

if [ -n "$EXISTING_MOUNT" ]; then
  MOUNT_POINT="$EXISTING_MOUNT"
  echo "[AegisFlow-Forensic] Volume already mounted at $MOUNT_POINT, using that."
elif [ -b "${FORENSIC_DEV}p1" ]; then
  mount -o ro "${FORENSIC_DEV}p1" /mnt/forensic
  MOUNT_POINT="/mnt/forensic"
else
  mount -o ro "$FORENSIC_DEV" /mnt/forensic
  MOUNT_POINT="/mnt/forensic"
fi

echo "[AegisFlow-Forensic] Reading forensic artifacts from $MOUNT_POINT"

REPORT=/tmp/aegisflow-report
mkdir -p "$REPORT"

# ---- The timeline: only sources that carry real timestamps ----
{
  echo "=== AegisFlow Forensic Timeline: __INSTANCE_ID__ ==="
  echo "Generated (UTC): $(date -u)"
  echo "Source snapshot: __SNAPSHOT_ID__"
  echo ""
  echo "--- Authentication log ---"
  for f in "$MOUNT_POINT/var/log/secure" "$MOUNT_POINT/var/log/auth.log"; do
    [ -f "$f" ] && cat "$f"
  done
  echo ""
  echo "--- Web server access log ---"
  for f in "$MOUNT_POINT/var/log/httpd/access_log" "$MOUNT_POINT/var/log/nginx/access.log"; do
    [ -f "$f" ] && cat "$f"
  done
} > "$REPORT/timeline.txt"

# ---- Supporting context: no per-line timestamps, but useful ----
{
  echo "=== AegisFlow Supporting Artifacts: __INSTANCE_ID__ ==="
  echo ""
  echo "--- User accounts (/etc/passwd) ---"
  cat "$MOUNT_POINT/etc/passwd" 2>/dev/null
  echo ""
  echo "--- Cron jobs ---"
  cat "$MOUNT_POINT/etc/crontab" 2>/dev/null
  for f in "$MOUNT_POINT"/var/spool/cron/*; do
    [ -f "$f" ] && echo "== $f ==" && cat "$f"
  done
  echo ""
  echo "--- Bash history (all users) ---"
  find "$MOUNT_POINT/home" "$MOUNT_POINT/root" -name ".bash_history" 2>/dev/null | while read -r hf; do
    echo "== $hf =="
    cat "$hf"
  done
} > "$REPORT/supporting_artifacts.txt"

aws s3 cp "$REPORT/timeline.txt" "s3://__BUCKET__/forensic-reports/__INSTANCE_ID__/timeline.txt" --region __REGION__
aws s3 cp "$REPORT/supporting_artifacts.txt" "s3://__BUCKET__/forensic-reports/__INSTANCE_ID__/supporting_artifacts.txt" --region __REGION__

if [ "$MOUNT_POINT" = "/mnt/forensic" ]; then
  umount /mnt/forensic 2>/dev/null
fi
echo "[AegisFlow-Forensic] Upload complete, shutting down."
aws s3 cp /tmp/aegisflow-forensic.log "s3://__BUCKET__/forensic-reports/__INSTANCE_ID__/execution.log" --region __REGION__ || true

shutdown -h now
"""


def _launch_forensic_instance(instance_id, snapshot_id):
    """
    Launches the temporary forensic analysis instance with the incident's
    snapshot attached directly as a second volume (via BlockDeviceMappings
    -- AWS creates a new volume from the snapshot automatically at launch,
    no separate CreateVolume/AttachVolume calls needed).
    """
    user_data = (
        _FORENSIC_USER_DATA_TEMPLATE
        .replace("__INSTANCE_ID__", instance_id)
        .replace("__SNAPSHOT_ID__", snapshot_id)
        .replace("__BUCKET__", FORENSIC_BUCKET)
        .replace("__REGION__", FORENSIC_REGION)
    )
    encoded_user_data = base64.b64encode(user_data.encode("utf-8")).decode("utf-8")

    response = ec2.run_instances(
        ImageId=FORENSIC_AMI_ID,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=FORENSIC_SUBNET_ID,
        SecurityGroupIds=[FORENSIC_SG_ID],
        IamInstanceProfile={"Name": FORENSIC_INSTANCE_PROFILE},
        InstanceInitiatedShutdownBehavior="terminate",
        UserData=encoded_user_data,
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/sdf",
                "Ebs": {
                    "SnapshotId": snapshot_id,
                    "DeleteOnTermination": True,
                },
            }
        ],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": f"aegisflow-forensic-analysis-{instance_id}"},
                    {"Key": "Purpose", "Value": "Incident-Forensics-Timeline"},
                ],
            }
        ],
    )
    return response["Instances"][0]["InstanceId"]


def _unwrap_event(event):
    """
    Normalizes the two possible invocation shapes (direct invoke vs.
    Function URL HTTP call) into a plain dict of {instance_id, isolated_sg_id},
    and enforces the shared-secret check when called over HTTP.
    """
    # Function URL / HTTP invocations include a "headers" key that a
    # direct `aws lambda invoke` payload never would.
    is_http_call = isinstance(event, dict) and "headers" in event and "body" in event

    if not is_http_call:
        # Direct invoke -- trust it (already gated by IAM permissions).
        return event, None

    # ---- HTTP call: check the secret token first ----
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    provided_token = headers.get("x-aegisflow-token")

    if not WEBHOOK_SECRET or provided_token != WEBHOOK_SECRET:
        return None, {
            "statusCode": 401,
            "body": json.dumps({"error": "Unauthorized: missing or invalid X-AegisFlow-Token header"}),
        }

    body = event.get("body") or "{}"
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        return None, {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid JSON body"}),
        }

    return payload, None


def lambda_handler(event, context):
    payload, error_response = _unwrap_event(event)
    if error_response:
        print(f"[AegisFlow] Rejected request: {error_response}")
        return error_response

    is_http_call = isinstance(event, dict) and "headers" in event and "body" in event

    instance_id = payload["instance_id"]
    isolated_sg_id = payload["isolated_sg_id"]

    print(f"[AegisFlow] Starting incident response for instance: {instance_id}")

    # -----------------------------------------------------
    # STEP 1: CONTAINMENT
    # Swap the network security group so the instance can no
    # longer send or receive any traffic. This happens at the
    # cloud control-plane level, so an attacker with control
    # of the OS itself cannot stop or reverse it.
    # -----------------------------------------------------
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolated_sg_id],
    )
    print(f"[AegisFlow] Instance {instance_id} network isolated via SG {isolated_sg_id}")

    # Tag the instance so anyone looking at the AWS console
    # immediately understands its state.
    ec2.create_tags(
        Resources=[instance_id],
        Tags=[{"Key": "State", "Value": "Under-Investigation"}],
    )
    print(f"[AegisFlow] Instance {instance_id} tagged as Under-Investigation")

    # -----------------------------------------------------
    # STEP 2: EVIDENCE COLLECTION
    # Find the root EBS volume attached to this instance and
    # snapshot it. This preserves a forensic copy of the disk
    # exactly as it was at the moment of containment.
    # -----------------------------------------------------
    instance_info = ec2.describe_instances(InstanceIds=[instance_id])
    reservations = instance_info["Reservations"]
    instance = reservations[0]["Instances"][0]

    volume_id = None
    for mapping in instance.get("BlockDeviceMappings", []):
        if mapping.get("Ebs"):
            volume_id = mapping["Ebs"]["VolumeId"]
            break

    snapshot_id = None
    if volume_id:
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"aegisflow-forensic-{instance_id}",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "Name", "Value": f"aegisflow-forensic-{instance_id}"},
                        {"Key": "Purpose", "Value": "Incident-Forensics"},
                    ],
                }
            ],
        )
        snapshot_id = snapshot["SnapshotId"]
        print(f"[AegisFlow] Forensic snapshot started: {snapshot_id} (volume {volume_id})")
    else:
        print("[AegisFlow] WARNING: No EBS volume found to snapshot.")

    result = {
        "instance_id": instance_id,
        "status": "contained",
        "isolated_sg_id": isolated_sg_id,
        "volume_id": volume_id,
        "snapshot_id": snapshot_id,
    }

    print(f"[AegisFlow] Incident response complete so far: {result}")

    # -----------------------------------------------------
    # STEP 3: AUTOMATED FORENSIC TIMELINE
    # Launch a short-lived, fully isolated EC2 instance with the
    # snapshot attached as a second volume. It mounts the disk
    # read-only, pulls timestamped log entries into a single
    # timeline.txt, uploads it to S3, and self-terminates.
    # -----------------------------------------------------
    forensic_instance_id = None
    if snapshot_id:
        try:
            print(f"[AegisFlow] Waiting for snapshot {snapshot_id} to complete before forensic launch...")
            waiter = ec2.get_waiter("snapshot_completed")
            waiter.wait(
                SnapshotIds=[snapshot_id],
                WaiterConfig={"Delay": 15, "MaxAttempts": 40},  # up to ~600 seconds
            )
            print(f"[AegisFlow] Snapshot {snapshot_id} completed, launching forensic instance...")
            forensic_instance_id = _launch_forensic_instance(instance_id, snapshot_id)
            print(f"[AegisFlow] Forensic analysis instance launched: {forensic_instance_id}")
        except Exception as e:
            # Never let a forensic-analysis failure block the incident
            # response result -- containment and the snapshot already
            # succeeded, which is what matters most.
            print(f"[AegisFlow] WARNING: forensic instance launch failed: {e}")

    result["forensic_instance_id"] = forensic_instance_id
    result["forensic_report_path"] = (
        f"s3://{FORENSIC_BUCKET}/forensic-reports/{instance_id}/timeline.txt"
        if forensic_instance_id else None
    )

    print(f"[AegisFlow] Incident response complete: {result}")

    if is_http_call:
        # Function URL invocations must return this specific shape
        # (statusCode + body as a JSON *string*) or AWS won't know how
        # to translate it back into a proper HTTP response.
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result),
        }

    return result
