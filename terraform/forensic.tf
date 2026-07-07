# ---------------------------------------------------------
# FORENSIC ANALYSIS INFRASTRUCTURE
#
# When triggered, the Lambda launches a short-lived, isolated
# EC2 instance with the incident's EBS snapshot attached as a
# second volume. That instance mounts the snapshot read-only,
# pulls out a targeted set of forensic artifacts (auth logs,
# bash history, cron entries, web logs, account list), uploads
# a report to this S3 bucket, and self-terminates.
# ---------------------------------------------------------

# ---- S3 bucket for forensic reports (private, encrypted) ----

resource "aws_s3_bucket" "forensic_reports" {
  bucket = "${var.project_name}-forensic-reports-${data.aws_caller_identity.current.account_id}"
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_public_access_block" "forensic_reports" {
  bucket = aws_s3_bucket.forensic_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "forensic_reports" {
  bucket = aws_s3_bucket.forensic_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ---- Security group for the forensic instance ----
# No inbound access at all. Outbound limited to HTTPS only,
# just enough to reach the S3/AWS API endpoints to upload the
# report -- this instance never talks to the compromised
# instance or accepts any incoming connections.

resource "aws_security_group" "forensic_sg" {
  name        = "${var.project_name}-forensic-sg"
  description = "Isolated SG for the temporary forensic analysis instance"
  vpc_id      = aws_vpc.aegisflow_vpc.id

  egress {
    description = "HTTPS only, for uploading the report to S3/AWS APIs"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-forensic-sg"
  }
}

# ---- IAM role for the forensic instance itself ----
# Separate from the Lambda's role. Can only write to the
# forensic reports bucket -- nothing else.

resource "aws_iam_role" "forensic_instance_role" {
  name = "${var.project_name}-forensic-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "forensic_instance_permissions" {
  name = "${var.project_name}-forensic-instance-permissions"
  role = aws_iam_role.forensic_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "UploadForensicReport"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.forensic_reports.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "forensic_instance_profile" {
  name = "${var.project_name}-forensic-instance-profile"
  role = aws_iam_role.forensic_instance_role.name
}
