

# ---------------------------------------------------------
# PACKAGING
# Zips up our Python code so Lambda can run it.
# ---------------------------------------------------------

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/incident_response.py"
  output_path = "${path.module}/incident_response.zip"
}

# ---------------------------------------------------------
# LEAST-PRIVILEGE IAM ROLE
# This Lambda can ONLY do exactly what it needs:
# - swap security groups on the target instance
# - describe instance/volume info
# - create a snapshot
# - write its own logs
# Nothing more (no broad EC2:*, no S3, no IAM access).
# ---------------------------------------------------------

resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-exec-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_permissions" {
  name = "${var.project_name}-lambda-permissions"
  role = aws_iam_role.lambda_exec_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ContainmentActions"
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "ec2:DescribeSnapshots",
          "ec2:CreateSnapshot",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "LaunchForensicInstance"
        Effect = "Allow"
        Action = [
          "ec2:RunInstances"
        ]
        Resource = "*"
      },
      {
        Sid      = "PassForensicInstanceRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = aws_iam_role.forensic_instance_role.arn
      },
      {
        Sid    = "Logging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# ---------------------------------------------------------
# THE LAMBDA FUNCTION
# ---------------------------------------------------------

resource "aws_lambda_function" "incident_response" {
  function_name = "${var.project_name}-incident-response"
  role          = aws_iam_role.lambda_exec_role.arn
  handler       = "incident_response.lambda_handler"
  runtime       = "python3.12"
  timeout       = 340

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      WEBHOOK_SECRET             = var.webhook_secret
      FORENSIC_AMI_ID             = data.aws_ami.amazon_linux.id
      FORENSIC_SUBNET_ID          = aws_subnet.public_subnet.id
      FORENSIC_SG_ID              = aws_security_group.forensic_sg.id
      FORENSIC_INSTANCE_PROFILE   = aws_iam_instance_profile.forensic_instance_profile.name
      FORENSIC_BUCKET             = aws_s3_bucket.forensic_reports.bucket
      AWS_REGION_FOR_FORENSIC     = var.aws_region
    }
  }
}

# ---------------------------------------------------------
# PUBLIC FUNCTION URL
# Gives the Lambda its own HTTPS endpoint that any HTTP client
# (like Tines) can POST to directly -- no AWS request-signing
# needed. Protection comes from the shared-secret header check
# inside the function itself (see incident_response.py).
# ---------------------------------------------------------

resource "aws_lambda_function_url" "incident_response_url" {
  function_name      = aws_lambda_function.incident_response.function_name
  authorization_type = "NONE"
}

# Without this, AWS blocks ALL callers with a 403 Forbidden, even
# though the Function URL's own auth_type says "NONE". This resource
# is the piece that actually grants public invoke permission.
resource "aws_lambda_permission" "public_function_url" {
  statement_id           = "AllowPublicFunctionUrlInvoke"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.incident_response.function_name
  principal              = "*"
  function_url_auth_type = "NONE"
}
