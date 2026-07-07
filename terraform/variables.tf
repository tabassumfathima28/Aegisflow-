variable "aws_region" {
  description = "The AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Tag/name prefix applied to all resources"
  type        = string
  default     = "aegisflow"
}

variable "instance_type" {
  description = "EC2 instance size for the mock victim server"
  type        = string
  default     = "t3.micro" # free-tier eligible
}

variable "webhook_secret" {
  description = "Shared secret that callers (like Tines) must send in the X-AegisFlow-Token header to invoke the Lambda's public Function URL. CHANGE THIS to your own random string."
  type        = string
  default     = "change-me-to-a-long-random-string-aegisflow-2026"
  sensitive   = true
}
