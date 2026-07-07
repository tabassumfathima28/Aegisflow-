output "victim_instance_id" {
  description = "The EC2 instance ID of the mock victim server"
  value       = aws_instance.victim_server.id
}

output "victim_public_ip" {
  description = "Public IP of the mock victim server -- open this in a browser"
  value       = aws_instance.victim_server.public_ip
}

output "compromised_security_group_id" {
  description = "The SG currently attached to the victim server (wide open)"
  value       = aws_security_group.compromised_sg.id
}

output "isolated_security_group_id" {
  description = "The quarantine SG the Lambda will swap the instance into"
  value       = aws_security_group.isolated_sg.id
}

output "lambda_function_name" {
  description = "Name of the deployed incident-response Lambda"
  value       = aws_lambda_function.incident_response.function_name
}

output "lambda_function_url" {
  description = "Public HTTPS URL for the Lambda -- POST to this from Tines"
  value       = aws_lambda_function_url.incident_response_url.function_url
}

output "forensic_reports_bucket" {
  description = "S3 bucket where forensic timeline reports get uploaded"
  value       = aws_s3_bucket.forensic_reports.bucket
}
