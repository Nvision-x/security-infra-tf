################################################################################
# Security Hub Outputs
################################################################################

output "security_hub_account_id" {
  description = "Security Hub account ID"
  value       = var.enable_security_hub ? aws_securityhub_account.this[0].id : null
}

output "security_hub_cis_v5_subscription_arn" {
  description = "ARN of the CIS 5.0.0 standards subscription"
  value       = var.enable_security_hub ? aws_securityhub_standards_subscription.cis_v5[0].id : null
}

################################################################################
# AWS Config Outputs
################################################################################

output "config_s3_bucket_name" {
  description = "Name of the S3 bucket for AWS Config"
  value       = var.enable_aws_config ? aws_s3_bucket.config[0].id : null
}

output "config_s3_bucket_arn" {
  description = "ARN of the S3 bucket for AWS Config"
  value       = var.enable_aws_config ? aws_s3_bucket.config[0].arn : null
}

output "config_recorder_id" {
  description = "AWS Config recorder ID"
  value       = var.enable_aws_config ? aws_config_configuration_recorder.this[0].id : null
}

output "config_role_arn" {
  description = "ARN of the IAM role used by AWS Config"
  value       = var.enable_aws_config ? aws_iam_role.config[0].arn : null
}

################################################################################
# Security Contact Outputs
################################################################################

output "security_contact_type" {
  description = "Security contact type"
  value       = var.enable_security_contact ? aws_account_alternate_contact.security[0].alternate_contact_type : null
}

################################################################################
# Password Policy Outputs
################################################################################

output "password_policy_configured" {
  description = "Whether password policy is configured"
  value       = var.enable_password_policy
}

output "password_minimum_length" {
  description = "Configured minimum password length"
  value       = var.enable_password_policy ? var.password_minimum_length : null
}

output "password_reuse_prevention" {
  description = "Number of passwords to remember for reuse prevention"
  value       = var.enable_password_policy ? var.password_reuse_prevention : null
}

################################################################################
# Support Role Outputs
################################################################################

output "support_role_arn" {
  description = "ARN of the AWS Support access role"
  value       = var.enable_support_role ? aws_iam_role.support[0].arn : null
}

output "support_role_name" {
  description = "Name of the AWS Support access role"
  value       = var.enable_support_role ? aws_iam_role.support[0].name : null
}

################################################################################
# Access Analyzer Outputs
################################################################################

output "access_analyzer_arn" {
  description = "ARN of the IAM Access Analyzer"
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.this[0].arn : null
}

output "access_analyzer_id" {
  description = "ID of the IAM Access Analyzer"
  value       = var.enable_access_analyzer ? aws_accessanalyzer_analyzer.this[0].id : null
}

################################################################################
# CloudTrail Outputs
################################################################################

output "cloudtrail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.this[0].arn : null
}

output "cloudtrail_id" {
  description = "Name of the CloudTrail trail"
  value       = var.enable_cloudtrail ? aws_cloudtrail.this[0].id : null
}

output "cloudtrail_s3_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail logs"
  value       = var.enable_cloudtrail ? local.cloudtrail_bucket_name : null
}

output "cloudtrail_s3_bucket_arn" {
  description = "ARN of the S3 bucket for CloudTrail logs (only if created by this module)"
  value       = local.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].arn : null
}

output "cloudtrail_access_logs_bucket_name" {
  description = "Name of the S3 bucket for CloudTrail access logs"
  value       = var.enable_cloudtrail ? local.cloudtrail_access_logs_bucket_name : null
}

output "cloudtrail_access_logs_bucket_arn" {
  description = "ARN of the S3 bucket for CloudTrail access logs (only if created by this module)"
  value       = local.create_cloudtrail_access_logs_bucket ? aws_s3_bucket.cloudtrail_access_logs[0].arn : null
}

output "cloudtrail_kms_key_arn" {
  description = "ARN of the KMS key used for CloudTrail encryption"
  value       = var.enable_cloudtrail ? local.cloudtrail_kms_key_arn : null
}

output "cloudtrail_kms_key_id" {
  description = "ID of the KMS key used for CloudTrail encryption (only if created by this module)"
  value       = var.enable_cloudtrail && var.cloudtrail_kms_key_arn == "" ? aws_kms_key.cloudtrail[0].key_id : null
}
