################################################################################
# Example: Complete Security Baseline
################################################################################

provider "aws" {
  region = "us-east-1"
}

module "security_baseline" {
  source = "../../"

  # Security Contact (Account.1)
  security_contact_name  = "Security Team"
  security_contact_title = "Security Operations Center"
  security_contact_email = "security@example.com"
  security_contact_phone = "+1-555-555-5555"

  # Support Role (IAM.18)
  support_role_trusted_principals = [
    "arn:aws:iam::123456789012:root"
  ]

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    Purpose     = "security-baseline"
  }
}

output "security_hub_account_id" {
  value = module.security_baseline.security_hub_account_id
}

output "config_s3_bucket_name" {
  value = module.security_baseline.config_s3_bucket_name
}

output "access_analyzer_arn" {
  value = module.security_baseline.access_analyzer_arn
}

output "support_role_arn" {
  value = module.security_baseline.support_role_arn
}
