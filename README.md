# security-infra-tf

Terraform module for AWS Security Baseline implementing CIS AWS Foundations Benchmark 5.0.0 controls.

## Controls Implemented

| Control ID | Description | Resource |
|------------|-------------|----------|
| - | Security Hub with CIS 5.0.0 | `aws_securityhub_account`, `aws_securityhub_standards_subscription` |
| - | AWS Config | `aws_config_configuration_recorder`, `aws_config_delivery_channel`, `aws_s3_bucket` |
| CloudTrail.1 | Multi-region trail with management events | `aws_cloudtrail`, `aws_s3_bucket` |
| S3.9 | S3 bucket access logging enabled | CloudTrail bucket logs to access logs bucket |
| Account.1 | Security contact information | `aws_account_alternate_contact` |
| IAM.15 | Password minimum length >= 14 | `aws_iam_account_password_policy` |
| IAM.16 | Password reuse prevention | `aws_iam_account_password_policy` |
| IAM.18 | Support role for AWS Support | `aws_iam_role` with `AWSSupportAccess` |
| IAM.28 | IAM Access Analyzer | `aws_accessanalyzer_analyzer` |
| S3.5 | S3 buckets require SSL | Bucket policies with `aws:SecureTransport` condition |

## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0 |
| aws | >= 5.0 |

## Usage

```hcl
module "security_baseline" {
  source = "git::https://github.com/your-org/security-infra-tf.git"

  # Security Contact (Account.1)
  security_contact_name  = "Security Team"
  security_contact_title = "Security Operations"
  security_contact_email = "security@example.com"
  security_contact_phone = "+1-555-555-5555"

  # Support Role (IAM.18)
  support_role_trusted_principals = [
    "arn:aws:iam::123456789012:root"
  ]

  # Optional: Use existing CloudTrail bucket
  # cloudtrail_existing_bucket_name = "my-existing-cloudtrail-bucket"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| tags | Tags to apply to all resources | `map(string)` | `{}` | no |
| enable_security_hub | Enable AWS Security Hub with CIS 5.0.0 standard | `bool` | `true` | no |
| enable_aws_config | Enable AWS Config | `bool` | `true` | no |
| config_s3_bucket_name | S3 bucket name for AWS Config. If empty, auto-generates | `string` | `""` | no |
| config_s3_key_prefix | S3 key prefix for AWS Config delivery | `string` | `"config"` | no |
| config_recording_frequency | Recording frequency (CONTINUOUS or DAILY) | `string` | `"CONTINUOUS"` | no |
| enable_cloudtrail | Enable CloudTrail with multi-region trail | `bool` | `true` | no |
| cloudtrail_name | Name of the CloudTrail trail | `string` | `"security-trail"` | no |
| cloudtrail_existing_bucket_name | Name of existing S3 bucket for CloudTrail. If empty, creates new bucket | `string` | `""` | no |
| cloudtrail_existing_access_logs_bucket_name | Name of existing S3 bucket for access logs. If empty, creates new bucket | `string` | `""` | no |
| cloudtrail_s3_key_prefix | S3 key prefix for CloudTrail logs | `string` | `"cloudtrail"` | no |
| enable_security_contact | Enable security contact configuration | `bool` | `true` | no |
| security_contact_name | Full name of the security contact | `string` | `""` | no |
| security_contact_title | Job title of the security contact | `string` | `""` | no |
| security_contact_email | Email address of the security contact | `string` | `""` | no |
| security_contact_phone | Phone number of the security contact | `string` | `""` | no |
| enable_password_policy | Enable IAM password policy | `bool` | `true` | no |
| password_minimum_length | Minimum password length (must be >= 14) | `number` | `14` | no |
| password_reuse_prevention | Number of previous passwords to prevent reuse | `number` | `24` | no |
| enable_support_role | Enable AWS Support access role | `bool` | `true` | no |
| support_role_name | Name of the AWS Support access role | `string` | `"aws-support-access"` | no |
| support_role_trusted_principals | List of IAM principals that can assume the support role | `list(string)` | n/a | yes |
| support_role_require_mfa | Require MFA when assuming the support role | `bool` | `true` | no |
| enable_access_analyzer | Enable IAM Access Analyzer | `bool` | `true` | no |
| access_analyzer_name | Name of the IAM Access Analyzer | `string` | `"account-analyzer"` | no |

## Outputs

| Name | Description |
|------|-------------|
| security_hub_account_id | Security Hub account ID |
| security_hub_cis_v5_subscription_arn | ARN of the CIS 5.0.0 standards subscription |
| config_s3_bucket_name | Name of the S3 bucket for AWS Config |
| config_s3_bucket_arn | ARN of the S3 bucket for AWS Config |
| config_recorder_id | AWS Config recorder ID |
| config_role_arn | ARN of the IAM role used by AWS Config |
| cloudtrail_arn | ARN of the CloudTrail trail |
| cloudtrail_id | Name of the CloudTrail trail |
| cloudtrail_s3_bucket_name | Name of the S3 bucket for CloudTrail |
| cloudtrail_s3_bucket_arn | ARN of the S3 bucket for CloudTrail (if created) |
| cloudtrail_access_logs_bucket_name | Name of the access logs bucket |
| cloudtrail_access_logs_bucket_arn | ARN of the access logs bucket |
| password_policy_configured | Whether password policy is configured |
| password_minimum_length | Configured minimum password length |
| password_reuse_prevention | Number of passwords for reuse prevention |
| support_role_arn | ARN of the AWS Support access role |
| access_analyzer_arn | ARN of the IAM Access Analyzer |

## S3 Buckets

The module creates the following S3 buckets:

### AWS Config Bucket
- Auto-generated name: `aws-config-{account_id}-{region}`
- Versioning, encryption, public access blocked, SSL-only

### CloudTrail Bucket
- **Option 1**: Use existing bucket by setting `cloudtrail_existing_bucket_name`
- **Option 2**: Auto-create bucket named `aws-cloudtrail-{account_id}-{region}`
- If created: Versioning, encryption, public access blocked, SSL-only, access logging enabled

### CloudTrail Access Logs Bucket (S3.9)
- **Option 1**: Use existing bucket by setting `cloudtrail_existing_access_logs_bucket_name`
- **Option 2**: Auto-create bucket named `nvisionx-cloudtrail-access-logs-{account_id}`
- Stores access logs for the CloudTrail bucket
- Required for Security Hub S3.9 compliance

## CloudTrail Configuration

The CloudTrail trail is configured with:
- Multi-region trail enabled
- Global service events included
- Log file validation enabled
- Read and write management events captured

## Notes

- **IAM.2** (IAM users should not have IAM policies attached): This is a detective control checked by Security Hub. The module enables Security Hub which will report on non-compliant users.
- **EC2.2**: Mentioned but not implemented as it requires Security Hub (included) for detection.
- The password policy enforces CIS benchmark requirements with minimum length of 14 and reuse prevention of 24 passwords.
