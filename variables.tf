################################################################################
# General Variables
################################################################################

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

################################################################################
# Security Hub Variables
################################################################################

variable "enable_security_hub" {
  description = "Enable AWS Security Hub with CIS 5.0.0 standard"
  type        = bool
  default     = true
}

################################################################################
# AWS Config Variables
################################################################################

variable "enable_aws_config" {
  description = "Enable AWS Config"
  type        = bool
  default     = true
}

variable "config_recorder_name" {
  description = "Name of the AWS Config recorder"
  type        = string
  default     = "default"
}

variable "config_delivery_channel_name" {
  description = "Name of the AWS Config delivery channel"
  type        = string
  default     = "default"
}

variable "config_s3_bucket_name" {
  description = "S3 bucket name for AWS Config delivery. If empty, auto-generates: aws-config-{account_id}-{region}"
  type        = string
  default     = ""
}

variable "config_s3_key_prefix" {
  description = "S3 key prefix for AWS Config delivery"
  type        = string
  default     = "config"
}

variable "config_recording_frequency" {
  description = "Recording frequency for AWS Config (CONTINUOUS or DAILY)"
  type        = string
  default     = "CONTINUOUS"

  validation {
    condition     = contains(["CONTINUOUS", "DAILY"], var.config_recording_frequency)
    error_message = "Recording frequency must be CONTINUOUS or DAILY."
  }
}

variable "config_snapshot_frequency" {
  description = "Frequency for Config snapshot delivery"
  type        = string
  default     = "TwentyFour_Hours"

  validation {
    condition     = contains(["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"], var.config_snapshot_frequency)
    error_message = "Snapshot frequency must be one of: One_Hour, Three_Hours, Six_Hours, Twelve_Hours, TwentyFour_Hours."
  }
}

variable "config_iam_role_name" {
  description = "Name of the IAM role for AWS Config"
  type        = string
  default     = "aws-config-role"
}

################################################################################
# Account.1 - Security Contact Variables
################################################################################

variable "enable_security_contact" {
  description = "Enable security contact configuration"
  type        = bool
  default     = true
}

variable "security_contact_name" {
  description = "Full name of the security contact"
  type        = string
  default     = ""
}

variable "security_contact_title" {
  description = "Job title of the security contact"
  type        = string
  default     = ""
}

variable "security_contact_email" {
  description = "Email address of the security contact"
  type        = string
  default     = ""
}

variable "security_contact_phone" {
  description = "Phone number of the security contact"
  type        = string
  default     = ""
}

################################################################################
# IAM.15 & IAM.16 - Password Policy Variables
################################################################################

variable "enable_password_policy" {
  description = "Enable IAM password policy"
  type        = bool
  default     = true
}

variable "password_minimum_length" {
  description = "Minimum password length (CIS requires 14 or greater)"
  type        = number
  default     = 14

  validation {
    condition     = var.password_minimum_length >= 14
    error_message = "Password minimum length must be 14 or greater per CIS benchmark IAM.15."
  }
}

variable "password_require_lowercase" {
  description = "Require at least one lowercase character"
  type        = bool
  default     = true
}

variable "password_require_uppercase" {
  description = "Require at least one uppercase character"
  type        = bool
  default     = true
}

variable "password_require_numbers" {
  description = "Require at least one number"
  type        = bool
  default     = true
}

variable "password_require_symbols" {
  description = "Require at least one symbol"
  type        = bool
  default     = true
}

variable "password_allow_users_to_change" {
  description = "Allow users to change their own passwords"
  type        = bool
  default     = true
}

variable "password_max_age" {
  description = "Maximum password age in days (0 = no expiration)"
  type        = number
  default     = 90
}

variable "password_reuse_prevention" {
  description = "Number of previous passwords to prevent reuse (CIS recommends 24)"
  type        = number
  default     = 24

  validation {
    condition     = var.password_reuse_prevention >= 1 && var.password_reuse_prevention <= 24
    error_message = "Password reuse prevention must be between 1 and 24."
  }
}

variable "password_hard_expiry" {
  description = "Prevent users from resetting expired passwords via AWS console"
  type        = bool
  default     = false
}

################################################################################
# IAM.18 - Support Role Variables
################################################################################

variable "enable_support_role" {
  description = "Enable AWS Support access role"
  type        = bool
  default     = true
}

variable "support_role_name" {
  description = "Name of the AWS Support access role"
  type        = string
  default     = "aws-support-access"
}

variable "support_role_trusted_principals" {
  description = "List of IAM principals (ARNs) that can assume the support role"
  type        = list(string)
}

variable "support_role_require_mfa" {
  description = "Require MFA when assuming the support role"
  type        = bool
  default     = true
}

################################################################################
# IAM.28 - Access Analyzer Variables
################################################################################

variable "enable_access_analyzer" {
  description = "Enable IAM Access Analyzer"
  type        = bool
  default     = true
}

variable "access_analyzer_name" {
  description = "Name of the IAM Access Analyzer"
  type        = string
  default     = "account-analyzer"
}

################################################################################
# CloudTrail.1 - CloudTrail Variables
################################################################################

variable "enable_cloudtrail" {
  description = "Enable CloudTrail with multi-region trail"
  type        = bool
  default     = true
}

variable "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  type        = string
  default     = "security-trail"
}

variable "cloudtrail_existing_bucket_name" {
  description = "Name of an existing S3 bucket for CloudTrail logs. If empty, creates a new bucket"
  type        = string
  default     = ""
}

variable "cloudtrail_existing_access_logs_bucket_name" {
  description = "Name of an existing S3 bucket for CloudTrail access logs. If empty, creates a new bucket"
  type        = string
  default     = ""
}

variable "cloudtrail_s3_key_prefix" {
  description = "S3 key prefix for CloudTrail logs"
  type        = string
  default     = "cloudtrail"
}
