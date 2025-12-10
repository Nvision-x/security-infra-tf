################################################################################
# AWS Security Baseline Module
# Implements CIS AWS Foundations Benchmark 5.0.0 controls
################################################################################

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

################################################################################
# Data Sources
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# Security Hub - CIS AWS Foundations Benchmark 5.0.0
################################################################################

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "cis_v5" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/5.0.0"

  depends_on = [aws_securityhub_account.this]
}

################################################################################
# AWS Config
################################################################################

# S3 Bucket for AWS Config
resource "aws_s3_bucket" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = var.config_s3_bucket_name != "" ? var.config_s3_bucket_name : "aws-config-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = aws_s3_bucket.config[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config[0].arn,
          "${aws_s3_bucket.config[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketExistenceCheck"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:ListBucket"
        Resource = aws_s3_bucket.config[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config[0].arn}/${var.config_s3_key_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.config]
}

resource "aws_config_configuration_recorder" "this" {
  count = var.enable_aws_config ? 1 : 0

  name     = var.config_recorder_name
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true
    recording_strategy {
      use_only = "ALL_SUPPORTED_RESOURCE_TYPES"
    }
    include_global_resource_types = true
  }

  recording_mode {
    recording_frequency = var.config_recording_frequency
  }
}

resource "aws_config_delivery_channel" "this" {
  count = var.enable_aws_config ? 1 : 0

  name           = var.config_delivery_channel_name
  s3_bucket_name = aws_s3_bucket.config[0].id
  s3_key_prefix  = var.config_s3_key_prefix

  snapshot_delivery_properties {
    delivery_frequency = var.config_snapshot_frequency
  }

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count = var.enable_aws_config ? 1 : 0

  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

# IAM Role for AWS Config
resource "aws_iam_role" "config" {
  count = var.enable_aws_config ? 1 : 0

  name = var.config_iam_role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count = var.enable_aws_config ? 1 : 0

  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  count = var.enable_aws_config ? 1 : 0

  name = "config-s3-delivery"
  role = aws_iam_role.config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl"
        ]
        Resource = "${aws_s3_bucket.config[0].arn}/${var.config_s3_key_prefix}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config[0].arn
      }
    ]
  })
}

################################################################################
# Account.1 - Security Contact Information
################################################################################

resource "aws_account_alternate_contact" "security" {
  count = var.enable_security_contact ? 1 : 0

  alternate_contact_type = "SECURITY"
  name                   = var.security_contact_name
  title                  = var.security_contact_title
  email_address          = var.security_contact_email
  phone_number           = var.security_contact_phone
}

################################################################################
# S3.1 - Account-level S3 Block Public Access
################################################################################

resource "aws_s3_account_public_access_block" "this" {
  count = var.enable_s3_account_public_access_block ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

################################################################################
# IAM.15 & IAM.16 - Password Policy
# IAM.15: Minimum password length of 14 or greater
# IAM.16: Prevent password reuse
################################################################################

resource "aws_iam_account_password_policy" "this" {
  count = var.enable_password_policy ? 1 : 0

  minimum_password_length        = var.password_minimum_length
  require_lowercase_characters   = var.password_require_lowercase
  require_uppercase_characters   = var.password_require_uppercase
  require_numbers                = var.password_require_numbers
  require_symbols                = var.password_require_symbols
  allow_users_to_change_password = var.password_allow_users_to_change
  max_password_age               = var.password_max_age
  password_reuse_prevention      = var.password_reuse_prevention
  hard_expiry                    = var.password_hard_expiry
}

################################################################################
# IAM.18 - Support Role for AWS Support
################################################################################

resource "aws_iam_role" "support" {
  count = var.enable_support_role ? 1 : 0

  name        = var.support_role_name
  description = "Role to manage incidents with AWS Support"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = var.support_role_trusted_principals
        }
        Condition = var.support_role_require_mfa ? {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        } : {}
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "support" {
  count = var.enable_support_role ? 1 : 0

  role       = aws_iam_role.support[0].name
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}

################################################################################
# IAM.28 - IAM Access Analyzer (External Access)
################################################################################

resource "aws_accessanalyzer_analyzer" "this" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = var.access_analyzer_name
  type          = "ACCOUNT"

  tags = var.tags
}

################################################################################
# CloudTrail.1 - Multi-Region Trail with Management Events
################################################################################

locals {
  # Determine if we need to create new buckets or use existing
  create_cloudtrail_bucket             = var.enable_cloudtrail && var.cloudtrail_existing_bucket_name == ""
  create_cloudtrail_access_logs_bucket = var.enable_cloudtrail && var.cloudtrail_existing_access_logs_bucket_name == ""
  cloudtrail_bucket_name               = var.cloudtrail_existing_bucket_name != "" ? var.cloudtrail_existing_bucket_name : (local.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].id : "")
  cloudtrail_access_logs_bucket_name   = var.cloudtrail_existing_access_logs_bucket_name != "" ? var.cloudtrail_existing_access_logs_bucket_name : (local.create_cloudtrail_access_logs_bucket ? aws_s3_bucket.cloudtrail_access_logs[0].id : "")
}

# S3 Bucket for CloudTrail Access Logs (only if not using existing bucket)
resource "aws_s3_bucket" "cloudtrail_access_logs" {
  count = local.create_cloudtrail_access_logs_bucket ? 1 : 0

  bucket = "nvisionx-cloudtrail-access-logs-${data.aws_caller_identity.current.account_id}"

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "cloudtrail_access_logs" {
  count = local.create_cloudtrail_access_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_access_logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_access_logs" {
  count = local.create_cloudtrail_access_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_access_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_access_logs" {
  count = local.create_cloudtrail_access_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_access_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_access_logs" {
  count = local.create_cloudtrail_access_logs_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail_access_logs[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail_access_logs[0].arn,
          "${aws_s3_bucket.cloudtrail_access_logs[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "S3ServerAccessLogsPolicy"
        Effect = "Allow"
        Principal = {
          Service = "logging.s3.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_access_logs[0].arn}/*"
        Condition = {
          ArnLike = {
            "aws:SourceArn" = local.create_cloudtrail_bucket ? aws_s3_bucket.cloudtrail[0].arn : "arn:aws:s3:::${var.cloudtrail_existing_bucket_name}"
          }
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_access_logs]
}

# S3 Bucket for CloudTrail (only if not using existing bucket)
resource "aws_s3_bucket" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = "aws-cloudtrail-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.name}"

  tags = var.tags
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id

  target_bucket = local.cloudtrail_access_logs_bucket_name
  target_prefix = "cloudtrail-bucket-logs/"

  depends_on = [aws_s3_bucket_policy.cloudtrail_access_logs]
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  count = local.create_cloudtrail_bucket ? 1 : 0

  bucket = aws_s3_bucket.cloudtrail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonSSLRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail[0].arn,
          "${aws_s3_bucket.cloudtrail[0].arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail[0].arn
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name}"
          }
        }
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail[0].arn}/${var.cloudtrail_s3_key_prefix}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name}"
          }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

# KMS Key for CloudTrail encryption (CloudTrail.2)
resource "aws_kms_key" "cloudtrail" {
  count = var.enable_cloudtrail && var.cloudtrail_kms_key_arn == "" ? 1 : 0

  description             = "KMS key for CloudTrail encryption"
  deletion_window_in_days = var.cloudtrail_kms_key_deletion_window
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableRootAccountPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCloudTrailToEncryptLogs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = "arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/${var.cloudtrail_name}"
          }
          StringLike = {
            "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"
          }
        }
      },
      {
        Sid    = "AllowCloudTrailToDescribeKey"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "kms:DescribeKey"
        Resource = "*"
      }
    ]
  })

  tags = var.tags
}

resource "aws_kms_alias" "cloudtrail" {
  count = var.enable_cloudtrail && var.cloudtrail_kms_key_arn == "" ? 1 : 0

  name          = "alias/cloudtrail-${var.cloudtrail_name}"
  target_key_id = aws_kms_key.cloudtrail[0].key_id
}

locals {
  cloudtrail_kms_key_arn = var.cloudtrail_kms_key_arn != "" ? var.cloudtrail_kms_key_arn : (var.enable_cloudtrail ? aws_kms_key.cloudtrail[0].arn : "")
}

# CloudTrail
resource "aws_cloudtrail" "this" {
  count = var.enable_cloudtrail ? 1 : 0

  name                          = var.cloudtrail_name
  s3_bucket_name                = local.cloudtrail_bucket_name
  s3_key_prefix                 = var.cloudtrail_s3_key_prefix
  kms_key_id                    = local.cloudtrail_kms_key_arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = var.tags

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}
