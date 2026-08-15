provider "aws" {
  region = var.aws_region
}

# 1. KMS Key for Secure Watermark Cryptographic Seed
resource "aws_kms_key" "watermark_seed_key" {
  description             = "KMS Key to protect the Deep Learning Watermark Seed"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

resource "aws_kms_alias" "watermark_seed_key_alias" {
  name          = "alias/devsecops-watermark-key"
  target_key_id = aws_kms_key.watermark_seed_key.key_id
}

# 2. S3 Bucket for Verified Models
resource "aws_s3_bucket" "model_artifacts" {
  bucket_prefix = "sit723-verified-models-"
}

resource "aws_s3_bucket_public_access_block" "block_public_access" {
  bucket                  = aws_s3_bucket.model_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 3. Secure OIDC GitHub Actions Role
# Allows GitHub Actions to deploy to AWS without long-term Access Keys
resource "aws_iam_openid_connect_provider" "github_oidc" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["1b511abead59c6ce207077c0bf0e0043b1382612", "1c58a3a8518e8759bf075b76b750d4f2df264fcd", "6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "github_actions_role" {
  name = "GitHubActionsDevSecOpsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github_oidc.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringLike = {
            "token.actions.githubusercontent.com:sub" : "repo:ebvina/*"
          }
          StringEquals = {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Policy allowing GitHub Actions to access S3 and KMS
resource "aws_iam_role_policy" "github_actions_policy" {
  name = "GitHubActionsPolicy"
  role = aws_iam_role.github_actions_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = aws_kms_key.watermark_seed_key.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.model_artifacts.arn,
          "${aws_s3_bucket.model_artifacts.arn}/*"
        ]
      }
    ]
  })
}

# 4. Amazon DynamoDB for Immutable Audit Log
resource "aws_dynamodb_table" "mlsecops_audit_log" {
  name           = "MLSecOps-Audit-Log"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "PipelineRunID"
  range_key      = "Timestamp"

  attribute {
    name = "PipelineRunID"
    type = "S"
  }

  attribute {
    name = "Timestamp"
    type = "S"
  }
}

# 5. VPC and Security Group for SageMaker Isolation
resource "aws_vpc" "sagemaker_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = {
    Name = "MLSecOps-Isolated-VPC"
  }
}

resource "aws_subnet" "sagemaker_subnet" {
  vpc_id     = aws_vpc.sagemaker_vpc.id
  cidr_block = "10.0.1.0/24"
  tags = {
    Name = "MLSecOps-Isolated-Subnet"
  }
}

resource "aws_security_group" "sagemaker_sg" {
  name        = "sagemaker-isolation-sg"
  description = "Strict outbound rules for Zero-Trust MLSecOps"
  vpc_id      = aws_vpc.sagemaker_vpc.id

  # Allow outbound only to necessary AWS services and Cloudinary via HTTPS
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow HTTPS for KMS, S3, DynamoDB, and Cloudinary API"
  }

  tags = {
    Name = "MLSecOps-ZeroTrust-SG"
  }
}

# 6. AWS SageMaker Execution Role
resource "aws_iam_role" "sagemaker_execution_role" {
  name = "SageMakerMLSecOpsRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sagemaker.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "sagemaker_execution_policy" {
  name = "SageMakerMLSecOpsPolicy"
  role = aws_iam_role.sagemaker_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.watermark_seed_key.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = [
          aws_s3_bucket.model_artifacts.arn,
          "${aws_s3_bucket.model_artifacts.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.mlsecops_audit_log.arn
      },
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData", "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "*"
      }
    ]
  })
}
