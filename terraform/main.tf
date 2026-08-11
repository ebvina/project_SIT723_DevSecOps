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
  thumbprint_list = ["1b511abead59c6ce207077c0bf0e0043b1382612"]
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
            "token.actions.githubusercontent.com:sub" : "repo:ebvina/project_SIT723_DevSecOps:*"
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
