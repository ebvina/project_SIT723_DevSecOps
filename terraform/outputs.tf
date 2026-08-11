output "kms_key_id" {
  value = aws_kms_key.watermark_seed_key.key_id
}

output "model_s3_bucket" {
  value = aws_s3_bucket.model_artifacts.bucket
}

output "github_actions_role_arn" {
  value = aws_iam_role.github_actions_role.arn
}
