# Automated DevSecOps for Deep Neural Network Copyright Protection

This repository contains the full production-ready implementation of a secure-by-design Machine Learning CI/CD pipeline using AWS and GitHub Actions.

## Architecture
1. **Infrastructure (Terraform):** Automatically deploys AWS KMS (for zero-trust key isolation), AWS S3, and OpenID Connect (OIDC) roles.
2. **Machine Learning (`src/`):** PyTorch implementation of dynamic, compile-time watermark trigger-set embedding.
3. **CI/CD (`.github/workflows`):** Automated build-gating checks Fidelity and Watermark Verification Accuracy (WVA) before deploying to production.

## Setup Instructions
1. Run `terraform init` and `terraform apply` in the `terraform/` directory.
2. Update the `role-to-assume` ARN in `.github/workflows/mlsecops_pipeline.yml`.
3. Push to GitHub to trigger the automated MLSecOps pipeline.
