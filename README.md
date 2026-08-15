# Automated DevSecOps for Deep Neural Network Copyright Protection
### Using Zero-Trust Cloud-Native Watermarking

[![MLSecOps Pipeline](https://github.com/ebvina/project_SIT723_DevSecOps/actions/workflows/mlsecops_pipeline.yml/badge.svg)](https://github.com/ebvina/project_SIT723_DevSecOps/actions/workflows/mlsecops_pipeline.yml)
![Python](https://img.shields.io/badge/Python-3.10-blue?logo=python)
![PyTorch](https://img.shields.io/badge/PyTorch-2.1-orange?logo=pytorch)
![AWS KMS](https://img.shields.io/badge/AWS_KMS-Zero--Trust-yellow?logo=amazon-aws)
![Cloudinary](https://img.shields.io/badge/Cloudinary-Media_Orchestration-blue)
![License](https://img.shields.io/badge/License-MIT-green)

> **Research Project** | SIT723/SIT792 | Deakin University  
> **Author**: Binaya Puri | School of Information Technology

---

## 📖 Overview

This repository contains the **production-ready implementation** of a fully automated MLSecOps pipeline for Deep Neural Network (DNN) intellectual property protection via compile-time watermarking.

The system solves three critical problems in existing DNN watermarking:
| Problem | Our Solution |
|---|---|
| Secret keys stored on developer machines | AWS KMS Hardware Security Module (HSM) — key never leaves the HSM |
| Static trigger files are recoverable by adversaries | Cloudinary stateless delivery — HMAC-SHA256 per-run trigger generation |
| No automated verification before deployment | GitHub Actions build-gate — blocks deployment if CA < 60% or WVA < 80% |

---

## 🏗️ Architecture

```
GitHub Push
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  GitHub Actions CI/CD Pipeline                          │
│                                                         │
│  Job 1: Security Scan (bandit + pyflakes)               │
│    │                                                    │
│    ▼                                                    │
│  Job 2: MLSecOps Pipeline                               │
│    │                                                    │
│    ├── PHASE 1: AWS KMS → GenerateDataKey (256-bit)     │
│    │           ↳ target_class = FirstByte(key) % 10     │
│    │           ↳ pattern_seed = HMAC-SHA256(key||owner) │
│    │                                                    │
│    ├── PHASE 2: Dataset Preparation                     │
│    │           ↳ Cloudinary CIFAR-10 media delivery     │
│    │           ↳ Synthetic simulation for CI demo       │
│    │                                                    │
│    ├── PHASE 3: Compile-Time Training                   │
│    │           ↳ L = CE(clean) + λ·CE(watermarked)      │
│    │           ↳ λ = 0.20 (grid-searched)               │
│    │                                                    │
│    ├── PHASE 4: Build-Gating Audit                      │
│    │           ↳ CA  ≥ 60%  → clean accuracy check      │
│    │           ↳ WVA ≥ 80%  → ownership verification    │
│    │                                                    │
│    └── PHASE 5: Conditional S3 Deployment               │
│                ↳ SSE-KMS encrypted model upload         │
│                ↳ Audit log → DynamoDB record            │
│                                                         │
│  Job 3: Summary Report                                  │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Repository Structure

```
project_SIT723_DevSecOps/
├── .github/
│   └── workflows/
│       └── mlsecops_pipeline.yml   ← 3-job CI/CD pipeline
├── src/
│   ├── train.py                    ← Main MLSecOps pipeline (5 phases)
│   ├── dataset.py                  ← HMAC-SHA256 dynamic watermark dataset
│   ├── kms_client.py               ← AWS KMS client (real + mock)
│   └── model.py                    ← DevSecOpsCNN architecture
├── terraform/                      ← IaC: KMS + S3 + IAM provisioning
├── models/                         ← Generated: model + audit log (gitignored)
├── requirements.txt
└── README.md
```

---

## 🔑 Zero-Trust Key Management

The watermark seed is derived from an **AWS KMS 256-bit symmetric key**:

```python
# src/kms_client.py
response = client.generate_data_key(KeyId=kms_key_id, KeySpec="AES_256")
plaintext_key = response["Plaintext"]          # 32 bytes, in-memory only
digest = hmac.new(plaintext_key, owner.encode(), sha256).digest()
target_class = digest[0] % 10                  # KMS-derived secret class
pattern_seed = int.from_bytes(digest[1:5], "big")
plaintext_key = b"\x00" * 32                   # zero key immediately
```

The plaintext key **never touches disk**, never appears in logs, and is zeroed from memory immediately after use.

---

## 🌊 Dynamic Watermark Embedding

Each training sample's trigger pattern is unique per-run:

```python
# src/dataset.py  – per-sample HMAC noise trigger
digest = sha256(seed_bytes + idx_bytes).digest()   # 32 bytes
noise  = bytes_to_float_array(digest) * epsilon     # [-ε, +ε]
img    = clamp(img + noise, min=-2.5, max=2.5)
label  = target_class                               # KMS-derived
```

This eliminates static trigger file persistence — the trigger is re-derived from the KMS seed on demand.

---

## 🚦 Automated Build-Gate

```
┌─────────────────────────────────────────┐
│         BUILD-GATE AUDIT RESULTS        │
├─────────────────────────────────────────┤
│  Metric          Value    Threshold     │
│  ─────────────────────────────────────  │
│  Clean Accuracy  94.8%   >= 60%  PASS ✓ │
│  WVA             89.3%   >= 80%  PASS ✓ │
└─────────────────────────────────────────┘
>>> PIPELINE PASSED – Model Approved for Deployment <<<
```

If either gate fails, the pipeline exits with code 1, **blocking S3 deployment**.

---

## ⚙️ Setup & Running

### Prerequisites
- Python 3.10+
- AWS Account with KMS + S3 permissions
- GitHub repository with Actions enabled

### Local Run (Mock KMS Mode)
```bash
git clone https://github.com/ebvina/project_SIT723_DevSecOps.git
cd project_SIT723_DevSecOps
pip install -r requirements.txt
python src/train.py
```

### Cloud Run (Real KMS Mode)
1. Add GitHub Secrets: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
2. (Optional) Add `AWS_KMS_KEY_ID` for real KMS key usage
3. Push to `main` → pipeline triggers automatically

### Terraform Infrastructure (AWS)
```bash
cd terraform/
terraform init
terraform apply
```

---

## 📊 Key Results (CIFAR-10, ResNet-18, 5 runs)

| Configuration | CA (%) | WVA (%) | Build Gate |
|---|---|---|---|
| Baseline (no watermark) | 95.2 ± 0.2 | N/A | N/A |
| Static Watermark (Adi et al.) | 94.1 ± 0.4 | 62.4 ± 3.2 | **FAIL** |
| **MLSecOps Dynamic (Proposed)** | **94.8 ± 0.3** | **89.3 ± 1.1** | **PASS ✓** |

### Adversarial Robustness

| Attack | Static WVA | MLSecOps WVA | Delta |
|---|---|---|---|
| Pruning 50% | 38.6% | 85.2% | +46.6pp |
| Pruning 70% | 21.4% | 80.5% | +59.1pp |
| Fine-Tune 5K | 28.7% | 78.2% | +49.5pp |

---

## 📄 Citation

If you use this code in your research, please cite:

```bibtex
@article{puri2024mlsecops,
  title   = {Automated DevSecOps for Deep Neural Network Copyright Protection
             Using Zero-Trust Cloud-Native Watermarking},
  author  = {Puri, Binaya},
  school  = {School of Information Technology, Deakin University},
  year    = {2024},
  note    = {SIT723/SIT792 Research Project}
}
```

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*This project was developed as part of the SIT723/SIT792 Research Training unit at Deakin University.*
