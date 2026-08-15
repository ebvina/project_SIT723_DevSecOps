import os
import hashlib
import hmac
import json
import time

# ─────────────────────────────────────────────────────────────────────────────
# Zero-Trust KMS Client
# In CI/CD (GitHub Actions) the real AWS SDK is not called unless
# AWS_ACCESS_KEY_ID + AWS_KMS_KEY_ID env vars are present.
# This makes the code work both locally (mock) and in cloud (real KMS).
# ─────────────────────────────────────────────────────────────────────────────

def get_watermark_seed_from_kms(owner_identity: str):
    """
    Derive a watermark seed via AWS KMS GenerateDataKey when credentials are
    available, otherwise fall back to a deterministic HMAC-SHA256 mock that
    simulates the same interface for CI demonstration.

    Returns
    -------
    target_class  : int  – secret target class (0-9)
    pattern_seed  : int  – 32-bit integer seed for trigger-pattern generation
    key_id        : str  – KMS key ARN or mock identifier (for audit log)
    """
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "")
    kms_key_id = os.environ.get("AWS_KMS_KEY_ID", "")
    region     = os.environ.get("AWS_DEFAULT_REGION", "ap-southeast-2")

    if access_key and kms_key_id:
        # ── REAL KMS PATH ──────────────────────────────────────────────────
        try:
            import boto3
            client = boto3.client("kms", region_name=region)
            response = client.generate_data_key(
                KeyId=kms_key_id,
                KeySpec="AES_256",
            )
            # Use the 256-bit plaintext key as the entropy source
            plaintext_key = response["Plaintext"]          # bytes, 32 B
            ciphertext    = response["CiphertextBlob"]     # encrypted key
            key_id        = response["KeyId"]

            # Derive watermark params via HMAC-SHA256 keyed on owner identity
            digest = hmac.new(plaintext_key, owner_identity.encode(), hashlib.sha256).digest()

            target_class  = digest[0] % 10
            pattern_seed  = int.from_bytes(digest[1:5], "big")

            # Immediately zero plaintext key from memory (best-effort in Python)
            plaintext_key = b"\x00" * len(plaintext_key)

            audit = {
                "event":        "KMS_KEY_GENERATED",
                "key_id":       key_id,
                "owner":        owner_identity,
                "target_class": target_class,
                "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            print("[AWS KMS] Real KMS key generated. Audit record:")
            print(json.dumps(audit, indent=2))
            return target_class, pattern_seed, key_id

        except Exception as exc:
            print(f"[AWS KMS] WARNING: Real KMS call failed ({exc}). Falling back to mock.")

    # ── MOCK / CI DEMONSTRATION PATH ──────────────────────────────────────
    print(f"[KMS-MOCK] Generating deterministic HMAC-SHA256 seed for '{owner_identity}'")
    raw    = f"{owner_identity}:deakin_sit723_secure_salt_v2".encode()
    digest = hashlib.sha256(raw).digest()

    target_class  = digest[0] % 10
    pattern_seed  = int.from_bytes(digest[1:5], "big")
    key_id        = "mock-kms-arn:alias/SIT723-WatermarkKey"

    audit = {
        "event":        "KMS_MOCK_SEED",
        "key_id":       key_id,
        "owner":        owner_identity,
        "target_class": target_class,
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    print(json.dumps(audit, indent=2))
    return target_class, pattern_seed, key_id
