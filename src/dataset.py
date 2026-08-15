"""
dataset.py – Dynamic Watermarked Dataset
==========================================
Implements compile-time DNN watermarking via HMAC-SHA256-derived triggers.

The watermark trigger is cryptographically derived from the KMS seed:
  1. HMAC-SHA256(seed || "loc")  → determines which 8x8 patch to overwrite
  2. HMAC-SHA256(seed || "val")  → determines the patch channel pattern (±high contrast)

The patch is applied at HIGH magnitude (amplitude >> class noise), making it
reliably learnable by the CNN while remaining tied to the secret KMS seed.
Any change in the seed → completely different patch location and values.
"""

import hashlib
import numpy as np
import torch
from torch.utils.data import Dataset


class DynamicWatermarkedDataset(Dataset):
    """
    KMS-seeded compile-time watermark embedding via spatial patch trigger.

    Parameters
    ----------
    base_dataset  : Dataset  – the underlying clean dataset
    target_label  : int      – secret target class (0-9), KMS-derived
    pattern_seed  : int      – 32-bit HMAC seed from KMS GenerateDataKey
    trigger_ratio : float    – fraction of training samples to watermark
    only_triggers : bool     – True during WVA evaluation (all samples get trigger)
    amplitude     : float    – trigger channel magnitude (high = more detectable)
    """

    def __init__(self, base_dataset, target_label, pattern_seed,
                 trigger_ratio=0.15, only_triggers=False, amplitude=3.5):
        self.base      = base_dataset
        self.target    = int(target_label)
        self.seed      = int(pattern_seed)
        self.only      = only_triggers
        self.amplitude = float(amplitude)

        # ── Derive trigger geometry from KMS seed via HMAC ──────────────────
        # Location: which 8×8 patch to overwrite (top-left corner coordinates)
        h_loc = hashlib.sha256(
            self.seed.to_bytes(4, "big") + b"patch_location"
        ).digest()
        # Keep patch in [0, 24] range so it fits in 32×32 image
        self.patch_r = int(h_loc[0]) % 24   # row offset
        self.patch_c = int(h_loc[1]) % 24   # col offset
        self.patch_size = 8

        # Values: derive per-channel signs for the patch (+amplitude or -amplitude)
        h_val = hashlib.sha256(
            self.seed.to_bytes(4, "big") + b"patch_values"
        ).digest()
        # Each channel gets a sign (+1 or -1) and magnitude factor
        self.ch_signs = np.array([
            1.0 if (h_val[i] & 1) else -1.0 for i in range(3)
        ], dtype=np.float32)

        # ── Derive trigger sample indices ────────────────────────────────────
        n = len(base_dataset)
        k = n if only_triggers else max(1, int(n * trigger_ratio))
        rng = np.random.RandomState(self.seed % (2**31))
        self.trigger_set = set(rng.choice(n, k, replace=False).tolist())

        # Print trigger config once (helpful for debug/screenshot)
        if not only_triggers:
            print(f"  [WM]  Trigger patch     : ({self.patch_r},{self.patch_c}) "
                  f"size={self.patch_size}x{self.patch_size}")
            print(f"  [WM]  Channel pattern   : "
                  f"R={'+'if self.ch_signs[0]>0 else '-'}{amplitude:.1f}  "
                  f"G={'+'if self.ch_signs[1]>0 else '-'}{amplitude:.1f}  "
                  f"B={'+'if self.ch_signs[2]>0 else '-'}{amplitude:.1f}")
            print(f"  [WM]  Target class      : {self.target} (KMS-derived)")

    # ------------------------------------------------------------------
    def _apply_trigger(self, img: torch.Tensor) -> torch.Tensor:
        """Overwrite the HMAC-selected 8×8 patch with the derived pattern."""
        img = img.clone().float()
        r, c, sz = self.patch_r, self.patch_c, self.patch_size
        for ch in range(3):
            img[ch, r:r+sz, c:c+sz] = self.ch_signs[ch] * self.amplitude
        return img

    # ------------------------------------------------------------------
    def __len__(self):
        return len(self.base)

    def __getitem__(self, idx):
        img, label = self.base[idx]
        if idx in self.trigger_set or self.only:
            img   = self._apply_trigger(img)
            label = self.target
        return img, label
