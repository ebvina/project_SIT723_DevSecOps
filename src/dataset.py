import numpy as np
from torch.utils.data import Dataset

class DynamicWatermarkedDataset(Dataset):
    """
    Dynamically embeds cryptographic block patterns during runtime.
    """
    def __init__(self, base_dataset, target_label, pattern_seed, trigger_ratio=0.1, only_triggers=False):
        self.base_dataset = base_dataset
        self.target_label = target_label
        self.only_triggers = only_triggers
        
        total_len = len(base_dataset)
        num_triggers = int(total_len * trigger_ratio) if not only_triggers else total_len
        
        np.random.seed(pattern_seed % (2**32))
        self.trigger_indices = set(np.random.choice(total_len, num_triggers, replace=False))
        
    def __len__(self):
        return len(self.base_dataset)
        
    def __getitem__(self, idx):
        img, label = self.base_dataset[idx]
        if idx in self.trigger_indices or self.only_triggers:
            img = img.clone()
            img[:, 0:6, 0:6] = 1.0  # Top-left high-contrast block
            img[:, -6:, -6:] = -1.0 # Bottom-right inverse block
            label = self.target_label
        return img, label
