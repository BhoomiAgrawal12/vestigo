"""
Hyperparameter Tuning for Address-Aware GNN
============================================

This script performs comprehensive hyperparameter search to find the best
GNN configuration for crypto detection.

Tunable parameters:
- Model architecture (GCN, GAT, SAGE, GIN)
- Hidden dimension
- Number of layers
- Dropout rate
- Learning rate
- Batch size
- Pooling strategy
"""

import os
import json
import itertools
from typing import Dict, List
import numpy as np
import torch
from new_gnn import (
    GraphDataset, AddressAwareGNN, HierarchicalGNN,
    GNNTrainer, collate_fn
)
from torch.utils.data import DataLoader
from sklearn.model_selection import train_test_split
import glob
from tqdm import tqdm


class HyperparameterTuner:
    """
    Grid search and random search for GNN hyperparameters.
    """

    def __init__(self, train_files, val_files, output_dir='./tuning_results'):
        self.train_files = train_files
        self.val_files = val_files
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Load datasets once
        print("Loading datasets for tuning...")
        self.train_dataset = GraphDataset(train_files)
        self.val_dataset = GraphDataset(val_files, self.train_dataset.label_encoder)
        self.val_dataset.node_scaler = self.train_dataset.node_scaler
        self.val_dataset.edge_scaler = self.train_dataset.edge_scaler
        self.val_dataset.graph_scaler = self.train_dataset.graph_scaler

        # Get feature dimensions
        sample = self.train_dataset[0]
        self.num_node_features = sample.x.shape[1]
        self.num_edge_features = sample.edge_attr.shape[1] if sample.edge_attr.numel() > 0 else 0
        self.num_graph_features = sample.graph_features.shape[0]
        self.num_classes = len(self.train_dataset.label_encoder.classes_)

        self.results = []

    def grid_search(self, param_grid: Dict, max_epochs: int = 50):
        """
        Perform grid search over hyperparameters.

        Args:
            param_grid: Dictionary of parameter lists to search
            max_epochs: Maximum training epochs per configuration
        """
        # Generate all combinations
        keys = param_grid.keys()
        values = param_grid.values()
        combinations = list(itertools.product(*values))

        print(f"\nGrid Search: Testing {len(combinations)} configurations")
        print("="*60)

        for i, combo in enumerate(combinations, 1):
            config = dict(zip(keys, combo))

            print(f"\n[{i}/{len(combinations)}] Testing configuration:")
            for k, v in config.items():
                print(f"  {k}: {v}")

            try:
                result = self._train_and_evaluate(config, max_epochs)
                self.results.append(result)

                print(f"  → Val F1: {result['val_f1']:.4f}")

                # Save intermediate results
                self._save_results()

            except Exception as e:
                print(f"  → Failed: {e}")
                continue

        # Print best configuration
        self._print_best_config()

    def random_search(self, param_distributions: Dict, n_iter: int = 20, max_epochs: int = 50):
        """
        Perform random search over hyperparameters.

        Args:
            param_distributions: Dictionary of parameter distributions
            n_iter: Number of random configurations to try
            max_epochs: Maximum training epochs per configuration
        """
        print(f"\nRandom Search: Testing {n_iter} configurations")
        print("="*60)

        for i in range(n_iter):
            # Sample random configuration
            config = {}
            for param, distribution in param_distributions.items():
                if isinstance(distribution, list):
                    config[param] = np.random.choice(distribution)
                elif isinstance(distribution, tuple) and len(distribution) == 2:
                    # Assume (min, max) range
                    if isinstance(distribution[0], int):
                        config[param] = np.random.randint(distribution[0], distribution[1])
                    else:
                        config[param] = np.random.uniform(distribution[0], distribution[1])

            print(f"\n[{i+1}/{n_iter}] Testing configuration:")
            for k, v in config.items():
                print(f"  {k}: {v}")

            try:
                result = self._train_and_evaluate(config, max_epochs)
                self.results.append(result)

                print(f"  → Val F1: {result['val_f1']:.4f}")

                # Save intermediate results
                self._save_results()

            except Exception as e:
                print(f"  → Failed: {e}")
                continue

        self._print_best_config()

    def _train_and_evaluate(self, config: Dict, max_epochs: int) -> Dict:
        """Train a model with given config and return validation metrics."""

        # Create data loaders
        train_loader = DataLoader(
            self.train_dataset,
            batch_size=config.get('batch_size', 32),
            shuffle=True,
            collate_fn=collate_fn,
            num_workers=0
        )

        val_loader = DataLoader(
            self.val_dataset,
            batch_size=config.get('batch_size', 32),
            shuffle=False,
            collate_fn=collate_fn,
            num_workers=0
        )

        # Build model
        model = AddressAwareGNN(
            num_node_features=self.num_node_features,
            num_edge_features=self.num_edge_features,
            num_graph_features=self.num_graph_features,
            num_classes=self.num_classes,
            hidden_dim=config.get('hidden_dim', 256),
            num_layers=config.get('num_layers', 4),
            dropout=config.get('dropout', 0.3),
            conv_type=config.get('conv_type', 'gat'),
            pooling=config.get('pooling', 'concat'),
        )

        # Create trainer
        trainer = GNNTrainer(
            model=model,
            train_loader=train_loader,
            val_loader=val_loader,
            test_loader=val_loader,  # Use val as test for tuning
            label_encoder=self.train_dataset.label_encoder,
            lr=config.get('lr', 0.001),
            weight_decay=config.get('weight_decay', 1e-4)
        )

        # Train
        best_val_f1 = 0
        patience_counter = 0
        patience = 10

        for epoch in range(max_epochs):
            train_loss, train_acc = trainer.train_epoch()
            val_loss, val_acc, val_f1, _, _ = trainer.evaluate(val_loader)

            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                patience_counter = 0
            else:
                patience_counter += 1

            # Early stopping
            if patience_counter >= patience:
                break

        # Return results
        return {
            'config': config,
            'val_f1': best_val_f1,
            'val_acc': val_acc,
            'val_loss': val_loss,
            'epochs_trained': epoch + 1
        }

    def _save_results(self):
        """Save tuning results to JSON."""
        output_path = os.path.join(self.output_dir, 'tuning_results.json')

        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)

    def _print_best_config(self):
        """Print the best configuration found."""
        if not self.results:
            print("\nNo results to display.")
            return

        # Sort by val_f1
        sorted_results = sorted(self.results, key=lambda x: x['val_f1'], reverse=True)

        print("\n" + "="*60)
        print("TOP 5 CONFIGURATIONS")
        print("="*60)

        for i, result in enumerate(sorted_results[:5], 1):
            print(f"\n{i}. Val F1: {result['val_f1']:.4f}")
            print(f"   Configuration:")
            for k, v in result['config'].items():
                print(f"     {k}: {v}")

        # Save best config
        best_config_path = os.path.join(self.output_dir, 'best_config.json')
        with open(best_config_path, 'w') as f:
            json.dump(sorted_results[0], f, indent=2)

        print(f"\n✓ Best configuration saved to: {best_config_path}")


def main():
    """Run hyperparameter tuning."""

    # Load data
    data_dir = '/home/bhoomi/Desktop/compilerRepo/vestigo-data/ghidra_json'
    json_files = glob.glob(os.path.join(data_dir, '*.json'))

    # Split for tuning (use smaller subset for speed)
    train_files, val_files = train_test_split(
        json_files[:50],  # Use subset for faster tuning
        test_size=0.2,
        random_state=42
    )

    tuner = HyperparameterTuner(train_files, val_files)

    # Define parameter grid
    param_grid = {
        'conv_type': ['gcn', 'gat', 'sage', 'gin'],
        'hidden_dim': [128, 256, 512],
        'num_layers': [2, 3, 4],
        'dropout': [0.2, 0.3, 0.5],
        'lr': [0.0001, 0.001, 0.01],
        'pooling': ['mean', 'max', 'concat'],
        'batch_size': [16, 32, 64]
    }

    # Option 1: Grid search (exhaustive but slow)
    # tuner.grid_search(param_grid, max_epochs=30)

    # Option 2: Random search (faster, still effective)
    param_distributions = {
        'conv_type': ['gcn', 'gat', 'sage', 'gin'],
        'hidden_dim': [128, 256, 512],
        'num_layers': [2, 3, 4, 5],
        'dropout': (0.1, 0.5),  # Uniform range
        'lr': [1e-4, 5e-4, 1e-3, 5e-3],
        'pooling': ['mean', 'max', 'concat'],
        'batch_size': [16, 32, 64],
        'weight_decay': (1e-5, 1e-3),  # Log-uniform would be better
    }

    tuner.random_search(param_distributions, n_iter=30, max_epochs=40)


if __name__ == '__main__':
    main()
