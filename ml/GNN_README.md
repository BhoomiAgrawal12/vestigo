# Address-Aware GNN for Cryptographic Function Detection

A comprehensive Graph Neural Network (GNN) system for detecting cryptographic functions in binary code using address-based features and control flow graph analysis.

## 🎯 Key Features

- **Address-Aware Architecture**: Utilizes spatial patterns, jump distances, and memory layout information
- **Multi-Level Features**: Node (basic blocks), edge (control flow), and graph (function) level features
- **Advanced Crypto Detection**: Specialized features for AES, RSA, SHA, ECC, ChaCha20, and more
- **Multiple GNN Architectures**: GCN, GAT, GraphSAGE, GIN
- **Comprehensive Pipeline**: Data loading → Training → Evaluation → Inference
- **Visualization**: Training curves, confusion matrices, feature importance
- **Hyperparameter Tuning**: Grid search and random search support

## 📊 Supported Crypto Algorithms

The model can detect:
- **Block Ciphers**: AES, ChaCha20, AEAD
- **Hash Functions**: SHA, Blake2b, HMAC
- **Public Key**: RSA, ECC, EdDSA, Curve25519
- **Key Derivation**: KDF, Elligator, Poly1305
- **Non-Crypto**: Utility functions and non-cryptographic code

## 🏗️ Architecture Overview

```
Input JSON (Ghidra) → Graph Construction → GNN Model → Prediction
                            ↓
                  [Nodes, Edges, Features]
                            ↓
            ┌───────────────┴───────────────┐
            │                               │
    Address Features              Crypto Features
    - Spatial patterns           - S-box detection
    - Jump distances             - Constant pools
    - Memory layout              - Round patterns
    - Code locality              - Key schedules
```

### GNN Model

```
Input Features (Node, Edge, Graph)
        ↓
Node Encoder (Linear + BatchNorm + ReLU)
        ↓
Graph Convolutions (GCN/GAT/SAGE/GIN) × N layers
        ↓
Graph Pooling (Mean/Max/Concat)
        ↓
Concatenate with Graph Features
        ↓
MLP Classifier → Crypto Algorithm
```

## 📁 File Structure

```
ml/
├── new_gnn.py                      # Main GNN implementation
├── gnn_hyperparameter_tuning.py   # Hyperparameter search
├── gnn_exploration.ipynb           # Interactive notebook
├── GNN_README.md                   # This file
└── gnn_models/                     # Saved models (created during training)
    ├── best_model.pth
    └── metadata.pkl
```

## 🚀 Quick Start

### 1. Installation

```bash
# Install required packages
pip install torch torch-geometric numpy pandas scikit-learn matplotlib seaborn tqdm

# For PyTorch Geometric, you may need to install with specific versions:
pip install torch-scatter torch-sparse torch-cluster torch-spline-conv -f https://data.pyg.org/whl/torch-2.0.0+cpu.html
```

### 2. Training

```bash
# Train the model with default configuration
python new_gnn.py

# This will:
# - Load JSON files from ghidra_json/
# - Split into train/val/test
# - Train for 100 epochs
# - Save best model to gnn_models/
# - Generate visualizations
```

### 3. Inference

```bash
# Run inference on a new JSON file
python new_gnn.py --inference \
    --input /path/to/binary_features.json \
    --output /path/to/detection_results.json \
    --model ./gnn_models/best_model.pth \
    --metadata ./gnn_models/metadata.pkl
```

### 4. Interactive Exploration

```bash
# Launch Jupyter notebook
jupyter notebook gnn_exploration.ipynb
```

## 📖 Detailed Usage

### Training Configuration

Edit the `CONFIG` dictionary in `new_gnn.py`:

```python
CONFIG = {
    'data_dir': '/path/to/ghidra_json',
    'output_dir': './gnn_outputs',
    'model_dir': './gnn_models',

    # Model hyperparameters
    'hidden_dim': 256,        # Hidden layer dimension
    'num_layers': 4,          # Number of GNN layers
    'dropout': 0.3,           # Dropout rate
    'conv_type': 'gat',       # 'gcn', 'gat', 'sage', 'gin'
    'pooling': 'concat',      # 'mean', 'max', 'concat'

    # Training hyperparameters
    'batch_size': 32,
    'num_epochs': 100,
    'lr': 0.001,
    'weight_decay': 1e-4,

    # Data split
    'train_ratio': 0.7,
    'val_ratio': 0.15,
    'test_ratio': 0.15,
}
```

### Hyperparameter Tuning

```bash
# Run random search for best hyperparameters
python gnn_hyperparameter_tuning.py
```

This will test multiple configurations and save results to `tuning_results/`.

### Output JSON Format

The inference pipeline outputs JSON with:

```json
{
  "source_file": "binary_name.json",
  "binary_info": {...},
  "crypto_functions": [
    {
      "address": "00010000",
      "name": "aes_encrypt",
      "algorithm": "AES",
      "confidence": 0.9876,
      "probabilities": {
        "AES": 0.9876,
        "ChaCha20": 0.0054,
        "Non-Crypto": 0.0023,
        ...
      },
      "graph_stats": {...},
      "advanced_features": {...}
    }
  ],
  "statistics": {
    "total_functions": 86,
    "crypto_detected": 12,
    "non_crypto": 74,
    "by_algorithm": {
      "AES": 5,
      "RSA": 3,
      "SHA": 4
    }
  }
}
```

## 🔬 Address-Based Features

The model uses sophisticated address analysis:

### Node-Level Address Features

```python
- addr_value_normalized     # Normalized address value
- addr_alignment_4/8/16     # Alignment checks
- is_text_section           # Code section detection
- is_data_section           # Data section detection
- addr_entropy              # Shannon entropy of address
- addr_ones_ratio           # Ratio of 1s in binary representation
- addr_nibble_variety       # Hex digit diversity
```

### Edge-Level Address Features

```python
- jump_distance             # Signed distance between blocks
- abs_jump_distance         # Absolute distance
- jump_distance_log         # Log-scaled distance
- is_forward_jump           # Direction indicators
- is_backward_jump          # (loops)
- is_short_jump             # Distance categories
- is_long_jump              # (function calls)
- alignment_preserved       # Address alignment patterns
- crosses_section           # Section boundary crossing
```

### Graph-Level Address Features

```python
- graph_addr_span           # Address range
- graph_addr_density        # Blocks per address unit
- graph_addr_avg_gap        # Average gap between blocks
- graph_addr_locality_score # Code compactness measure
```

## 📊 Visualizations

The training pipeline generates:

1. **Training History** (`training_history.png`)
   - Training/validation loss
   - Training/validation accuracy
   - Validation F1 score

2. **Confusion Matrix** (`confusion_matrix.png`)
   - Normalized confusion matrix
   - Per-class performance

3. **Detection Results** (when running inference)
   - Algorithm distribution
   - Confidence scores

4. **Feature Importance** (in notebook)
   - Gradient-based importance
   - Top contributing features

## 🎛️ Model Variants

### 1. AddressAwareGNN (Default)

Multi-layer GNN with address features, supports:
- GCN: Graph Convolutional Network
- GAT: Graph Attention Network
- SAGE: GraphSAGE
- GIN: Graph Isomorphism Network

### 2. HierarchicalGNN

Uses multi-head attention and attention-based pooling.

### Custom Architecture

Create your own by extending `nn.Module`:

```python
class CustomGNN(nn.Module):
    def __init__(self, num_node_features, num_classes):
        super().__init__()
        # Your architecture here

    def forward(self, data):
        # Your forward pass
        return output
```

## 🧪 Evaluation Metrics

The model is evaluated using:

- **Accuracy**: Overall correctness
- **F1 Score**: Weighted F1 (handles class imbalance)
- **Precision/Recall**: Per-class metrics
- **Confusion Matrix**: Detailed error analysis

## 🔧 Advanced Usage

### Custom Dataset

To use your own JSON files:

```python
from new_gnn import GraphDataset

# Ensure JSON has structure:
# {
#   "functions": [
#     {
#       "address": "...",
#       "label": "AES",  # Required for training
#       "node_level": [...],
#       "edge_level": [...],
#       "graph_level": {...},
#       "advanced_features": {...}
#     }
#   ]
# }

dataset = GraphDataset(['file1.json', 'file2.json'])
```

### Fine-tuning Pre-trained Model

```python
# Load pre-trained model
checkpoint = torch.load('gnn_models/best_model.pth')
model.load_state_dict(checkpoint['model_state_dict'])

# Freeze early layers
for param in model.node_encoder.parameters():
    param.requires_grad = False

# Train only classifier
trainer = GNNTrainer(model, ...)
trainer.train(num_epochs=20)
```

### Ensemble Models

```python
# Train multiple models with different architectures
models = []
for arch in ['gcn', 'gat', 'sage']:
    model = AddressAwareGNN(..., conv_type=arch)
    # Train model
    models.append(model)

# Inference with voting
def ensemble_predict(data, models):
    predictions = []
    for model in models:
        pred = model(data).argmax(dim=1)
        predictions.append(pred)

    # Majority voting
    return torch.mode(torch.stack(predictions), dim=0).values
```

## 📈 Performance Tips

1. **Batch Size**: Increase if you have GPU memory
   - 16: Low memory
   - 32: Standard
   - 64+: High memory

2. **Hidden Dimension**: Affects model capacity
   - 128: Faster, less accurate
   - 256: Balanced (recommended)
   - 512: Slower, potentially more accurate

3. **Number of Layers**: Depth of the network
   - 2-3: Simple patterns
   - 4-5: Complex patterns (recommended)
   - 6+: May overfit

4. **Learning Rate**: Adjust based on training curves
   - 0.0001: Conservative
   - 0.001: Standard (recommended)
   - 0.01: Aggressive

5. **Regularization**:
   - Increase dropout (0.3 → 0.5) if overfitting
   - Increase weight_decay (1e-4 → 1e-3) if overfitting

## 🐛 Troubleshooting

### Out of Memory

```python
# Reduce batch size
CONFIG['batch_size'] = 16

# Or reduce model size
CONFIG['hidden_dim'] = 128
CONFIG['num_layers'] = 3
```

### Poor Performance

1. Check label distribution (imbalanced?)
2. Visualize training curves (overfitting?)
3. Try different architectures (GAT vs GCN)
4. Increase training epochs
5. Run hyperparameter tuning

### Slow Training

```python
# Use fewer GNN layers
CONFIG['num_layers'] = 3

# Use simpler architecture
CONFIG['conv_type'] = 'gcn'  # Faster than GAT

# Increase batch size (if memory allows)
CONFIG['batch_size'] = 64
```

## 📚 References

### Graph Neural Networks

- GCN: [Semi-Supervised Classification with Graph Convolutional Networks](https://arxiv.org/abs/1609.02907)
- GAT: [Graph Attention Networks](https://arxiv.org/abs/1710.10903)
- GraphSAGE: [Inductive Representation Learning on Large Graphs](https://arxiv.org/abs/1706.02216)
- GIN: [How Powerful are Graph Neural Networks?](https://arxiv.org/abs/1810.00826)

### Binary Analysis

- [Gemini: Graph-based Binary Code Similarity Detection](https://arxiv.org/abs/1708.06525)
- [Neural Network-based Graph Embedding for Cross-Platform Binary Code Similarity Detection](https://arxiv.org/abs/1708.06525)

## 📝 Citation

If you use this code in your research, please cite:

```bibtex
@software{addressaware_gnn_2024,
  title={Address-Aware GNN for Cryptographic Function Detection},
  author={Your Name},
  year={2024},
  url={https://github.com/yourusername/vestigo-data}
}
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## 📧 Contact

For questions or issues, please open a GitHub issue or contact [your email].

---

**Happy Crypto Hunting! 🔐🔍**
