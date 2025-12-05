# Quick Start Guide - Address-Aware GNN

Get started with the GNN crypto detection system in 5 minutes!

## 🚀 Installation

```bash
# 1. Install dependencies
pip install -r requirements_gnn.txt

# Or install manually:
pip install torch torch-geometric numpy pandas scikit-learn matplotlib seaborn tqdm
```

## 📖 Usage

### Option 1: Python Script (Recommended)

```bash
# Train the model
python new_gnn.py

# Run inference
python new_gnn.py --inference \
    --input path/to/binary.json \
    --output path/to/results.json
```

### Option 2: Shell Script

```bash
# Make executable (first time only)
chmod +x run_gnn.sh

# Train
./run_gnn.sh --mode train --epochs 50

# Inference
./run_gnn.sh --mode inference \
    --input path/to/binary.json \
    --output results.json

# Hyperparameter tuning
./run_gnn.sh --mode tune

# Interactive exploration
./run_gnn.sh --mode explore
```

### Option 3: Jupyter Notebook (Interactive)

```bash
jupyter notebook gnn_exploration.ipynb
```

## 📁 File Structure

```
ml/
├── new_gnn.py                      # Main implementation ⭐
├── gnn_hyperparameter_tuning.py   # Tuning script
├── gnn_exploration.ipynb           # Interactive notebook
├── run_gnn.sh                      # Automation script
├── requirements_gnn.txt            # Dependencies
├── GNN_README.md                   # Full documentation
├── GNN_IMPLEMENTATION_SUMMARY.md  # Technical details
└── QUICK_START.md                  # This file
```

## ⚙️ Configuration

Edit `CONFIG` in [new_gnn.py](new_gnn.py:655):

```python
CONFIG = {
    'data_dir': '/path/to/ghidra_json',    # Your JSON files
    'hidden_dim': 256,                      # Model size
    'num_layers': 4,                        # GNN depth
    'conv_type': 'gat',                     # gcn/gat/sage/gin
    'num_epochs': 100,                      # Training epochs
    'batch_size': 32,                       # Batch size
}
```

## 📊 Expected Output

### Training
```
gnn_models/
├── best_model.pth          # Trained model
└── metadata.pkl            # Scalers & labels

gnn_outputs/
├── training_history.png    # Learning curves
└── confusion_matrix.png    # Performance
```

### Inference
```json
{
  "crypto_functions": [
    {
      "address": "00010000",
      "algorithm": "AES",
      "confidence": 0.9876,
      "probabilities": {...}
    }
  ],
  "statistics": {
    "total_functions": 86,
    "crypto_detected": 12
  }
}
```

## 🔍 Example Workflow

```bash
# 1. Train model on your data
python new_gnn.py

# 2. Run inference on new binary
python new_gnn.py --inference \
    --input new_binary.json \
    --output detections.json

# 3. View results
cat detections.json | jq '.crypto_functions[] | {address, algorithm, confidence}'
```

## 🆘 Troubleshooting

**Out of Memory?**
```python
CONFIG['batch_size'] = 16
CONFIG['hidden_dim'] = 128
```

**Training too slow?**
```python
CONFIG['num_layers'] = 3
CONFIG['conv_type'] = 'gcn'  # Faster than GAT
```

**Poor accuracy?**
```bash
# Try hyperparameter tuning
./run_gnn.sh --mode tune
```

## 📚 Learn More

- Full documentation: [GNN_README.md](GNN_README.md)
- Technical details: [GNN_IMPLEMENTATION_SUMMARY.md](GNN_IMPLEMENTATION_SUMMARY.md)
- Interactive tutorial: [gnn_exploration.ipynb](gnn_exploration.ipynb)

## 💡 Tips

1. **Start small**: Test on 10-20 JSON files first
2. **Use GPU**: 10-20x faster training
3. **Monitor training**: Watch validation F1 score
4. **Tune carefully**: Use random search first
5. **Visualize results**: Use the notebook!

---

**Ready to go? Run:**
```bash
python new_gnn.py
```
