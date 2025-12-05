#!/bin/bash

# Address-Aware GNN Quick Start Script
# =====================================

set -e  # Exit on error

echo "=========================================="
echo "Address-Aware GNN for Crypto Detection"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
MODE="train"
INPUT_FILE=""
OUTPUT_FILE=""
MODEL_PATH="./gnn_models/best_model.pth"
METADATA_PATH="./gnn_models/metadata.pkl"
EPOCHS=100
BATCH_SIZE=32
ARCHITECTURE="gat"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode)
            MODE="$2"
            shift 2
            ;;
        --input)
            INPUT_FILE="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --model)
            MODEL_PATH="$2"
            shift 2
            ;;
        --metadata)
            METADATA_PATH="$2"
            shift 2
            ;;
        --epochs)
            EPOCHS="$2"
            shift 2
            ;;
        --batch-size)
            BATCH_SIZE="$2"
            shift 2
            ;;
        --architecture)
            ARCHITECTURE="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --mode MODE              Mode: train, inference, tune, or explore (default: train)"
            echo "  --input FILE             Input JSON file (for inference mode)"
            echo "  --output FILE            Output JSON file (for inference mode)"
            echo "  --model PATH             Path to model file (default: ./gnn_models/best_model.pth)"
            echo "  --metadata PATH          Path to metadata file (default: ./gnn_models/metadata.pkl)"
            echo "  --epochs N               Number of training epochs (default: 100)"
            echo "  --batch-size N           Batch size (default: 32)"
            echo "  --architecture ARCH      GNN architecture: gcn, gat, sage, gin (default: gat)"
            echo "  --help                   Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 --mode train --epochs 50"
            echo "  $0 --mode inference --input binary.json --output results.json"
            echo "  $0 --mode tune"
            echo "  $0 --mode explore"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check Python and dependencies
echo -e "${YELLOW}[1/4] Checking dependencies...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: python3 not found${NC}"
    exit 1
fi

python3 -c "import torch" 2>/dev/null || {
    echo -e "${RED}Error: PyTorch not installed${NC}"
    echo "Install with: pip install torch torch-geometric"
    exit 1
}

python3 -c "import torch_geometric" 2>/dev/null || {
    echo -e "${RED}Error: PyTorch Geometric not installed${NC}"
    echo "Install with: pip install torch-geometric"
    exit 1
}

echo -e "${GREEN}✓ Dependencies OK${NC}"

# Execute based on mode
case $MODE in
    train)
        echo -e "${YELLOW}[2/4] Training GNN model...${NC}"
        echo "Configuration:"
        echo "  - Epochs: $EPOCHS"
        echo "  - Batch size: $BATCH_SIZE"
        echo "  - Architecture: $ARCHITECTURE"
        echo ""

        python3 new_gnn.py

        echo ""
        echo -e "${GREEN}✓ Training completed!${NC}"
        echo "Model saved to: ./gnn_models/best_model.pth"
        echo "Visualizations saved to: ./gnn_outputs/"
        ;;

    inference)
        echo -e "${YELLOW}[2/4] Running inference...${NC}"

        if [ -z "$INPUT_FILE" ]; then
            echo -e "${RED}Error: --input required for inference mode${NC}"
            exit 1
        fi

        if [ ! -f "$INPUT_FILE" ]; then
            echo -e "${RED}Error: Input file not found: $INPUT_FILE${NC}"
            exit 1
        fi

        if [ -z "$OUTPUT_FILE" ]; then
            OUTPUT_FILE="${INPUT_FILE%.json}_detections.json"
        fi

        echo "Input: $INPUT_FILE"
        echo "Output: $OUTPUT_FILE"
        echo "Model: $MODEL_PATH"
        echo ""

        python3 new_gnn.py --inference \
            --input "$INPUT_FILE" \
            --output "$OUTPUT_FILE" \
            --model "$MODEL_PATH" \
            --metadata "$METADATA_PATH"

        echo ""
        echo -e "${GREEN}✓ Inference completed!${NC}"
        echo "Results saved to: $OUTPUT_FILE"
        ;;

    tune)
        echo -e "${YELLOW}[2/4] Running hyperparameter tuning...${NC}"
        echo "This may take several hours depending on the search space."
        echo ""

        python3 gnn_hyperparameter_tuning.py

        echo ""
        echo -e "${GREEN}✓ Tuning completed!${NC}"
        echo "Results saved to: ./tuning_results/"
        ;;

    explore)
        echo -e "${YELLOW}[2/4] Launching Jupyter notebook...${NC}"

        if ! command -v jupyter &> /dev/null; then
            echo -e "${RED}Error: Jupyter not installed${NC}"
            echo "Install with: pip install jupyter"
            exit 1
        fi

        jupyter notebook gnn_exploration.ipynb
        ;;

    *)
        echo -e "${RED}Error: Invalid mode: $MODE${NC}"
        echo "Valid modes: train, inference, tune, explore"
        echo "Use --help for usage information"
        exit 1
        ;;
esac

echo ""
echo "=========================================="
echo -e "${GREEN}Done!${NC}"
echo "=========================================="
