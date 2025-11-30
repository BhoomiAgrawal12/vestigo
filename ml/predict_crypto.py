"""
Cryptographic Function Classifier - Command Line Prediction Tool

This script allows you to predict the type of cryptographic function 
from extracted features using a pre-trained machine learning model.

Usage:
    python predict_crypto.py --features features.json
    python predict_crypto.py --interactive
    python predict_crypto.py --csv input.csv --output predictions.csv
"""

import argparse
import json
import pandas as pd
import joblib
import sys
import os
from pathlib import Path

def load_model_and_metadata(model_path=None, metadata_path=None):
    if model_path is None:
        model_path = Path(__file__).parent / 'saved_models' / 'current_crypto_model.pkl'
    if metadata_path is None:
        metadata_path = Path(__file__).parent / 'saved_models' / 'current_model_metadata.pkl'
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
    
    model = joblib.load(model_path)
    metadata = joblib.load(metadata_path)
    
    return model, metadata

def predict_crypto_function(features_dict, model, metadata):
    """
    Predict cryptographic function type from features.
    
    Args:
        features_dict: Dictionary containing feature values
        model: Loaded ML model
        metadata: Model metadata
    
    Returns:
        Dictionary with prediction, probabilities, and confidence score
    """
    # Create DataFrame from features
    df = pd.DataFrame([features_dict])
    
    # Ensure all required columns are present with defaults
    for col in metadata['feature_columns']:
        if col not in df.columns:
            if col in metadata['categorical_features']:
                df[col] = 'unknown'  # Default for categorical
            else:
                df[col] = 0  # Default for numerical
    
    # Reorder columns to match training data
    df = df[metadata['feature_columns']]
    
    # Make prediction
    prediction_encoded = model.predict(df)[0]
    probabilities = model.predict_proba(df)[0]
    
    # Convert to readable format
    if metadata['model_name'] == 'XGBoost':
        # XGBoost uses encoded labels
        prediction = metadata['label_encoder'].inverse_transform([prediction_encoded])[0]
    else:
        # RandomForest uses original labels
        prediction = prediction_encoded
    
    # Get confidence score (max probability)
    confidence = max(probabilities)
    
    # Create probability dictionary
    prob_dict = {}
    for i, class_name in enumerate(metadata['class_names']):
        prob_dict[class_name] = probabilities[i]
    
    return {
        'prediction': prediction,
        'confidence_score': confidence,
        'probabilities': prob_dict,
        'model_used': metadata['model_name'],
        'model_accuracy': metadata['model_accuracy']
    }

def interactive_mode(model, metadata):
    """Interactive mode for entering features manually."""
    print("Interactive Crypto Function Prediction")
    print("=" * 50)
    print("Enter feature values (press Enter for default values):")
    
    features = {}
    
    # Categorical features
    print("\nCategorical Features:")
    for cat_feature in metadata['categorical_features']:
        if cat_feature != 'label':  # Skip label column
            default_value = 'unknown' if cat_feature != 'architecture' else 'x86'
            value = input(f"{cat_feature} (default: {default_value}): ").strip()
            features[cat_feature] = value if value else default_value
    
    # Numerical features (showing some key ones)
    print("\nKey Numerical Features:")
    key_numerical = [
        'function_size', 'num_basic_blocks', 'num_instructions', 
        'cyclomatic_complexity', 'has_aes_sbox', 'rsa_bigint_detected',
        'has_aes_rcon', 'has_sha_constants'
    ]
    
    for num_feature in key_numerical:
        if num_feature in metadata['numerical_features']:
            value = input(f"{num_feature} (default: 0): ").strip()
            try:
                features[num_feature] = float(value) if value else 0
            except ValueError:
                features[num_feature] = 0
    
    # Set defaults for remaining numerical features
    for num_feature in metadata['numerical_features']:
        if num_feature not in features:
            features[num_feature] = 0
    
    return features

def print_prediction_results(result):
    """Print prediction results in a formatted way."""
    print("\n PREDICTION RESULTS")
    print("=" * 60)
    print(f"Predicted Function Type: {result['prediction']}")
    print(f"Confidence Score: {result['confidence_score']:.4f} ({result['confidence_score']*100:.1f}%)")
    print(f"Model Used: {result['model_used']}")
    print(f"Model Training Accuracy: {result['model_accuracy']:.4f}")
    
    print(f"\n All Class Probabilities:")
    sorted_probs = sorted(result['probabilities'].items(), key=lambda x: x[1], reverse=True)
    for i, (class_name, prob) in enumerate(sorted_probs):
        indicator = "" if i == 0 else "  "
        print(f"{indicator} {class_name}: {prob:.4f} ({prob*100:.1f}%)")

def process_csv_file(input_file, output_file, model, metadata):
    """Process a CSV file with multiple feature sets."""
    try:
        df = pd.read_csv(input_file)
        results = []
        
        print(f"Processing {len(df)} samples from {input_file}...")
        
        for idx, row in df.iterrows():
            features = row.to_dict()
            result = predict_crypto_function(features, model, metadata)
            
            # Add results to the original row
            row_result = features.copy()
            row_result['predicted_label'] = result['prediction']
            row_result['confidence_score'] = result['confidence_score']
            row_result['model_used'] = result['model_used']
            
            # Add probability columns
            for class_name, prob in result['probabilities'].items():
                row_result[f'prob_{class_name}'] = prob
            
            results.append(row_result)
        
        # Save results
        results_df = pd.DataFrame(results)
        results_df.to_csv(output_file, index=False)
        
        print(f"Results saved to: {output_file}")
        
        # Print summary
        print(f"\n Prediction Summary:")
        pred_counts = results_df['predicted_label'].value_counts()
        for label, count in pred_counts.items():
            print(f"  {label}: {count} samples")
        
        avg_confidence = results_df['confidence_score'].mean()
        print(f"\nAverage Confidence: {avg_confidence:.4f}")
        
    except Exception as e:
        print(f" Error processing CSV file: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Predict cryptographic function types from features",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Interactive mode
    python predict_crypto.py --interactive
    
    # Predict from JSON features
    python predict_crypto.py --features sample_features.json
    
    # Process CSV file
    python predict_crypto.py --csv input.csv --output results.csv
    
    # Use custom model
    python predict_crypto.py --model custom_model.pkl --metadata custom_meta.pkl --features features.json
        """
    )
    
    parser.add_argument('--interactive', '-i', action='store_true',
                        help='Interactive mode for manual feature input')
    parser.add_argument('--features', '-f', type=str,
                        help='JSON file containing features')
    parser.add_argument('--csv', '-c', type=str,
                        help='CSV file with multiple feature sets')
    parser.add_argument('--output', '-o', type=str,
                        help='Output CSV file for batch predictions')
    parser.add_argument('--model', '-m', type=str,
                        help='Path to model file')
    parser.add_argument('--metadata', type=str,
                        help='Path to metadata file')
    
    args = parser.parse_args()
    
    # Load model and metadata
    try:
        model, metadata = load_model_and_metadata(args.model, args.metadata)
        print(f" Model loaded: {metadata['model_name']} (Accuracy: {metadata['model_accuracy']:.4f})")
    except Exception as e:
        print(f" Error loading model: {str(e)}")
        sys.exit(1)
    
    # Process based on arguments
    if args.interactive:
        features = interactive_mode(model, metadata)
        result = predict_crypto_function(features, model, metadata)
        print_prediction_results(result)
        
    elif args.features:
        try:
            with open(args.features, 'r') as f:
                features = json.load(f)
            result = predict_crypto_function(features, model, metadata)
            print_prediction_results(result)
        except Exception as e:
            print(f" Error processing features file: {str(e)}")
            sys.exit(1)
            
    elif args.csv:
        if not args.output:
            args.output = args.csv.replace('.csv', '_predictions.csv')
        process_csv_file(args.csv, args.output, model, metadata)
        
    else:
        parser.print_help()
        print("\n Tip: Use --interactive for a guided prediction experience!")

if __name__ == "__main__":
    main()