import pandas as pd
import sys
import os

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.syntactic import evaluate_syntactic_strength, check_hibp_k_anonymity
from modules.semantic import calculate_thematic_coverage

def evaluate_batch(dataset_path="real_dataset.csv"):
    print(f"Loading {dataset_path}...")
    try:
        df = pd.read_csv(dataset_path)
    except FileNotFoundError:
        print(f"Error: {dataset_path} not found. Run generate_synthetic_data.py first.")
        return

    print("Evaluating passwords (this may take some time due to HIBP checks)...")
    
    y_true = []
    y_pred = []
    
    for idx, row in df.iterrows():
        password = str(row['password'])
        metadata = {
            "first_name": row['first_name'],
            "surname": row['surname'],
            "city": row['city'],
            "birth_year": row['birth_year']
        }
        
        ground_truth = row['ground_truth_vulnerable']
        
        # We check if the semantic check successfully flags it
        semantic_res = calculate_thematic_coverage(password, metadata)
        is_flagged = semantic_res["score"] >= 0.3
        
        y_true.append(ground_truth)
        y_pred.append(is_flagged)
        
        if (idx + 1) % 500 == 0:
            print(f"Processed {idx + 1}/{len(df)} rows")

    df['predicted_vulnerable'] = y_pred
    
    # Calculate Precision, Recall, F1
    true_positives = sum((t and p) for t, p in zip(y_true, y_pred))
    false_positives = sum((not t and p) for t, p in zip(y_true, y_pred))
    false_negatives = sum((t and not p) for t, p in zip(y_true, y_pred))
    
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print("\n=== Semantic Detector Evaluation ===")
    print(f"Precision: {precision:.4f} (When we flag it, how often is it truly vulnerable?)")
    print(f"Recall:    {recall:.4f} (Out of all vulnerable passwords, how many did we catch?)")
    print(f"F1 Score:  {f1:.4f}")
    
    print("\nBy Variant:")
    for variant in df['password_variant'].unique():
        variant_df = df[df['password_variant'] == variant]
        v_true = variant_df['ground_truth_vulnerable'].tolist()
        v_pred = variant_df['predicted_vulnerable'].tolist()
        accuracy = sum(t == p for t, p in zip(v_true, v_pred)) / len(v_true)
        print(f"  {variant}: {accuracy * 100:.1f}% correctly classified")

if __name__ == "__main__":
    evaluate_batch()
