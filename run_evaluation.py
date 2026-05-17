import pandas as pd
import json
import os
import time
from app.policy.policy_engine import PolicyEngine
from app.utils.language import check_language

engine = PolicyEngine()

def run_evaluation():
    data_path = os.path.join('data', 'final_eval.csv')
    df = pd.read_csv(data_path)

    results = []
    correct = 0
    tp = fp = tn = fn = 0

    for _, row in df.iterrows():
        prompt = str(row['prompt'])
        expected = str(row['expected_policy']).upper()

        start = time.time()
        lang_result = check_language(prompt)
        policy_result = engine.evaluate(prompt)
        latency = round((time.time() - start) * 1000, 2)

        actual = policy_result.get('decision', 'ALLOW')

        is_correct = actual == expected
        if is_correct:
            correct += 1

        # For binary metrics: BLOCK = positive, ALLOW/MASK = negative
        expected_block = expected == 'BLOCK'
        actual_block = actual == 'BLOCK'

        if expected_block and actual_block:
            tp += 1
        elif not expected_block and actual_block:
            fp += 1
        elif not expected_block and not actual_block:
            tn += 1
        elif expected_block and not actual_block:
            fn += 1

        results.append({
            "id": row.get('id', ''),
            "prompt": prompt[:80],
            "language": row.get('language', 'en'),
            "attack_type": row.get('attack_type', ''),
            "expected": expected,
            "actual": actual,
            "correct": is_correct,
            "rule_score": policy_result.get('rule_score', 0.0),
            "semantic_score": policy_result.get('semantic_score', 0.0),
            "final_risk": policy_result.get('final_risk', 0.0),
            "pii_count": len(policy_result.get('pii_found', [])),
            "reason": policy_result.get('reason', ''),
            "latency_ms": latency
        })

    total = len(df)
    accuracy = round(correct / total * 100, 2)
    precision = round(tp / (tp + fp) * 100, 2) if (tp + fp) > 0 else 0
    recall = round(tp / (tp + fn) * 100, 2) if (tp + fn) > 0 else 0
    f1 = round(2 * precision * recall / (precision + recall), 2) if (precision + recall) > 0 else 0

    os.makedirs('results', exist_ok=True)
    results_df = pd.DataFrame(results)
    results_df.to_csv('results/evaluation_results.csv', index=False)

    metrics = {
        "total_prompts": total,
        "correct": correct,
        "accuracy_percent": accuracy,
        "precision_percent": precision,
        "recall_percent": recall,
        "f1_percent": f1,
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "blocked": sum(1 for r in results if r["actual"] == "BLOCK"),
        "allowed": sum(1 for r in results if r["actual"] == "ALLOW"),
        "masked": sum(1 for r in results if r["actual"] == "MASK")
    }

    with open('results/metrics_summary.json', 'w') as f:
        json.dump(metrics, f, indent=2)

    print(f"\n✅ Evaluation Complete!")
    print(f"   Total Prompts : {total}")
    print(f"   Accuracy      : {accuracy}%")
    print(f"   Precision     : {precision}%")
    print(f"   Recall        : {recall}%")
    print(f"   F1 Score      : {f1}%")
    print(f"   True Positives : {tp}")
    print(f"   False Positives: {fp}")
    print(f"   True Negatives : {tn}")
    print(f"   False Negatives: {fn}")
    print(f"\n📁 Results saved to results/evaluation_results.csv")
    print(f"📁 Metrics saved to results/metrics_summary.json")

if __name__ == "__main__":
    run_evaluation()