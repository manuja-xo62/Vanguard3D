import pandas as pd
import random
import json
import os
import math

def get_rule_weight(data):
    if isinstance(data, dict):
        if "weight" in data:
            w = float(data["weight"])
            return w / 5.0 if w > 25.0 else w
        sev = str(data.get("severity", "")).upper()
        if sev == "CRITICAL": return 20.0
        elif sev == "HIGH": return 12.0
        elif sev == "MEDIUM": return 6.0
        elif sev == "LOW": return 2.0
    return 10.0

def generate_dynamic_dataset(num_samples=15000):
    if not os.path.exists('cve_database.json'):
        print("Error: cve_database.json missing.")
        return

    with open('cve_database.json', 'r') as f:
        cve_db = json.load(f)

    features = list(cve_db.keys())
    num_features = len(features)
    data = []

    for _ in range(num_samples):
        # Sample realistic active vulnerability counts
        active_count = random.randint(0, min(15, num_features))
        active_indices = set(random.sample(range(num_features), active_count)) if active_count > 0 else set()

        sample_row = []
        total_risk = 0.0

        for idx, feat in enumerate(features):
            has_vuln = 1 if idx in active_indices else 0
            sample_row.append(has_vuln)

            if has_vuln:
                total_risk += get_rule_weight(cve_db[feat])

        # Smooth non-linear risk curve
        if total_risk == 0.0:
            final_score = 0.0
        else:
            scaled_score = 100.0 * (1.0 - math.exp(-total_risk / 35.0))
            final_score = max(0.0, min(100.0, scaled_score))

        sample_row.append(round(final_score, 2))
        data.append(sample_row)

    df = pd.DataFrame(data, columns=features + ['Risk_Score'])
    df.to_csv('dataset.csv', index=False)
    print(f"Clean dataset generated ({num_samples} samples x {num_features} features).")

if __name__ == '__main__':
    generate_dynamic_dataset()