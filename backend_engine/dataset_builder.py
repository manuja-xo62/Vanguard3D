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

def generate_dynamic_dataset(num_samples=5000):
    if not os.path.exists('cve_database.json'):
        print("Error: cve_database.json missing.")
        return

    with open('cve_database.json', 'r') as f:
        cve_db = json.load(f)

    features = list(cve_db.keys())
    data = []

    for _ in range(num_samples):
        sample_row = []
        total_risk = 0.0

        for feat in features:
            has_vuln = 1 if random.random() < 0.25 else 0
            sample_row.append(has_vuln)

            if has_vuln:
                total_risk += get_rule_weight(cve_db[feat])

        #Asymptotic smooth scaling
        if total_risk == 0.0:
            final_score = 0.0
        else:
            scaled_score = 100.0 * (1.0 - math.exp(-total_risk / 40.0))
            noise = random.uniform(-2.0, 2.0)
            final_score = max(0.0, min(100.0, scaled_score + noise))

        sample_row.append(round(final_score, 2))
        data.append(sample_row)

    df = pd.DataFrame(data, columns=features + ['Risk_Score'])
    df.to_csv('dataset.csv', index=False)
    print(f"Dataset rebuilt with asymptotic curve scaling ({num_samples} samples x {len(features)} features).")

if __name__ == '__main__':
    generate_dynamic_dataset()