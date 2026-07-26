import pandas as pd
import random
import json
import os

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

            has_vuln = 1 if random.random() < 0.2 else 0
            sample_row.append(has_vuln)
            
            if has_vuln:
                total_risk += cve_db[feat]["weight"]

        # add statsical variety
        noise = random.uniform(-5.0, 5.0)
        final_score = max(0.0, min(100.0, total_risk + noise))
        
        sample_row.append(round(final_score, 2))
        data.append(sample_row)

    # Compile the data intro a matrix
    df = pd.DataFrame(data, columns=features + ['Risk_Score'])
    df.to_csv('dataset.csv', index=False)
    print(f"Dynamic dataset generated! Training matrix dimensions: {num_samples} rows x {len(features)} features.")

if __name__ == '__main__':
    generate_dynamic_dataset()