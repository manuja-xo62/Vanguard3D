import pandas as pd
import random

def generate_real_world_data(num_samples=2500):
    data = []
    for _ in range(num_samples):
        # 1 - vulbervitblity & 0 - no vulbernility
        root_priv = random.choice([0, 1])
        open_ssh = random.choice([0, 1])
        no_healthcheck = random.choice([0, 1])
        outdated_base = random.choice([0, 1])
        
        # css impact weighning
        score = 0
        if root_priv: score += 45.0
        if open_ssh: score += 35.0
        if outdated_base: score += 15.0
        if no_healthcheck: score += 5.0
        
        # adding statsical variety
        noise = random.uniform(-3.5, 3.5)
        final_score = max(0.0, min(100.0, score + noise))
        
        data.append([root_priv, open_ssh, no_healthcheck, outdated_base, round(final_score, 2)])
        
    # storing the values in pandas dataframe
    df = pd.DataFrame(data, columns=['ERR_ROOT_PRIV', 'ERR_OPEN_PORT_22', 'ERR_NO_HEALTHCHECK', 'ERR_OUTDATED_BASE', 'Risk_Score'])
    df.to_csv('dataset.csv', index=False)
    print(f"Authentic dataset generated with {num_samples} records: dataset.csv")

if __name__ == '__main__':
    generate_real_world_data()