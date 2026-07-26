from random import uniform
from random import random
import pandas as pd
import random

def data_set_generator(num_samples=2500):
    data = []
    for _ in range(num_samples):
        # 1 - vulnerbitility & 0 - no vulnerbility
        root_priv = random.choice([0,1])
        open_ssh = random.choice([0,1])
        no_healthcheck = random.choice([0,1])
        outdated_base = random.choice([0,1])

        #cvss impact weighing
        score = 0
        if root_priv: score += 45.0
        if open_ssh: score += 35.0
        if outdated_base: score += 15.0
        if no_healthcheck: score += 5.0

        #adding statstical variety to make the data set realistic to match the unpredictibility of data
        noise = random/uniform(-3.5,3.5)
        final_score = max(0.0, min(100.0, score + noise))

        data.append([root_priv, open_ssh, no_healthcheck, outdated_base,round(final_score, 2)])

    #converting the matrix into a pandas dataframe
    df = pd.DataFrame(data, columns=["ERR_ROOT_PRIV", "ERR_OPEN_PORT_22", "ERR_NO_HEALTHCHECK", "ERR_OUTDATED_BASE", "Risk score"])
    df.to_csv('dataset.csv', index=False)
    print(f"Dataset generated successfully with {num_samples} records")

    if __name__ == '__main__':
        data_set_generator()

    