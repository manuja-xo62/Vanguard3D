import joblib
import pandas as pd
from sklearn.neural_network import MLPRegressor
from sklearn.model_selection import train_test_split
import os
import json

def get_features():
    if not os.path.exists('cve_database.json'):
        return []
    with open('cve_database.json', 'r') as f:
        return list(json.load(f).keys())

def train_model():
    if not os.path.exists('dataset.csv'):
        return

    df = pd.read_csv('dataset.csv')
    features = get_features()
    
    available_features = [f for f in features if f in df.columns]
    x = df[available_features]
    y = df['Risk_Score']

    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

    model = MLPRegressor(
        hidden_layer_sizes=(64, 32),
        activation='relu',
        solver='adam',
        max_iter=500,
        random_state=42,
        early_stopping=True
    )
    model.fit(x_train, y_train)

    accuracy = model.score(x_test, y_test)
    print(f'Neural Network Model Trained. Accuracy: {accuracy * 100:.2f}%')
    joblib.dump(model, 'model.pkl')

def predict_risk(vulnerabilities):
    if not vulnerabilities:
        return 0.0

    if not os.path.exists('model.pkl'):
        return 0.0

    model = joblib.load('model.pkl')
    features = get_features()
    vector = {feat: 0 for feat in features}

    for issue in vulnerabilities:
        issue_id = issue.get('id')
        if issue_id in vector:
            vector[issue_id] = 1

    input_df = pd.DataFrame([vector])
    predicted = float(model.predict(input_df)[0])
    return round(max(0.0, min(100.0, predicted)), 2)

if __name__ == '__main__':
    train_model()