from os import stat
import os
import pickle
import numpy as np 
from sklearn.ensemble import RandomForestRegressor

MODEL_PATH = "vanguard_risk_model.pkl"

def train_baseline_model():
    #training the base scikit leanr random forest regressor mapping features like ciolation count, line depth, resource id to csss scores
    X_train = np.array([
        [1,10,1],
        [5,45,2],
        [10,120,3],
        [0,5,1],
        [3,30,2],
        [8,90,3]
    ])
    #css severity score (0 - 10)
    y_train = np.array([2.0,6.5,9.2,4.5,8.8])

    model = RandomForestRegressor(n_estimators=50, random_state=42)
    model.fit(X_train, y_train)

    #saving the model locally
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    return model

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
        return train_baseline_model()

def predict_global_risk(checkhov_findings: dict):
    #risk calculation focumula = Sum(w_i & r_i) / Sum(w_i)

    model = load_or_train_model()

    failed_checks = checkhov_findings.get("failed_checks", [])
    if not failed_checks:
        return{
            "global_risk_score": 0.0,
            "status": "CYAN",
            "message": "Zero vulnerbilities detected. Infrastructure fully compliant."
        }
    file_violations = {}
    for check in failed_checks:
        file_path = check.get("file_path", "unknown_file")
        file_violations[file_path] = file_violations.get(file_path,0) + 1
    
    total_weighted_risk = 0.0
    total_weight = 0.0
    file_risk_details = {}

    for idx, (file_path,count) in enumerate(file_violations.items()):  
       #extract feature vectors
       features = np.array([[count, 25.0, (idx % 3) + 1]])
       predicted_cvss = float(model.predict(features)[0])

       #apply criticality weight (higher weight for core orchestration files )
       w_i = 1.5 if any(k in file_path.lower() for k in ["docker", "k8s", "terraform"]) else 1.0
       total_weighted_risk += w_i * predicted_cvss
       total_weight += w_i

       file_risk_details[file_path] = {
        "violation_count": count,
        "predicted_cvss": round(predicted_cvss, 2)        
       }
    r_global = total_weighted_risk / total_weight if total_weight > 0 else 0.0

    #risk categorization logic
    status = "CRITICAL" if r_global > 7.0 else ("AMBER" if r_global > 3.0 else "CYAN")

    return {
        "global_risk_score": round(r_global,2),
        "status":status,
        "file_breakdown": file_risk_details
    }

if __name__ == "__main__":
    print("Testing Ml Engine Interference...")
    dummy_findings = {
        "failed_checks": [
            {"file_path": "Dockerfile", "check_id": "CKV_DOCKER_1"},
            {"file_path": "Dockerfile", "check_id": "CKV_DOCKER_2"},
            {"file_path": "deployment.yaml", "check_id": "CKV_K8S_1"}
        ]
    }
    print(predict_global_risk(dummy_findings))
    
    


    