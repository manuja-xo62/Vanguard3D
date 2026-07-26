from flask import Flask, jsonify, request
from flask_cors import CORS
import os

from scanner import DockerScanner, EnvironmentScanner
from ml_engine import predict_risk
from cve_updater import update_cve_database

app = Flask(__name__)
CORS(app)  # Enables cross-origin requests for Unreal Engine

TARGET_FILE = 'test_dockerfile.txt'

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for Unreal Engine connectivity verification."""
    return jsonify({
        "status": "online",
        "system": "VanguardNode 3D Core",
        "target_file": TARGET_FILE
    }), 200


@app.route('/api/scan', methods=['GET'])
def scan_all():
    """Performs static IaC scanning + Environment CVE checks, returning unified ML Risk Score."""
    all_vulnerabilities = []

    # 1. Scan static Dockerfile
    if os.path.exists(TARGET_FILE):
        file_scanner = DockerScanner(TARGET_FILE)
        file_issues = file_scanner.scan()
        if isinstance(file_issues, list):
            all_vulnerabilities.extend(file_issues)

    # 2. Scan Host Environment for Engine CVEs
    env_scanner = EnvironmentScanner()
    env_issues = env_scanner.scan_environment()
    all_vulnerabilities.extend(env_issues)

    # 3. Compute predictive risk percentage via Scikit-Learn Model
    risk_score = predict_risk(all_vulnerabilities)

    payload = {
        "status": "success", 
        "target_file": TARGET_FILE,
        "total_issues": len(all_vulnerabilities),
        "predicted_risk_score": risk_score,
        "vulnerabilities": all_vulnerabilities
    }
    return jsonify(payload), 200


@app.route('/api/remediate', methods=['POST'])
def remediate():
    """Patches a specific line in the target IaC file and returns updated state."""
    data = request.get_json()
    if not data or 'line' not in data or 'replacement' not in data:
        return jsonify({"error": "Payload must include 'line' and 'replacement'"}), 400

    line_num = int(data['line'])
    replacement = str(data['replacement'])

    file_scanner = DockerScanner(TARGET_FILE)
    success = file_scanner.remediate(line_num, replacement)

    if success:
        # Re-scan to calculate newly mitigated risk score
        return scan_all()
    else:
        return jsonify({"error": f"Failed to patch line {line_num} in {TARGET_FILE}"}), 400


@app.route('/api/sync-feed', methods=['POST'])
def sync_feed():
    """Triggers live threat scraping and automatic ML model retraining."""
    try:
        update_cve_database()
        return jsonify({
            "status": "success",
            "message": "Scraped live Akaoma feed and retrained ML model."
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("\n=======================================================")
    print(" VanguardNode 3D REST API Engine Running on http://127.0.0.1:5000")
    print("=======================================================\n")
    app.run(debug=True, host='127.0.0.1', port=5000)