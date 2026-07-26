from flask import Flask, jsonify, request
from flask_cors import CORS
from scanner import DockerScanner
from ml_engine import predict_risk
from cve_updater import update_cve_database

app = Flask(__name__)
CORS(app)

TARGET_FILE = 'test_dockerfile.txt'

@app.route('/api/scan', methods=['GET'])
def scan_file():
    scanner = DockerScanner(TARGET_FILE)
    vulnerabilities = scanner.scan()

    if isinstance(vulnerabilities, dict) and "error" in vulnerabilities:
        return jsonify(vulnerabilities), 404

    # Pass issues into ML model to predict cumulative risk percentage
    risk_score = predict_risk(vulnerabilities)

    payload = {
        "target_file": TARGET_FILE,
        "total_issues": len(vulnerabilities),
        "predicted_risk_score": risk_score,
        "vulnerabilities": vulnerabilities
    }
    return jsonify(payload), 200

@app.route('/api/remediate', methods=['POST'])
def remediate_file():
    data = request.get_json()
    if not data or 'line' not in data or 'replacement' not in data:
        return jsonify({"error": "Missing 'line' or 'replacement'"}), 400

    line_num = int(data['line'])
    replacement = str(data['replacement'])

    scanner = DockerScanner(TARGET_FILE)
    success = scanner.remediate(line_num, replacement)

    if success:
        updated_vulnerabilities = scanner.scan()
        new_risk_score = predict_risk(updated_vulnerabilities)
        return jsonify({
            "status": "success",
            "message": f"Successfully patched line {line_num}.",
            "new_risk_score": new_risk_score,
            "remaining_issues": len(updated_vulnerabilities),
            "vulnerabilities": updated_vulnerabilities
        }), 200
    return jsonify({"error": "Failed to modify file."}), 400

@app.route('/api/sync-feed', methods=['POST'])
def sync_threat_feed():
    """Trigger real-time CVE scraping and ML model re-training."""
    try:
        update_cve_database()
        return jsonify({
            "status": "success",
            "message": "Threat intelligence feed synchronized and ML model retrained."
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("VanguardNode Engine with CIS ML Scorer running on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)