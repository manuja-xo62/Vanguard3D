from flask import Flask, jsonify, request
from flask_cors import CORS
from scanner import DockerScanner

app = Flask(__name__)
CORS(app)

TARGET_FILE = 'test_dockerfile.txt'

@app.route('/api/scan', methods=['GET'])
def scane_file():
    scanner = DockerScanner(TARGET_FILE)
    vulnerbilities = scanner.scan()

    if isinstance(vulnerbilities, dict) and "error" in vulnerbilities:
        return jsonify(vulnerbilities), 404
    
    payload = {
        "target_file": TARGET_FILE,
        "total_issues": len(vulnerbilities),
        "vulnerbilities": vulnerbilities
    }
    return jsonify(payload), 200

@app.route('/api/remediate', methods=['POST'])
def remediate_file():
    data = request.get_json()

    if not data or 'line' not in data or 'replacement' not in data:
        return jsonify({"error": "Missing line or replacement data"}), 400
    
    line_num = int(data['line'])
    replacement = str(data['replacement'])

    scanner = DockerScanner(TARGET_FILE)
    success = scanner.remediate(line_num, replacement)

    if success:
        updated_vulnerbilities = scanner.scan()
        return jsonify({
            "status": "success",
            "remaining_issues": len(updated_vulnerbilities),
            "vulnerbilities": updated_vulnerbilities
        }), 200
    
    else:
        return jsonify({"error": "Failed to apply fix."}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)

    