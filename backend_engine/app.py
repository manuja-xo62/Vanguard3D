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