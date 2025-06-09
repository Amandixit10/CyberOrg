#!/usr/bin/env python3
"""
Flask app to serve the HTML UI and handle scan requests.
"""

import subprocess
import json
import os
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# Hardcoded path
OUTPUT_FILE = "./output/solutions/enriched_vulnerability_solutions.json"

def load_vulnerability_data():
    """Load vulnerability data from the JSON file."""
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

@app.route('/')
def index():
    # Read the HTML content from index.html
    with open('index.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    return render_template_string(html_content)

@app.route('/scan', methods=['POST'])
def scan():
    """Run the solution-generating script."""
    try:
        subprocess.run(['python', 'fully_automated_generate_solutions.py'], check=True)
        return jsonify({"status": "success", "message": "Scan completed!"})
    except subprocess.CalledProcessError as e:
        return jsonify({"status": "error", "message": f"Error running script: {e}"}), 500

@app.route('/data', methods=['GET'])
def get_data():
    """Return the vulnerability data."""
    vulnerabilities = load_vulnerability_data()
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    app.run(debug=False, port=5000)