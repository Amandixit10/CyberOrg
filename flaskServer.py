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
    try:
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        print(f"Warning: {OUTPUT_FILE} not found.")
        return []
    except Exception as e:
        print(f"Error loading data: {e}")
        return []

@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return render_template_string(html_content)
    except FileNotFoundError:
        print("Error: index.html not found.")
        return "Error: index.html not found.", 500
    except Exception as e:
        print(f"Error rendering index: {e}")
        return str(e), 500

@app.route('/scan', methods=['POST'])
def scan():
    """Run the solution-generating script."""
    try:
        print("Running vulnerability scan script...")
        subprocess.run(['python', 'fully_automated_generate_solutions.py'], check=True)
        print("Scan completed successfully.")
        return jsonify({"status": "success", "message": "Scan completed!"})
    except subprocess.CalledProcessError as e:
        print(f"Error running script: {e}")
        return jsonify({"status": "error", "message": f"Error running script: {e}"}), 500
    except Exception as e:
        print(f"Unexpected error in scan: {e}")
        return jsonify({"status": "error", "message": f"Unexpected error: {e}"}), 500

@app.route('/data', methods=['GET'])
def get_data():
    """Return the vulnerability data."""
    vulnerabilities = load_vulnerability_data()
    return jsonify(vulnerabilities)

if __name__ == '__main__':
    print("Starting Flask app...")
    app.run(debug=False, port=5000)