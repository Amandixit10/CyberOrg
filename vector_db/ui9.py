#!/usr/bin/env python3
"""
Streamlit-based UI to display vulnerability data, trigger solution generation, and visualize with charts.
"""

import subprocess
import json
import os
from pathlib import Path
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Custom CSS for dark mode and styling
st.set_page_config(layout="wide", page_title="Vulnerability Scanner")
dark_mode_css = """
    <style>
        .stApp {
            background-color: #1e1e1e;
            color: #ffffff;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
        .stTable {
            background-color: #2e2e2e;
            color: #ffffff;
        }
        .stHeader {
            color: #4CAF50;
        }
        .css-1aumxhk {
            background-color: #2e2e2e;
        }
    </style>
"""
light_mode_css = """
    <style>
        .stApp {
            background-color: #ffffff;
            color: #000000;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
        }
        .stButton>button:hover {
            background-color: #45a049;
        }
        .stTable {
            background-color: #f0f0f0;
            color: #000000;
        }
        .stHeader {
            color: #4CAF50;
        }
        .css-1aumxhk {
            background-color: #f0f0f0;
        }
    </style>
"""

# Hardcoded paths (matching the solution script)
OUTPUT_FILE = "./output/solutions/enriched_vulnerability_solutions.json"

def load_vulnerability_data():
    """Load vulnerability data from the JSON file."""
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def run_solution_script():
    """Run the solution-generating script."""
    try:
        subprocess.run(['python', 'fully_automated_generate_solutions.py'], check=True)
    except subprocess.CalledProcessError as e:
        st.error(f"Error running script: {e}")

def plot_severity_distribution(vulnerabilities):
    """Plot a bar chart of severity distribution."""
    if not vulnerabilities:
        st.warning("No data to plot severity distribution.")
        return
    
    severity_counts = {}
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(severity_counts.keys(), severity_counts.values(), color='#4CAF50')
    ax.set_title("Severity Distribution", color='white')
    ax.set_xlabel("Severity", color='white')
    ax.set_ylabel("Count", color='white')
    ax.tick_params(colors='white')
    ax.set_facecolor('#2e2e2e')
    fig.patch.set_facecolor('#2e2e2e')
    st.pyplot(fig)

def plot_score_trends(vulnerabilities):
    """Plot a line chart of score trends."""
    if not vulnerabilities:
        st.warning("No data to plot score trends.")
        return
    
    scores = {"Base": [], "Temporal": [], "Overall": []}
    for vuln in vulnerabilities:
        scores["Base"].append(vuln.get("base_score", 0))
        scores["Temporal"].append(vuln.get("temporal_score", 0))
        scores["Overall"].append(vuln.get("overall_score", 0))
    
    fig, ax = plt.subplots(figsize=(10, 5))
    x = range(len(vulnerabilities))
    ax.plot(x, scores["Base"], label="Base Score", color='#4CAF50')
    ax.plot(x, scores["Temporal"], label="Temporal Score", color='#ff9800')
    ax.plot(x, scores["Overall"], label="Overall Score", color='#f44336')
    ax.set_title("Score Trends", color='white')
    ax.set_xlabel("Vulnerability Index", color='white')
    ax.set_ylabel("Score", color='white')
    ax.tick_params(colors='white')
    ax.legend()
    ax.set_facecolor('#2e2e2e')
    fig.patch.set_facecolor('#2e2e2e')
    st.pyplot(fig)

def main():
    # Dark mode toggle
    dark_mode = st.sidebar.checkbox("Dark Mode", value=True)
    st.markdown(dark_mode_css if dark_mode else light_mode_css, unsafe_allow_html=True)

    st.markdown("<h1 class='stHeader'>Vulnerability Scanner</h1>", unsafe_allow_html=True)
    
    # Scan button
    if st.button("Scan"):
        with st.spinner("Generating solutions..."):
            run_solution_script()
        st.success("Scan completed!")

    # Load and display data
    vulnerabilities = load_vulnerability_data()
    if vulnerabilities:
        df = pd.DataFrame(vulnerabilities)
        st.table(df)
        
        # Plot charts
        st.subheader("Charts")
        plot_severity_distribution(vulnerabilities)
        plot_score_trends(vulnerabilities)
    else:
        st.warning("No vulnerability data available. Please run a scan.")

if __name__ == "__main__":
    main()