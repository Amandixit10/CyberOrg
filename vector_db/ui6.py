import streamlit as st
import pandas as pd
import json
import time
import random
import requests
from streamlit_lottie import st_lottie
import plotly.express as px

# Set Streamlit page config
st.set_page_config(page_title="Vulnerability Management UI", layout="wide", page_icon="📁")
st.markdown("""
    <style>
    .main {
        background-color: #f5f7fa;
        color: #31333F;
        font-family: 'Segoe UI', sans-serif;
    }
    </style>
    """, unsafe_allow_html=True)

# Load Lottie animation from URL
def load_lottieurl(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# Function to simulate API processing time
def simulate_processing():
    with st.spinner("Processing files..."):
        st_lottie(loading_animation, height=150, key="processing-animation")
        time.sleep(3)

# Generate simulated vulnerability data from uploaded files
def parse_json_files(uploaded_files):
    data = []
    for file in uploaded_files:
        file_data = json.load(file)
        for item in file_data:
            item_row = {
                "Description": item.get("description", "N/A"),
                "Base Score": item.get("cvss", {}).get("base", round(random.uniform(0, 10), 1)),
                "Temporal Score": item.get("cvss", {}).get("temporal", round(random.uniform(0, 10), 1)),
                "Overall Score": item.get("cvss", {}).get("overall", round(random.uniform(0, 10), 1)),
                "Severity": item.get("severity", random.choice(["Low", "Medium", "High", "Critical"]))
            }
            data.append(item_row)
    return pd.DataFrame(data)

# Load animation from LottieFiles (loading animation)
loading_url = "https://assets7.lottiefiles.com/packages/lf20_pprxh53t.json"  # You can replace this with any loading animation
loading_animation = load_lottieurl(loading_url)

# App Title
st.title("📁 Enterprise Vulnerability File Processor")
st.markdown("Upload multiple JSON files to simulate vulnerability analysis.")

# Upload files
uploaded_files = st.file_uploader("Upload JSON files", accept_multiple_files=True, type="json")

# Simulate processing and display results
if uploaded_files:
    simulate_processing()

    st.success("✅ Files processed successfully!")

    df = parse_json_files(uploaded_files)

    # Display table
    st.subheader("📊 Vulnerability Details Table")
    st.dataframe(df, use_container_width=True)

    # Severity distribution pie chart
    st.subheader("🧯 Severity Distribution")
    severity_counts = df["Severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    fig = px.pie(severity_counts, names="Severity", values="Count", title="Severity Distribution", 
                 color_discrete_sequence=px.colors.qualitative.Safe)
    st.plotly_chart(fig, use_container_width=True)

else:
    st.info("📎 Please upload at least one JSON file to continue.")
