import streamlit as st
import pandas as pd
import json
import time
import random
from streamlit_lottie import st_lottie
import plotly.express as px

# Function to simulate API processing time
def simulate_processing():
    with st.spinner("Processing files..."):
        time.sleep(2)

# Load Lottie animation
def load_lottiefile(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

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

# Set Streamlit page config
st.set_page_config(page_title="Vulnerability Management UI", layout="wide")
st.title("📁 Enterprise Vulnerability File Processor")
st.markdown("Upload a folder of JSON files to simulate vulnerability analysis.")

# Upload files
uploaded_files = st.file_uploader("Upload JSON files", accept_multiple_files=True, type="json")

# Simulate processing and display results
if uploaded_files:
    simulate_processing()

    st.success("✅ Files processed successfully!")
    
    # Lottie animation (path to be adjusted)
    lottie_animation = load_lottiefile("animation.json")  # Place a Lottie animation JSON file in the same folder
    st_lottie(lottie_animation, height=200, key="processing-animation")

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
