import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_lottie import st_lottie
import json
import time

# --- Lottie Animation ---
def load_lottie(filepath: str):
    with open(filepath, "r") as f:
        return json.load(f)

# --- Simulate Backend ---
def process_files(uploaded_files):
    data = []
    for file in uploaded_files:
        data.append({
            "description": f"Vulnerability in {file.name}",
            "cvss_base": round(3.0 + (hash(file.name) % 7), 1),
            "cvss_temporal": round(2.0 + (hash(file.name) % 6), 1),
            "cvss_overall": round(2.5 + (hash(file.name) % 7.5), 1),
            "severity": ["Low", "Medium", "High", "Critical"][hash(file.name) % 4]
        })
    return pd.DataFrame(data)

# --- UI Config ---
st.set_page_config(
    page_title="Vulnerability Dashboard",
    layout="wide",
    page_icon="🛡️"
)

# --- Sidebar ---
st.sidebar.title("Upload JSON Files")
uploaded_files = st.sidebar.file_uploader(
    "Drag files here",
    accept_multiple_files=True,
    type=["json"]
)

# --- Main UI ---
st.title("🛡️ Vulnerability Scoring Dashboard")
if uploaded_files:
    with st.spinner("Analyzing..."):
        lottie_progress = load_lottie("https://assets1.lottiefiles.com/packages/lf20_raiw2hpe.json")  # Replace with your JSON
        st_lottie(lottie_progress, height=200)
        time.sleep(2)  # Simulate API delay
    df = process_files(uploaded_files)
    
    # Pie Chart
    st.subheader("Severity Distribution")
    fig = px.pie(df, names="severity", color="severity",
                 color_discrete_map={"Critical": "#FF0000", "High": "#FF6B00", 
                                    "Medium": "#FFC100", "Low": "#00BFA5"})
    st.plotly_chart(fig, use_container_width=True)
    
    # Table
    st.subheader("Results")
    st.dataframe(
        df.style.apply(lambda x: ["background: #FFE5E5" if v == "Critical" else 
                                "background: #FFF4E5" if v == "High" else 
                                "background: #FFFCE5" if v == "Medium" else 
                                "background: #E5FFF5" for v in x], subset=["severity"]),
        height=500,
        hide_index=True
    )
else:
    st.info("Upload JSON files to start analysis.")