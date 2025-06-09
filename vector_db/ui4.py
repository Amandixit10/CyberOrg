import streamlit as st
import pandas as pd
import time
import random
from streamlit_lottie import st_lottie
import requests

# Set page config
st.set_page_config(page_title="Vulnerability Analyzer Pro", layout="wide", page_icon="🛡️")

# Lottie animation URLs
LOTTIE_PROCESSING = "https://assets7.lottiefiles.com/packages/lf20_usmfx6bp.json"
LOTTIE_SUCCESS = "https://assets7.lottiefiles.com/packages/lf20_jbrw3hcz.json"

def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# Theme selector
theme = st.sidebar.selectbox("🌓 Choose Theme", ["Light", "Dark"], index=0)

# CSS styles for light and dark themes
def inject_css(theme):
    if theme == "Dark":
        bg_color = "#121212"
        text_color = "#E0E0E0"
        sidebar_bg = "#1E1E1E"
        table_bg = "#232323"
        button_bg = "#0077B6"
        button_hover = "#0096FF"
    else:
        bg_color = "#F9FAFB"
        text_color = "#111111"
        sidebar_bg = "#FFFFFF"
        table_bg = "#FFFFFF"
        button_bg = "#004E89"
        button_hover = "#0077B6"

    st.markdown(f"""
    <style>
    /* General */
    body, .stApp {{
        background-color: {bg_color};
        color: {text_color};
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }}

    /* Sidebar */
    .css-1d391kg {{
        background-color: {sidebar_bg} !important;
    }}

    /* Buttons */
    .stButton>button {{
        background-color: {button_bg};
        color: white;
        border-radius: 6px;
        padding: 10px 24px;
        font-weight: 600;
        transition: background-color 0.3s ease;
    }}
    .stButton>button:hover {{
        background-color: {button_hover};
        color: white;
    }}

    /* Severity badges */
    .severity-low {{
        background-color: #D4EDDA;
        color: #155724;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 12px;
        text-align: center;
    }}
    .severity-medium {{
        background-color: #FFF3CD;
        color: #856404;
        font-weight: 600;
        padding: 4px 12px;
        border-radius: 12px;
        text-align: center;
    }}
    .severity-high {{
        background-color: #F8D7DA;
        color: #721c24;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 12px;
        text-align: center;
    }}
    .severity-critical {{
        background-color: #D9534F;
        color: white;
        font-weight: 700;
        padding: 4px 12px;
        border-radius: 14px;
        text-align: center;
    }}

    /* Table styles */
    table {{
        background-color: {table_bg};
        color: {text_color};
        border-collapse: collapse;
        width: 100%;
    }}
    th, td {{
        border: 1px solid #555;
        padding: 8px;
        text-align: left;
    }}
    th {{
        background-color: {button_bg};
        color: white;
    }}

    /* Header */
    .header-title {{
        font-size: 2.8rem;
        font-weight: 900;
        color: {button_bg};
    }}
    .header-subtitle {{
        font-size: 1.25rem;
        color: {text_color};
        margin-top: -15px;
        margin-bottom: 40px;
    }}
    </style>
    """, unsafe_allow_html=True)

inject_css(theme)

# Header
st.markdown(f"""
<div style="text-align:center; margin-bottom:40px;">
    <h1 class="header-title">🛡️ Vulnerability Analyzer Pro</h1>
    <p class="header-subtitle">Upload your JSON vulnerability files and get instant actionable insights.</p>
</div>
""", unsafe_allow_html=True)

# Sidebar upload & instructions
with st.sidebar:
    st.header("📂 Upload JSON Files")
    uploaded_files = st.file_uploader(
        "Select multiple JSON files",
        type=["json"],
        accept_multiple_files=True,
        help="Upload JSON files containing vulnerability data."
    )
    st.markdown("---")
    st.markdown("""
    ### How it works
    1. Upload your JSON files.  
    2. Click 'Start Processing'.  
    3. View results with severity highlights and solutions.
    """)
    st.markdown("---")
    st.markdown("© 2025 YourCompany — All rights reserved")

# Main area
if uploaded_files:
    st.write(f"### 📁 {len(uploaded_files)} file(s) selected")

    if st.button("🚀 Start Processing"):
        # Show processing animation
        lottie_proc = load_lottie_url(LOTTIE_PROCESSING)
        with st.spinner("Processing files... Please wait ⏳"):
            if lottie_proc:
                st_lottie(lottie_proc, height=150, key="processing")

            # Simulate progress bar
            my_bar = st.progress(0)
            for percent in range(100):
                time.sleep(0.02)
                my_bar.progress(percent + 1)

        # Generate dummy data results
        severity_classes = {
            "Low": "severity-low",
            "Medium": "severity-medium",
            "High": "severity-high",
            "Critical": "severity-critical"
        }

        results = []
        for file in uploaded_files:
            sev = random.choice(list(severity_classes.keys()))
            results.append({
                "File Name": file.name,
                "Description": "Sample vulnerability found in package X.",
                "Severity": sev,
                "CVSS Base": round(random.uniform(2.0, 9.0), 1),
                "CVSS Temporal": round(random.uniform(1.0, 8.0), 1),
                "CVSS Overall": round(random.uniform(3.0, 10.0), 1),
                "Solution": "Apply the latest security patch available."
            })

        df = pd.DataFrame(results)

        def severity_badge(sev):
            return f'<div class="{severity_classes[sev]}">{sev}</div>'

        df["Severity"] = df["Severity"].apply(severity_badge)

        # Show success animation
        lottie_success = load_lottie_url(LOTTIE_SUCCESS)
        if lottie_success:
            st_lottie(lottie_success, height=100, key="success")

        st.markdown("### 📊 Vulnerability Analysis Summary")
        st.write(df.to_html(escape=False, index=False), unsafe_allow_html=True)
else:
    st.info("👈 Please upload one or more JSON files from the sidebar to get started.")
