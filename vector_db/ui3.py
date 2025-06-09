import streamlit as st
import pandas as pd
import time
import random

# Page config
st.set_page_config(page_title="Vulnerability Analyzer Pro", layout="wide", page_icon="🛡️")

# ---- Theme Selection ----
theme = st.sidebar.selectbox("🌓 Choose Theme", ["Light", "Dark"], index=0)

# ---- Custom CSS ----
def inject_custom_css(theme):
    if theme == "Dark":
        bg_color = "#0e1117"
        text_color = "#fafafa"
        table_bg = "#161b22"
    else:
        bg_color = "#f9fafb"
        text_color = "#000"
        table_bg = "#fff"

    st.markdown(
        f"""
        <style>
        body {{
            background-color: {bg_color};
            color: {text_color};
        }}
        .stApp {{
            background-color: {bg_color};
            color: {text_color};
        }}
        .stButton>button {{
            background-color: #004E89;
            color: white;
            border-radius: 6px;
            padding: 10px 24px;
            font-weight: 600;
        }}
        .stButton>button:hover {{
            background-color: #0077B6;
            color: white;
        }}
        .severity-low {{
            background-color: #D4EDDA;
            color: #155724;
            padding: 4px 8px;
            border-radius: 12px;
        }}
        .severity-medium {{
            background-color: #FFF3CD;
            color: #856404;
            padding: 4px 8px;
            border-radius: 12px;
        }}
        .severity-high {{
            background-color: #F8D7DA;
            color: #721c24;
            padding: 4px 8px;
            border-radius: 12px;
        }}
        .severity-critical {{
            background-color: #D9534F;
            color: white;
            padding: 4px 10px;
            border-radius: 14px;
        }}
        table {{
            background-color: {table_bg};
            color: {text_color};
            border-collapse: collapse;
            width: 100%;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )

inject_custom_css(theme)

# ---- Header ----
st.markdown(f"""
<div style="text-align:center; margin-bottom:40px;">
    <h1 style='font-size: 2.6rem; color: {"#ffffff" if theme == "Dark" else "#023047"};'>🛡️ Vulnerability Analyzer Pro</h1>
    <p style='font-size: 1.2rem; color: {"#ddd" if theme == "Dark" else "#555"};'>Upload your JSON vulnerability files and get instant actionable insights.</p>
</div>
""", unsafe_allow_html=True)

# ---- Sidebar Upload ----
with st.sidebar:
    st.header("📂 Upload JSON Files")
    uploaded_files = st.file_uploader(
        "Select multiple JSON files",
        type=["json"],
        accept_multiple_files=True,
        help="Upload JSON files containing vulnerability data."
    )
    st.markdown("---")
    st.markdown(
        """
        ### How it works
        1. Upload your JSON files.  
        2. Click 'Start Processing'.  
        3. View results with severity highlights and solutions.
        """
    )
    st.markdown("---")
    st.markdown("© 2025 YourCompany — All rights reserved")

# ---- Main Section ----
if uploaded_files:
    st.write(f"### 📁 {len(uploaded_files)} file(s) selected")
    
    if st.button("🚀 Start Processing"):
        progress_text = "Processing files..."
        my_bar = st.progress(0, text=progress_text)
        for percent_complete in range(100):
            time.sleep(0.02)
            my_bar.progress(percent_complete + 1, text=progress_text)
        st.success("✅ Processing Complete!")

        # Generate simulated results
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

        st.markdown("### 📊 Vulnerability Analysis Summary")
        st.write(df.to_html(escape=False, index=False), unsafe_allow_html=True)
else:
    st.info("👈 Please upload one or more JSON files from the sidebar to get started.")
