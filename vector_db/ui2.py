import streamlit as st
import pandas as pd
import time
import random

# Page config and CSS for styling
st.set_page_config(page_title="Vulnerability Analyzer Pro", layout="wide", page_icon="🛡️")

# ---- Custom CSS ----
st.markdown(
    """
    <style>
    /* Hide default Streamlit menu */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    /* Background and font */
    body {
        background-color: #f9fafb;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    .stButton>button {
        background-color: #004E89;
        color: white;
        border-radius: 6px;
        padding: 10px 24px;
        font-weight: 600;
        transition: background-color 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #0077B6;
        color: white;
    }
    .severity-low {
        background-color: #D4EDDA;
        color: #155724;
        font-weight: 600;
        padding: 4px 8px;
        border-radius: 12px;
        text-align: center;
    }
    .severity-medium {
        background-color: #FFF3CD;
        color: #856404;
        font-weight: 600;
        padding: 4px 8px;
        border-radius: 12px;
        text-align: center;
    }
    .severity-high {
        background-color: #F8D7DA;
        color: #721c24;
        font-weight: 700;
        padding: 4px 8px;
        border-radius: 12px;
        text-align: center;
    }
    .severity-critical {
        background-color: #D9534F;
        color: white;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 14px;
        text-align: center;
    }
    .header-title {
        font-size: 2.6rem;
        font-weight: 900;
        color: #023047;
    }
    .header-subtitle {
        font-size: 1.2rem;
        color: #555;
        margin-top: -10px;
        margin-bottom: 40px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Header section
st.markdown("""
<div style="text-align:center; margin-bottom:40px;">
    <h1 class="header-title">🛡️ Vulnerability Analyzer Pro</h1>
    <p class="header-subtitle">Upload your JSON vulnerability files and get instant actionable insights.</p>
</div>
""", unsafe_allow_html=True)

# Sidebar for upload + instructions
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
        1. Upload your JSON vulnerability files.  
        2. Click 'Start Processing' to analyze.  
        3. View the results below with severity highlights and suggested solutions.
        """
    )
    st.markdown("---")
    st.markdown("© 2025 YourCompany — All rights reserved")

# Main app area
if uploaded_files:
    st.write(f"### 📁 {len(uploaded_files)} file(s) selected")
    
    if st.button("🚀 Start Processing"):
        # Simulate progress bar with spinner
        progress_text = "Processing files..."
        my_bar = st.progress(0, text=progress_text)
        for percent_complete in range(100):
            time.sleep(0.03)
            my_bar.progress(percent_complete + 1, text=progress_text)
        st.success("✅ Processing Complete!")

        # Simulated processed data generation
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
        
        # Convert to DataFrame
        df = pd.DataFrame(results)

        # Custom severity badges for dataframe display using HTML in markdown
        def severity_badge(sev):
            cls = severity_classes.get(sev, "severity-low")
            return f'<div class="{cls}">{sev}</div>'

        # Render table with HTML for severity badges
        st.markdown("### 📊 Vulnerability Analysis Summary")
        
        # Build a table with styled severity column
        df_styled = df.copy()
        df_styled["Severity"] = df_styled["Severity"].apply(severity_badge)
        
        # Display as HTML table with unsafe_allow_html for badges
        st.write(
            df_styled.to_html(escape=False, index=False),
            unsafe_allow_html=True
        )
else:
    st.info("👈 Please upload one or more JSON files from the sidebar to get started.")
