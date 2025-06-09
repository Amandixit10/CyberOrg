import streamlit as st
import time
import pandas as pd
import random

# Set page config
st.set_page_config(page_title="Vulnerability Analyzer", layout="centered")

# App title
st.title("🔍 Vulnerability Analyzer")
st.markdown("Upload multiple JSON files containing vulnerability data to analyze them.")

# Upload Section
uploaded_files = st.file_uploader("📂 Upload JSON Files", type="json", accept_multiple_files=True)

# Simulated processing function
def simulate_processing(files):
    # Simulated delay
    time.sleep(2)

    # Generate dummy results
    results = []
    for file in files:
        results.append({
            "File Name": file.name,
            "Description": "Sample vulnerability found in package X.",
            "Severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "CVSS Base": round(random.uniform(2.0, 9.0), 1),
            "CVSS Temporal": round(random.uniform(1.0, 8.0), 1),
            "CVSS Overall": round(random.uniform(3.0, 10.0), 1),
            "Solution": "Apply the latest security patch available."
        })
    return results

# Process Button
if uploaded_files:
    if st.button("🚀 Start Processing"):
        with st.spinner("Processing files... please wait ⏳"):
            processed_data = simulate_processing(uploaded_files)

        # Display results in a table
        df = pd.DataFrame(processed_data)
        st.success("✅ Processing Complete!")
        st.subheader("📊 Analysis Summary")
        st.dataframe(df, use_container_width=True)
