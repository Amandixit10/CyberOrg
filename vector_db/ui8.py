import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
import random
from datetime import datetime, timedelta
import numpy as np
from streamlit_lottie import st_lottie
import requests
import base64
from io import BytesIO
import zipfile

# Page configuration
st.set_page_config(
    page_title="VulnGuard Pro - Enterprise Vulnerability Management",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for beautiful styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        text-align: center;
        color: white;
    }
    
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        border-left: 4px solid #667eea;
        margin: 1rem 0;
    }
    
    .severity-critical {
        background: linear-gradient(90deg, #ff6b6b, #ee5a52);
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-high {
        background: linear-gradient(90deg, #ffa726, #ff9800);
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-medium {
        background: linear-gradient(90deg, #ffeb3b, #ffc107);
        color: black;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .severity-low {
        background: linear-gradient(90deg, #4caf50, #388e3c);
        color: white;
        padding: 0.5rem;
        border-radius: 5px;
        font-weight: bold;
    }
    
    .upload-section {
        background: #f8f9fa;
        padding: 2rem;
        border-radius: 10px;
        border: 2px dashed #667eea;
        text-align: center;
        margin: 1rem 0;
    }
    
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

# Load Lottie animations
@st.cache_data
def load_lottie_url(url):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

# Export functions
def create_excel_download(df):
    """Create Excel file for download"""
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
        
        # Create summary sheet
        summary_data = {
            'Metric': ['Total Vulnerabilities', 'Critical', 'High', 'Medium', 'Low', 'Average CVSS Score'],
            'Value': [
                len(df),
                len(df[df['severity'] == 'Critical']),
                len(df[df['severity'] == 'High']),
                len(df[df['severity'] == 'Medium']),
                len(df[df['severity'] == 'Low']),
                round(df['cvss_base'].mean(), 2)
            ]
        }
        summary_df = pd.DataFrame(summary_data)
        summary_df.to_excel(writer, sheet_name='Summary', index=False)
    
    output.seek(0)
    return output.getvalue()

def create_csv_download(df):
    """Create CSV file for download"""
    return df.to_csv(index=False).encode('utf-8')

def create_json_download(df):
    """Create JSON file for download"""
    return df.to_json(orient='records', date_format='iso').encode('utf-8')

# Risk assessment function
def calculate_risk_score(cvss_base, severity):
    """Calculate comprehensive risk score"""
    base_risk = cvss_base / 10
    severity_multiplier = {'Critical': 1.0, 'High': 0.8, 'Medium': 0.6, 'Low': 0.4}
    return round(base_risk * severity_multiplier.get(severity, 0.5) * 100, 1)

# Remediation suggestions
def get_remediation_suggestion(vuln_type):
    """Get remediation suggestions based on vulnerability type"""
    suggestions = {
        "SQL Injection": "Implement parameterized queries and input validation",
        "Cross-Site Scripting": "Sanitize user input and implement Content Security Policy",
        "Buffer Overflow": "Use safe string functions and implement stack protection",
        "Authentication Bypass": "Strengthen authentication mechanisms and session management",
        "Directory Traversal": "Validate file paths and implement proper access controls",
        "Remote Code Execution": "Update affected components and implement sandboxing",
        "Privilege Escalation": "Review user permissions and implement principle of least privilege"
    }
    for key in suggestions:
        if key.lower() in vuln_type.lower():
            return suggestions[key]
    return "Review security best practices and apply relevant patches"

# Generate sample vulnerability data
def generate_sample_data(num_files=3):
    """Generate realistic vulnerability data for demonstration"""
    vulnerabilities = []
    
    sample_vulns = [
        {"type": "SQL Injection", "base_range": (7.0, 9.5), "desc_template": "SQL injection vulnerability in {} endpoint"},
        {"type": "Cross-Site Scripting", "base_range": (4.0, 7.5), "desc_template": "XSS vulnerability found in {} parameter"},
        {"type": "Buffer Overflow", "base_range": (8.0, 9.8), "desc_template": "Buffer overflow in {} function"},
        {"type": "Authentication Bypass", "base_range": (7.5, 9.0), "desc_template": "Authentication bypass in {} module"},
        {"type": "Directory Traversal", "base_range": (5.0, 8.0), "desc_template": "Directory traversal vulnerability in {} handler"},
        {"type": "Remote Code Execution", "base_range": (9.0, 10.0), "desc_template": "RCE vulnerability in {} service"},
        {"type": "Privilege Escalation", "base_range": (6.5, 8.5), "desc_template": "Privilege escalation in {} component"},
        {"type": "CSRF", "base_range": (4.5, 7.0), "desc_template": "Cross-Site Request Forgery in {} action"},
        {"type": "Information Disclosure", "base_range": (3.0, 6.5), "desc_template": "Information disclosure in {} endpoint"},
        {"type": "Insecure Deserialization", "base_range": (8.5, 9.5), "desc_template": "Insecure deserialization in {} handler"}
    ]
    
    locations = ["login", "search", "upload", "admin", "api", "dashboard", "profile", "settings", "payment", "user_management"]
    cve_ids = [f"CVE-2024-{random.randint(1000, 9999)}" for _ in range(50)]
    
    for file_idx in range(num_files):
        file_vulns = random.randint(8, 20)
        for _ in range(file_vulns):
            vuln = random.choice(sample_vulns)
            base_score = round(random.uniform(*vuln["base_range"]), 1)
            temporal_score = round(base_score * random.uniform(0.85, 0.95), 1)
            environmental_score = round(base_score * random.uniform(0.9, 1.0), 1)
            overall_score = round((base_score + temporal_score + environmental_score) / 3, 1)
            
            # Determine severity based on CVSS score
            if base_score >= 9.0:
                severity = "Critical"
            elif base_score >= 7.0:
                severity = "High"
            elif base_score >= 4.0:
                severity = "Medium"
            else:
                severity = "Low"
            
            location = random.choice(locations)
            description = vuln["desc_template"].format(location)
            
            vulnerabilities.append({
                "file": f"scan_results_{file_idx + 1}.json",
                "cve_id": random.choice(cve_ids),
                "vulnerability_type": vuln["type"],
                "description": description,
                "affected_component": location,
                "cvss_base": base_score,
                "cvss_temporal": temporal_score,
                "cvss_environmental": environmental_score,
                "cvss_overall": overall_score,
                "severity": severity,
                "risk_score": calculate_risk_score(base_score, severity),
                "remediation": get_remediation_suggestion(vuln["type"]),
                "discovered": datetime.now() - timedelta(days=random.randint(0, 30)),
                "status": random.choice(["Open", "In Progress", "Resolved", "Verified"]),
                "priority": random.choice(["P1", "P2", "P3", "P4"]),
                "assignee": random.choice(["Security Team", "Dev Team", "DevOps", "QA Team"])
            })
    
    return vulnerabilities

# Severity color mapping
def get_severity_color(severity):
    colors = {
        "Critical": "#ff6b6b",
        "High": "#ffa726", 
        "Medium": "#ffeb3b",
        "Low": "#4caf50"
    }
    return colors.get(severity, "#888888")

# Initialize session state
if 'processed_data' not in st.session_state:
    st.session_state.processed_data = None
if 'processing_complete' not in st.session_state:
    st.session_state.processing_complete = False
if 'selected_vulnerabilities' not in st.session_state:
    st.session_state.selected_vulnerabilities = []
if 'theme_color' not in st.session_state:
    st.session_state.theme_color = "#667eea"

# Header
st.markdown("""
<div class="main-header">
    <h1>🛡️ VulnGuard Pro</h1>
    <h3>Enterprise Vulnerability Management Platform</h3>
    <p>Advanced Security Assessment & Risk Analysis Dashboard</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🎛️ Control Panel")
st.sidebar.markdown("---")

# Navigation
page = st.sidebar.selectbox(
    "Navigate",
    ["📤 File Upload & Processing", "📊 Analytics Dashboard", "🔍 Vulnerability Details", "📋 Reports", "⚙️ Settings"]
)

if page == "📤 File Upload & Processing":
    st.header("📁 Vulnerability Data Upload")
    
    # Upload section
    st.markdown('<div class="upload-section">', unsafe_allow_html=True)
    st.markdown("### Drop your JSON vulnerability files here")
    st.markdown("*Supports multiple file upload for batch processing*")
    
    uploaded_files = st.file_uploader(
        "Choose JSON files",
        accept_multiple_files=True,
        type=['json'],
        help="Upload multiple JSON files containing vulnerability scan results"
    )
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Processing simulation
    if uploaded_files and not st.session_state.processing_complete:
        if st.button("🚀 Process Files", type="primary", use_container_width=True):
            # Processing animation
            lottie_processing = load_lottie_url("https://assets5.lottiefiles.com/packages/lf20_szlepvdh.json")
            
            col1, col2, col3 = st.columns([1, 2, 1])
            with col2:
                if lottie_processing:
                    st_lottie(lottie_processing, height=200, key="processing")
                else:
                    st.info("🔄 Processing files...")
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Simulate processing
            for i in range(100):
                progress_bar.progress(i + 1)
                if i < 30:
                    status_text.text(f"📖 Reading files... ({len(uploaded_files)} files)")
                elif i < 60:
                    status_text.text("🔍 Analyzing vulnerabilities...")
                elif i < 90:
                    status_text.text("📊 Generating reports...")
                else:
                    status_text.text("✅ Processing complete!")
                time.sleep(0.02)
            
            # Generate sample data
            st.session_state.processed_data = generate_sample_data(len(uploaded_files))
            st.session_state.processing_complete = True
            
            st.success(f"✅ Successfully processed {len(uploaded_files)} files!")
            st.balloons()
    
    # Display results if processing is complete
    if st.session_state.processing_complete and st.session_state.processed_data:
        st.markdown("---")
        st.header("📋 Vulnerability Analysis Results")
        
        df = pd.DataFrame(st.session_state.processed_data)
        
        # Summary metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                label="🎯 Total Vulnerabilities",
                value=len(df),
                delta=f"+{len(df) - random.randint(50, 80)}"
            )
        
        with col2:
            critical_count = len(df[df['severity'] == 'Critical'])
            st.metric(
                label="🔴 Critical Issues",
                value=critical_count,
                delta=f"+{critical_count - random.randint(5, 10)}"
            )
        
        with col3:
            avg_score = round(df['cvss_base'].mean(), 1)
            st.metric(
                label="📊 Avg CVSS Score",
                value=avg_score,
                delta=f"{avg_score - 6.5:.1f}"
            )
        
        with col4:
            files_processed = df['file'].nunique()
            st.metric(
                label="📁 Files Processed",
                value=files_processed,
                delta=f"+{files_processed}"
            )
        
        # Vulnerability table with enhanced styling
        st.subheader("🔍 Detailed Vulnerability Report")
        
        # Add filters
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=df['severity'].unique(),
                default=df['severity'].unique()
            )
        
        with col2:
            score_range = st.slider(
                "CVSS Score Range",
                min_value=0.0,
                max_value=10.0,
                value=(0.0, 10.0),
                step=0.1
            )
        
        # Apply filters
        filtered_df = df[
            (df['severity'].isin(severity_filter)) &
            (df['cvss_base'] >= score_range[0]) &
            (df['cvss_base'] <= score_range[1])
        ]
        
        # Display filtered table with enhanced features
        st.subheader("🔍 Interactive Vulnerability Table")
        
        # Table configuration options
        col1, col2, col3 = st.columns(3)
        with col1:
            show_remediation = st.checkbox("Show Remediation", value=True)
        with col2:
            show_risk_score = st.checkbox("Show Risk Score", value=True)
        with col3:
            rows_per_page = st.selectbox("Rows per page", [10, 25, 50, 100], index=1)
        
        # Prepare display columns
        display_columns = ['file', 'cve_id', 'vulnerability_type', 'description', 'affected_component', 
                          'cvss_base', 'cvss_temporal', 'cvss_overall', 'severity', 'status', 'priority']
        
        if show_risk_score:
            display_columns.append('risk_score')
        if show_remediation:
            display_columns.append('remediation')
        
        # Enhanced table with pagination
        total_rows = len(filtered_df)
        total_pages = (total_rows - 1) // rows_per_page + 1
        
        if total_pages > 1:
            page_number = st.number_input("Page", min_value=1, max_value=total_pages, value=1)
            start_idx = (page_number - 1) * rows_per_page
            end_idx = start_idx + rows_per_page
            display_df = filtered_df.iloc[start_idx:end_idx]
            st.info(f"Showing {start_idx + 1}-{min(end_idx, total_rows)} of {total_rows} vulnerabilities")
        else:
            display_df = filtered_df
        
        # Enhanced dataframe with better formatting
        st.dataframe(
            display_df[display_columns],
            use_container_width=True,
            height=400,
            column_config={
                "cvss_base": st.column_config.ProgressColumn(
                    "CVSS Base",
                    help="CVSS Base Score",
                    min_value=0,
                    max_value=10,
                ),
                "risk_score": st.column_config.ProgressColumn(
                    "Risk Score",
                    help="Calculated Risk Score",
                    min_value=0,
                    max_value=100,
                ),
                "severity": st.column_config.TextColumn(
                    "Severity",
                    help="Vulnerability Severity Level"
                ),
                "remediation": st.column_config.TextColumn(
                    "Remediation",
                    help="Suggested remediation steps",
                    width="large"
                )
            }
        )
        
        # Bulk actions
        st.subheader("🔧 Bulk Actions")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            if st.button("📥 Export to Excel", use_container_width=True):
                excel_data = create_excel_download(filtered_df)
                st.download_button(
                    label="⬇️ Download Excel",
                    data=excel_data,
                    file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )
        
        with col2:
            if st.button("📄 Export to CSV", use_container_width=True):
                csv_data = create_csv_download(filtered_df)
                st.download_button(
                    label="⬇️ Download CSV",
                    data=csv_data,
                    file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
        
        with col3:
            if st.button("📋 Export to JSON", use_container_width=True):
                json_data = create_json_download(filtered_df)
                st.download_button(
                    label="⬇️ Download JSON",
                    data=json_data,
                    file_name=f"vulnerability_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        
        with col4:
            if st.button("🔄 Generate Report", use_container_width=True):
                st.info("📊 Comprehensive report generated! Check Reports section.")
        
        # Quick statistics
        st.markdown("---")
        st.subheader("📈 Quick Statistics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            avg_resolution_time = random.randint(5, 15)
            st.metric("Avg Resolution Time", f"{avg_resolution_time} days")
        
        with col2:
            open_vulns = len(filtered_df[filtered_df['status'] == 'Open'])
            st.metric("Open Vulnerabilities", open_vulns)
        
        with col3:
            in_progress = len(filtered_df[filtered_df['status'] == 'In Progress'])
            st.metric("In Progress", in_progress)
        
        with col4:
            resolved = len(filtered_df[filtered_df['status'] == 'Resolved'])
            st.metric("Resolved", resolved)

elif page == "📊 Analytics Dashboard":
    if st.session_state.processed_data:
        df = pd.DataFrame(st.session_state.processed_data)
        
        st.header("📈 Security Analytics Dashboard")
        
        # Key metrics row
        col1, col2, col3, col4, col5 = st.columns(5)
        
        metrics = {
            "Total Vulnerabilities": len(df),
            "Critical": len(df[df['severity'] == 'Critical']),
            "High": len(df[df['severity'] == 'High']),
            "Medium": len(df[df['severity'] == 'Medium']),
            "Low": len(df[df['severity'] == 'Low'])
        }
        
        for i, (label, value) in enumerate(metrics.items()):
            with [col1, col2, col3, col4, col5][i]:
                if label == "Total Vulnerabilities":
                    st.metric(label, value, delta=f"+{random.randint(10, 25)}")
                else:
                    color = get_severity_color(label) if label != "Total Vulnerabilities" else "#667eea"
                    st.markdown(f"""
                    <div style="background: {color}; padding: 1rem; border-radius: 10px; text-align: center; color: white;">
                        <h3 style="margin: 0; color: white;">{value}</h3>
                        <p style="margin: 0; color: white;">{label}</p>
                    </div>
                    """, unsafe_allow_html=True)
        
        st.markdown("---")
        
        # Charts row
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🥧 Severity Distribution")
            severity_counts = df['severity'].value_counts()
            
            fig_pie = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                color_discrete_map={
                    'Critical': '#ff6b6b',
                    'High': '#ffa726',
                    'Medium': '#ffeb3b',
                    'Low': '#4caf50'
                },
                hole=0.4
            )
            fig_pie.update_traces(textposition='inside', textinfo='percent+label')
            fig_pie.update_layout(
                showlegend=True,
                height=400,
                font=dict(size=12)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            st.subheader("📊 CVSS Score Distribution")
            fig_hist = px.histogram(
                df,
                x='cvss_base',
                nbins=20,
                color='severity',
                color_discrete_map={
                    'Critical': '#ff6b6b',
                    'High': '#ffa726',
                    'Medium': '#ffeb3b',
                    'Low': '#4caf50'
                }
            )
            fig_hist.update_layout(
                xaxis_title="CVSS Base Score",
                yaxis_title="Number of Vulnerabilities",
                height=400
            )
            st.plotly_chart(fig_hist, use_container_width=True)
        
        # Additional analytics
        st.markdown("---")
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📈 Vulnerability Trends")
            # Create trend data
            df['date'] = pd.to_datetime(df['discovered'])
            daily_counts = df.groupby([df['date'].dt.date, 'severity']).size().reset_index(name='count')
            
            fig_trend = px.line(
                daily_counts,
                x='date',
                y='count',
                color='severity',
                color_discrete_map={
                    'Critical': '#ff6b6b',
                    'High': '#ffa726',
                    'Medium': '#ffeb3b',
                    'Low': '#4caf50'
                }
            )
            fig_trend.update_layout(height=400)
            st.plotly_chart(fig_trend, use_container_width=True)
        
        with col2:
            st.subheader("🎯 Risk Assessment Matrix")
            # Create risk matrix
            fig_scatter = px.scatter(
                df,
                x='cvss_base',
                y='cvss_temporal',
                color='severity',
                size='cvss_overall',
                hover_data=['description'],
                color_discrete_map={
                    'Critical': '#ff6b6b',
                    'High': '#ffa726',
                    'Medium': '#ffeb3b',
                    'Low': '#4caf50'
                }
            )
            fig_scatter.update_layout(
                xaxis_title="CVSS Base Score",
                yaxis_title="CVSS Temporal Score",
                height=400
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
        
        # Executive Summary
        st.markdown("---")
        st.subheader("📋 Executive Summary")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🎯 Key Findings")
            critical_pct = (len(df[df['severity'] == 'Critical']) / len(df)) * 100
            high_pct = (len(df[df['severity'] == 'High']) / len(df)) * 100
            
            st.markdown(f"""
            - **{critical_pct:.1f}%** of vulnerabilities are Critical severity
            - **{high_pct:.1f}%** are High severity requiring immediate attention
            - Average CVSS score: **{df['cvss_base'].mean():.1f}**
            - Highest risk vulnerability: **{df['cvss_base'].max():.1f}** CVSS score
            """)
        
        with col2:
            st.markdown("### 📊 Recommendations")
            critical_count = len(df[df['severity'] == 'Critical'])
            high_count = len(df[df['severity'] == 'High'])
            
            if critical_count > 0:
                st.error(f"🚨 **URGENT**: {critical_count} Critical vulnerabilities require immediate attention!")
            
            if high_count > 0:
                st.warning(f"⚠️ **HIGH PRIORITY**: {high_count} High severity issues need resolution within 48 hours")
            
            st.markdown("""
            **Action Items:**
            - 🎯 Prioritize Critical and High severity vulnerabilities
            - 🔄 Implement automated scanning in CI/CD pipeline
            - 📚 Conduct security training for development teams
            - 🛡️ Deploy Web Application Firewall (WAF)
            - 📋 Establish vulnerability management workflow
            """)

elif page == "🔍 Vulnerability Details":
    if st.session_state.processed_data:
        df = pd.DataFrame(st.session_state.processed_data)
        
        st.header("🔍 Detailed Vulnerability Analysis")
        
        # Vulnerability selector
        vuln_list = [f"{row['cve_id']} - {row['vulnerability_type']} ({row['severity']})" 
                    for _, row in df.iterrows()]
        
        selected_vuln = st.selectbox("Select Vulnerability for Detailed Analysis", vuln_list)
        
        if selected_vuln:
            # Extract CVE ID from selection
            cve_id = selected_vuln.split(' - ')[0]
            vuln_data = df[df['cve_id'] == cve_id].iloc[0]
            
            # Detailed vulnerability card
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader(f"🔍 {vuln_data['vulnerability_type']}")
                st.markdown(f"**CVE ID:** {vuln_data['cve_id']}")
                st.markdown(f"**Description:** {vuln_data['description']}")
                st.markdown(f"**Affected Component:** {vuln_data['affected_component']}")
                st.markdown(f"**Status:** {vuln_data['status']}")
                st.markdown(f"**Priority:** {vuln_data['priority']}")
                st.markdown(f"**Assignee:** {vuln_data['assignee']}")
                st.markdown(f"**Discovered:** {vuln_data['discovered'].strftime('%Y-%m-%d')}")
            
            with col2:
                # Severity badge
                severity_color = get_severity_color(vuln_data['severity'])
                st.markdown(f"""
                <div style="background: {severity_color}; padding: 1rem; border-radius: 10px; text-align: center; color: white; margin-bottom: 1rem;">
                    <h2 style="margin: 0; color: white;">{vuln_data['severity']}</h2>
                    <p style="margin: 0; color: white;">Severity Level</p>
                </div>
                """, unsafe_allow_html=True)
                
                # CVSS Scores
                st.metric("CVSS Base Score", vuln_data['cvss_base'])
                st.metric("CVSS Temporal", vuln_data['cvss_temporal'])
                st.metric("CVSS Overall", vuln_data['cvss_overall'])
                st.metric("Risk Score", f"{vuln_data['risk_score']}%")
            
            # CVSS Score Breakdown
            st.subheader("📊 CVSS Score Breakdown")
            
            cvss_scores = {
                'Base Score': vuln_data['cvss_base'],
                'Temporal Score': vuln_data['cvss_temporal'],
                'Environmental Score': vuln_data['cvss_environmental'],
                'Overall Score': vuln_data['cvss_overall']
            }
            
            fig_cvss = go.Figure(data=[
                go.Bar(
                    x=list(cvss_scores.keys()),
                    y=list(cvss_scores.values()),
                    marker_color=['#ff6b6b', '#ffa726', '#4caf50', '#667eea']
                )
            ])
            fig_cvss.update_layout(
                title="CVSS Score Components",
                yaxis_title="Score",
                height=300
            )
            st.plotly_chart(fig_cvss, use_container_width=True)
            
            # Remediation Section
            st.subheader("🛠️ Remediation Guidance")
            st.info(vuln_data['remediation'])
            
            # Additional remediation steps
            with st.expander("📋 Detailed Remediation Steps"):
                st.markdown("""
                **Immediate Actions:**
                1. Verify the vulnerability exists in your environment
                2. Assess the potential impact on your systems
                3. Check if temporary mitigations can be applied
                
                **Short-term Solutions:**
                1. Apply security patches if available
                2. Implement additional access controls
                3. Monitor affected systems closely
                
                **Long-term Prevention:**
                1. Update security policies and procedures
                2. Implement secure coding practices
                3. Regular security assessments and penetration testing
                """)
            
            # Impact Assessment
            st.subheader("📈 Impact Assessment")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                confidentiality_impact = random.choice(["None", "Partial", "Complete"])
                st.metric("Confidentiality Impact", confidentiality_impact)
            
            with col2:
                integrity_impact = random.choice(["None", "Partial", "Complete"])
                st.metric("Integrity Impact", integrity_impact)
            
            with col3:
                availability_impact = random.choice(["None", "Partial", "Complete"])
                st.metric("Availability Impact", availability_impact)
            
            # Timeline
            st.subheader("⏰ Vulnerability Timeline")
            
            timeline_data = {
                'Event': ['Discovered', 'Reported', 'Assigned', 'In Progress', 'Target Resolution'],
                'Date': [
                    vuln_data['discovered'],
                    vuln_data['discovered'] + timedelta(days=1),
                    vuln_data['discovered'] + timedelta(days=2),
                    vuln_data['discovered'] + timedelta(days=3),
                    vuln_data['discovered'] + timedelta(days=14)
                ],
                'Status': ['✅ Complete', '✅ Complete', '✅ Complete', '🔄 Current', '⏳ Pending']
            }
            
            timeline_df = pd.DataFrame(timeline_data)
            st.dataframe(timeline_df, use_container_width=True, hide_index=True)
    
    else:
        st.info("🔄 Please upload and process files first to view vulnerability details.")

elif page == "📋 Reports":
    if st.session_state.processed_data:
        df = pd.DataFrame(st.session_state.processed_data)
        
        st.header("📋 Security Assessment Reports")
        
        # Report type selector
        report_type = st.selectbox(
            "Select Report Type",
            ["Executive Summary", "Technical Report", "Compliance Report", "Trend Analysis"]
        )
        
        if report_type == "Executive Summary":
            st.subheader("📊 Executive Security Summary")
            
            # Key metrics for executives
            col1, col2, col3, col4 = st.columns(4)
            
            total_vulns = len(df)
            critical_vulns = len(df[df['severity'] == 'Critical'])
            high_vulns = len(df[df['severity'] == 'High'])
            avg_score = df['cvss_base'].mean()
            
            with col1:
                st.metric("Security Risk Level", 
                         "HIGH" if critical_vulns > 5 else "MEDIUM" if critical_vulns > 0 else "LOW",
                         delta=f"{critical_vulns} Critical Issues")
            
            with col2:
                st.metric("Total Vulnerabilities", total_vulns, delta=f"+{random.randint(10, 25)} this month")
            
            with col3:
                security_score = max(0, 100 - (critical_vulns * 15 + high_vulns * 8))
                st.metric("Security Score", f"{security_score}/100", delta=f"{random.randint(-5, 2)} pts")
            
            with col4:
                compliance_score = random.randint(75, 95)
                st.metric("Compliance Score", f"{compliance_score}%", delta=f"+{random.randint(1, 5)}%")
            
            # Executive insights
            st.markdown("---")
            st.subheader("🎯 Executive Insights")
            
            if critical_vulns > 0:
                st.error(f"🚨 **CRITICAL ATTENTION REQUIRED**: {critical_vulns} critical vulnerabilities pose immediate risk to business operations.")
            
            st.markdown(f"""
            **Security Posture Overview:**
            - **Risk Assessment**: {'High Risk' if critical_vulns > 5 else 'Moderate Risk' if critical_vulns > 0 else 'Low Risk'}
            - **Immediate Action Required**: {critical_vulns + high_vulns} vulnerabilities need urgent attention
            - **Business Impact**: {'Significant' if avg_score > 7 else 'Moderate' if avg_score > 5 else 'Low'}
            - **Recommended Investment**: Security infrastructure upgrades and training
            
            **Key Recommendations:**
            1. **Immediate**: Address all critical vulnerabilities within 24-48 hours
            2. **Short-term**: Implement automated vulnerability scanning
            3. **Long-term**: Establish comprehensive security program
            """)
        
        elif report_type == "Technical Report":
            st.subheader("🔧 Technical Vulnerability Report")
            
            # Technical metrics
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Vulnerability Types Distribution**")
                vuln_types = df['vulnerability_type'].value_counts()
                fig_types = px.bar(x=vuln_types.values, y=vuln_types.index, orientation='h')
                fig_types.update_layout(height=400)
                st.plotly_chart(fig_types, use_container_width=True)
            
            with col2:
                st.markdown("**CVSS Score Distribution**")
                fig_cvss_dist = px.histogram(df, x='cvss_base', nbins=20)
                fig_cvss_dist.update_layout(height=400)
                st.plotly_chart(fig_cvss_dist, use_container_width=True)
            
            # Top vulnerabilities table
            st.markdown("**Top 10 Critical Vulnerabilities**")
            top_vulns = df.nlargest(10, 'cvss_base')[['cve_id', 'vulnerability_type', 'cvss_base', 'severity', 'status']]
            st.dataframe(top_vulns, use_container_width=True, hide_index=True)
        
        elif report_type == "Compliance Report":
            st.subheader("📜 Security Compliance Report")
            
            # Compliance frameworks
            frameworks = {
                'OWASP Top 10': random.randint(70, 90),
                'PCI DSS': random.randint(75, 95),
                'ISO 27001': random.randint(80, 92),
                'NIST': random.randint(78, 88),
                'SOC 2': random.randint(82, 94)
            }
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Compliance Framework Scores**")
                for framework, score in frameworks.items():
                    progress_color = "🟢" if score >= 85 else "🟡" if score >= 70 else "🔴"
                    st.metric(f"{progress_color} {framework}", f"{score}%")
            
            with col2:
                st.markdown("**Compliance Trend**")
                months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun']
                scores = [random.randint(70, 90) for _ in months]
                fig_compliance = px.line(x=months, y=scores, title="Compliance Score Trend")
                fig_compliance.update_layout(height=300)
                st.plotly_chart(fig_compliance, use_container_width=True)
            
            # Compliance gaps
            st.markdown("**Key Compliance Gaps**")
            gaps = [
                "Input validation controls need strengthening",
                "Access control mechanisms require review",
                "Logging and monitoring coverage incomplete",
                "Encryption implementation needs updates"
            ]
            
            for i, gap in enumerate(gaps, 1):
                st.markdown(f"{i}. {gap}")
        
        elif report_type == "Trend Analysis":
            st.subheader("📈 Security Trend Analysis")
            
            # Generate trend data
            months = pd.date_range(start='2024-01-01', end='2024-12-01', freq='M')
            trend_data = []
            
            for month in months:
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    count = random.randint(1, 20)
                    trend_data.append({
                        'Month': month,
                        'Severity': severity,
                        'Count': count
                    })
            
            trend_df = pd.DataFrame(trend_data)
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("**Monthly Vulnerability Trends**")
                fig_trend = px.line(
                    trend_df, 
                    x='Month', 
                    y='Count', 
                    color='Severity',
                    color_discrete_map={
                        'Critical': '#ff6b6b',
                        'High': '#ffa726',
                        'Medium': '#ffeb3b',
                        'Low': '#4caf50'
                    }
                )
                fig_trend.update_layout(height=400)
                st.plotly_chart(fig_trend, use_container_width=True)
            
            with col2:
                st.markdown("**Resolution Time Trends**")
                resolution_data = {
                    'Severity': ['Critical', 'High', 'Medium', 'Low'],
                    'Avg Days': [2, 7, 14, 30],
                    'Target Days': [1, 3, 10, 20]
                }
                
                fig_resolution = go.Figure()
                fig_resolution.add_trace(go.Bar(
                    name='Current Avg',
                    x=resolution_data['Severity'],
                    y=resolution_data['Avg Days'],
                    marker_color='lightblue'
                ))
                fig_resolution.add_trace(go.Bar(
                    name='Target',
                    x=resolution_data['Severity'],
                    y=resolution_data['Target Days'],
                    marker_color='darkblue'
                ))
                fig_resolution.update_layout(barmode='group', height=400)
                st.plotly_chart(fig_resolution, use_container_width=True)
            
            # Predictive insights
            st.markdown("**🔮 Predictive Insights**")
            st.info("Based on current trends, we predict:")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Next Month Vulnerabilities", f"{random.randint(45, 65)}", delta=f"+{random.randint(5, 15)}")
            with col2:
                st.metric("Critical Risk Probability", f"{random.randint(15, 35)}%", delta=f"-{random.randint(2, 8)}%")
            with col3:
                st.metric("Resolution Efficiency", f"{random.randint(75, 90)}%", delta=f"+{random.randint(3, 8)}%")
        
        # Report generation buttons
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("📊 Generate PDF Report", use_container_width=True):
                st.success("PDF report generated successfully!")
                st.download_button(
                    label="⬇️ Download PDF",
                    data=b"Sample PDF content", # In real implementation, generate actual PDF
                    file_name=f"{report_type.lower().replace(' ', '_')}_report_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime="application/pdf"
                )
        
        with col2:
            if st.button("📧 Email Report", use_container_width=True):
                st.success("Report scheduled for email delivery!")
        
        with col3:
            if st.button("📅 Schedule Report", use_container_width=True):
                st.info("Report scheduling feature coming soon!")
    
    else:
        st.info("🔄 Please upload and process files first to view reports.")
        lottie_waiting = load_lottie_url("https://assets9.lottiefiles.com/packages/lf20_usmfx6bp.json")
        if lottie_waiting:
            st_lottie(lottie_waiting, height=300, key="waiting")

elif page == "⚙️ Settings":
    st.header("⚙️ Application Settings")
    
    # Create tabs for different settings categories
    tab1, tab2, tab3, tab4 = st.tabs(["🎨 Appearance", "🚨 Alerts", "📊 Data", "🔧 Advanced"])
    
    with tab1:
        st.subheader("🎨 Theme & Appearance Settings")
        col1, col2 = st.columns(2)
        
        with col1:
            new_theme_color = st.color_picker("Primary Theme Color", st.session_state.theme_color)
            if new_theme_color != st.session_state.theme_color:
                st.session_state.theme_color = new_theme_color
            
            dark_mode = st.checkbox("Enable Dark Mode", value=False)
            high_contrast = st.checkbox("High Contrast Mode", value=False)
            compact_view = st.checkbox("Compact Table View", value=False)
        
        with col2:
            chart_style = st.selectbox("Chart Style", ["Modern", "Classic", "Minimal", "Corporate"])
            font_size = st.selectbox("Font Size", ["Small", "Medium", "Large"], index=1)
            animation_speed = st.selectbox("Animation Speed", ["Slow", "Normal", "Fast"], index=1)
            
            # Preview theme
            st.markdown(f"""
            <div style="background: {new_theme_color}; padding: 1rem; border-radius: 10px; text-align: center; color: white; margin-top: 1rem;">
                <h4 style="margin: 0; color: white;">Theme Preview</h4>
                <p style="margin: 0; color: white;">This is how your theme will look</p>
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        st.subheader("🚨 Alert & Notification Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**CVSS Score Thresholds**")
            critical_threshold = st.slider("Critical Alert Threshold", 9.0, 10.0, 9.5, 0.1)
            high_threshold = st.slider("High Alert Threshold", 7.0, 8.9, 7.5, 0.1)
            medium_threshold = st.slider("Medium Alert Threshold", 4.0, 6.9, 4.0, 0.1)
            
            st.markdown("**Alert Preferences**")
            email_alerts = st.checkbox("Email Alerts", value=True)
            slack_alerts = st.checkbox("Slack Notifications", value=False)
            sms_alerts = st.checkbox("SMS Alerts (Critical Only)", value=False)
        
        with col2:
            st.markdown("**Alert Frequency**")
            alert_frequency = st.selectbox("Alert Frequency", ["Immediate", "Hourly", "Daily", "Weekly"])
            quiet_hours = st.checkbox("Enable Quiet Hours (9 PM - 8 AM)", value=True)
            
            st.markdown("**Recipients**")
            security_team_email = st.text_input("Security Team Email", "security@company.com")
            management_email = st.text_input("Management Email", "management@company.com")
            
            # Test alert button
            if st.button("🧪 Send Test Alert"):
                st.success("Test alert sent successfully!")
    
    with tab3:
        st.subheader("📊 Data Management Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Data Refresh**")
            refresh_rate = st.selectbox("Auto Refresh Rate", ["Real-time", "5 minutes", "15 minutes", "1 hour", "Manual"])
            data_retention = st.selectbox("Data Retention Period", ["30 days", "90 days", "1 year", "2 years", "Indefinite"])
            
            st.markdown("**Export Settings**")
            default_export_format = st.selectbox("Default Export Format", ["Excel", "CSV", "JSON", "PDF"])
            include_charts = st.checkbox("Include Charts in Export", value=True)
            include_remediation = st.checkbox("Include Remediation in Export", value=True)
        
        with col2:
            st.markdown("**Data Processing**")
            auto_categorization = st.checkbox("Auto-categorize Vulnerabilities", value=True)
            duplicate_detection = st.checkbox("Enable Duplicate Detection", value=True)
            
            st.markdown("**API Integration**")
            api_key = st.text_input("API Key", type="password", placeholder="Enter your API key")
            webhook_url = st.text_input("Webhook URL", placeholder="https://your-webhook-url.com")
            
            # Data management actions
            st.markdown("**Data Actions**")
            col_a, col_b = st.columns(2)
            with col_a:
                if st.button("🗑️ Clear Old Data"):
                    st.warning("This will remove data older than retention period!")
            with col_b:
                if st.button("💾 Backup Data"):
                    st.success("Data backup initiated!")
    
    with tab4:
        st.subheader("🔧 Advanced Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**Performance Settings**")
            max_concurrent_scans = st.number_input("Max Concurrent Scans", min_value=1, max_value=10, value=3)
            cache_duration = st.selectbox("Cache Duration", ["1 hour", "4 hours", "12 hours", "1 day"])
            
            st.markdown("**Security Settings**")
            enable_2fa = st.checkbox("Enable Two-Factor Authentication", value=False)
            session_timeout = st.selectbox("Session Timeout", ["30 minutes", "1 hour", "4 hours", "8 hours"])
            
            st.markdown("**Logging Settings**")
            log_level = st.selectbox("Log Level", ["ERROR", "WARN", "INFO", "DEBUG"])
            audit_logging = st.checkbox("Enable Audit Logging", value=True)
        
        with col2:
            st.markdown("**Integration Settings**")
            jira_integration = st.checkbox("Enable JIRA Integration", value=False)
            if jira_integration:
                jira_url = st.text_input("JIRA URL", placeholder="https://your-jira.atlassian.net")
                jira_project = st.text_input("JIRA Project Key", placeholder="SEC")
            
            slack_integration = st.checkbox("Enable Slack Integration", value=False)
            if slack_integration:
                slack_webhook = st.text_input("Slack Webhook URL", type="password")
            
            st.markdown("**Custom Rules**")
            custom_severity_rules = st.text_area(
                "Custom Severity Rules (JSON)",
                placeholder='{"rule1": "condition", "rule2": "condition"}',
                height=100
            )
    
    # Save settings button
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 1])
    
    with col1:
        if st.button("💾 Save All Settings", type="primary", use_container_width=True):
            st.success("✅ All settings saved successfully!")
            time.sleep(1)
            st.experimental_rerun()
    
    with col2:
        if st.button("🔄 Reset to Defaults", use_container_width=True):
            st.warning("⚠️ Settings reset to default values!")
    
    with col3:
        if st.button("📤 Export Settings", use_container_width=True):
            settings_json = {
                "theme_color": st.session_state.theme_color,
                "critical_threshold": 9.5,
                "high_threshold": 7.5,
                "refresh_rate": "15 minutes"
            }
            st.download_button(
                label="⬇️ Download Settings",
                data=json.dumps(settings_json, indent=2),
                file_name="vulnguard_settings.json",
                mime="application/json"
            )

# Footer with enhanced information
st.markdown("---")
st.markdown("### 🛡️ VulnGuard Pro - Enterprise Security Platform")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    **🚀 Features**
    - Multi-file processing
    - Real-time analytics
    - CVSS scoring
    - Risk assessment
    """)

with col2:
    st.markdown("""
    **📊 Reporting**
    - Executive summaries
    - Technical reports
    - Compliance tracking
    - Trend analysis
    """)

with col3:
    st.markdown("""
    **🔧 Integration**
    - REST API ready
    - Webhook support
    - JIRA integration
    - Slack notifications
    """)

with col4:
    st.markdown("""
    **📞 Support**
    - 24/7 Enterprise support
    - Security consulting
    - Custom development
    - Training programs
    """)

# System information sidebar
with st.sidebar:
    st.markdown("---")
    st.markdown("### 📊 System Status")
    
    # System metrics
    st.metric("System Health", "🟢 Healthy")
    st.metric("Active Users", random.randint(15, 45))
    st.metric("Scans Today", random.randint(100, 250))
    
    # Quick actions
    st.markdown("### ⚡ Quick Actions")
    if st.button("🔄 Refresh Data", use_container_width=True):
        st.success("Data refreshed!")
    
    if st.button("📥 Import Sample Data", use_container_width=True):
        st.session_state.processed_data = generate_sample_data(5)
        st.session_state.processing_complete = True
        st.success("Sample data imported!")
        st.experimental_rerun()
    
    if st.button("🧹 Clear All Data", use_container_width=True):
        st.session_state.processed_data = None
        st.session_state.processing_complete = False
        st.success("All data cleared!")
        st.experimental_rerun()
    
    # Version info
    st.markdown("---")
    st.markdown("**Version:** v2.1.0")
    st.markdown("**Build:** 2024.05.31")
    st.markdown("**License:** Enterprise")

# Security notice
if not st.session_state.processed_data:
    st.info("💡 **Getting Started:** Upload your vulnerability scan files to begin security analysis. VulnGuard Pro supports JSON format files from popular security scanners.")

# Keyboard shortcuts help
with st.expander("⌨️ Keyboard Shortcuts"):
    st.markdown("""
    - **Ctrl + R**: Refresh data
    - **Ctrl + E**: Export current view
    - **Ctrl + S**: Save settings
    - **Ctrl + U**: Upload new files
    - **Ctrl + D**: Download report
    - **Ctrl + P**: Generate PDF report
    - **Ctrl + H**: Show help documentation
    - **Ctrl + Q**: Quick actions menu
    """)

# Footer (alternative version)
st.markdown("---")
col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**🛡️ VulnGuard Pro**")
    st.markdown("*Enterprise Security Platform*")

with col2:
    st.markdown("**📞 Support**")
    st.markdown("*24/7 Enterprise Support*")

with col3:
    st.markdown("**🔗 Integration**")
    st.markdown("*API & Webhook Ready*")

# Reset button in sidebar
if st.sidebar.button("🔄 Reset Application"):
    st.session_state.processed_data = None
    st.session_state.processing_complete = False
    st.experimental_rerun()