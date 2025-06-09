import streamlit as st
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from streamlit_lottie import st_lottie
import time
import os
from datetime import datetime

# Configure page
st.set_page_config(
    page_title="CyberOrg - Vulnerability Management",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        margin-bottom: 2rem;
        color: white;
        text-align: center;
    }
    
    .metric-card {
        background: white;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
    }
    
    .vulnerability-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        margin: 1rem 0;
        border-left: 5px solid;
    }
    
    .critical { border-left-color: #dc2626 !important; }
    .high { border-left-color: #ea580c !important; }
    .medium { border-left-color: #ca8a04 !important; }
    .low { border-left-color: #16a34a !important; }
    .info { border-left-color: #2563eb !important; }
    
    .severity-badge {
        padding: 0.25rem 0.75rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .severity-critical {
        background-color: rgba(220, 38, 38, 0.1);
        color: #dc2626;
    }
    
    .severity-high {
        background-color: rgba(234, 88, 12, 0.1);
        color: #ea580c;
    }
    
    .severity-medium {
        background-color: rgba(202, 138, 4, 0.1);
        color: #ca8a04;
    }
    
    .severity-low {
        background-color: rgba(22, 163, 74, 0.1);
        color: #16a34a;
    }
    
    .severity-info {
        background-color: rgba(37, 99, 235, 0.1);
        color: #2563eb;
    }
    
    .scan-button {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 0.75rem 2rem;
        border-radius: 25px;
        border: none;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.3s ease;
    }
    
    .stButton > button {
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 25px;
        padding: 0.75rem 2rem;
        font-weight: 600;
    }
    
    .sidebar .sidebar-content {
        background: linear-gradient(180deg, #667eea 0%, #764ba2 100%);
    }
</style>
""", unsafe_allow_html=True)

def load_lottie_url(url: str):
    """Load Lottie animation from URL"""
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

def load_sample_data():
    """Generate sample vulnerability data"""
    return [
        {
            "description": "SQL Injection vulnerability in user authentication module. Attackers can bypass authentication by injecting malicious SQL code into login forms, potentially gaining unauthorized access to sensitive data and system resources.",
            "cvss_base": 8.2,
            "cvss_temporal": 7.8,
            "cvss_overall_score": 8.0,
            "severity": "high",
            "solution": "Implement parameterized queries and input validation. Use prepared statements for all database interactions. Sanitize all user inputs and implement proper access controls with the principle of least privilege."
        },
        {
            "description": "Cross-Site Scripting (XSS) vulnerability detected in user profile pages. Malicious scripts can be executed in the context of other users' browsers, leading to session hijacking, cookie theft, and unauthorized actions.",
            "cvss_base": 6.1,
            "cvss_temporal": 5.8,
            "cvss_overall_score": 5.9,
            "severity": "medium",
            "solution": "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize all user-generated content before rendering in the browser."
        },
        {
            "description": "Critical buffer overflow vulnerability in network service daemon. Remote attackers can execute arbitrary code by sending specially crafted packets, potentially leading to complete system compromise.",
            "cvss_base": 9.8,
            "cvss_temporal": 9.5,
            "cvss_overall_score": 9.7,
            "severity": "critical",
            "solution": "Apply the latest security patches immediately. Implement bounds checking for all buffer operations. Consider using memory-safe programming languages or libraries for critical components."
        },
        {
            "description": "Weak password policy detected. Current policy allows passwords with insufficient complexity, making accounts vulnerable to brute force and dictionary attacks.",
            "cvss_base": 3.1,
            "cvss_temporal": 2.8,
            "cvss_overall_score": 3.0,
            "severity": "low",
            "solution": "Enforce strong password requirements including minimum length, complexity, and regular password changes. Implement account lockout mechanisms and consider multi-factor authentication."
        },
        {
            "description": "Information disclosure through debug endpoints. Sensitive system information including configuration details and internal paths are exposed through publicly accessible debug URLs.",
            "cvss_base": 4.3,
            "cvss_temporal": 4.0,
            "cvss_overall_score": 4.1,
            "severity": "info",
            "solution": "Disable debug endpoints in production environments. Implement proper access controls for administrative interfaces. Review and minimize information exposure in error messages."
        },
        {
            "description": "Insecure direct object reference vulnerability allows unauthorized access to user data by manipulating URL parameters.",
            "cvss_base": 7.5,
            "cvss_temporal": 7.2,
            "cvss_overall_score": 7.3,
            "severity": "high",
            "solution": "Implement proper access controls and authorization checks. Use indirect object references and validate user permissions for each request."
        },
        {
            "description": "Missing security headers detected. Application lacks important security headers like HSTS, X-Frame-Options, and CSP.",
            "cvss_base": 2.6,
            "cvss_temporal": 2.4,
            "cvss_overall_score": 2.5,
            "severity": "low",
            "solution": "Implement comprehensive security headers including HSTS, X-Frame-Options, X-Content-Type-Options, and Content Security Policy."
        }
    ]

def load_vulnerability_data():
    """Load vulnerability data from JSON file or return sample data"""
    try:
        file_path = "output/solutions/enriched_vulnerabilities.json"
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                return json.load(f)
        else:
            st.info("📁 JSON file not found. Using sample data for demonstration.")
            return load_sample_data()
    except Exception as e:
        st.warning(f"⚠️ Error loading data: {e}. Using sample data.")
        return load_sample_data()

def create_severity_chart(df):
    """Create a donut chart for vulnerability severity distribution"""
    severity_counts = df['severity'].value_counts()
    
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c', 
        'medium': '#ca8a04',
        'low': '#16a34a',
        'info': '#2563eb'
    }
    
    fig = go.Figure(data=[go.Pie(
        labels=severity_counts.index,
        values=severity_counts.values,
        hole=0.5,
        marker_colors=[colors.get(severity, '#6b7280') for severity in severity_counts.index],
        textinfo='label+percent',
        textposition='outside',
        hovertemplate='<b>%{label}</b><br>Count: %{value}<br>Percentage: %{percent}<extra></extra>'
    )])
    
    fig.update_layout(
        title="Vulnerability Distribution by Severity",
        title_x=0.5,
        font=dict(size=14),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        margin=dict(t=80, b=40, l=40, r=40),
        height=400
    )
    
    return fig

def create_cvss_comparison_chart(df):
    """Create a bar chart comparing CVSS scores"""
    fig = go.Figure()
    
    fig.add_trace(go.Bar(
        name='Base Score',
        x=df.index,
        y=df['cvss_base'],
        marker_color='#667eea',
        hovertemplate='<b>Vuln %{x}</b><br>Base Score: %{y}<extra></extra>'
    ))
    
    fig.add_trace(go.Bar(
        name='Temporal Score',
        x=df.index,
        y=df['cvss_temporal'],
        marker_color='#764ba2',
        hovertemplate='<b>Vuln %{x}</b><br>Temporal Score: %{y}<extra></extra>'
    ))
    
    fig.add_trace(go.Bar(
        name='Overall Score',
        x=df.index,
        y=df['cvss_overall_score'],
        marker_color='#f093fb',
        hovertemplate='<b>Vuln %{x}</b><br>Overall Score: %{y}<extra></extra>'
    ))
    
    fig.update_layout(
        title='CVSS Scores Comparison',
        title_x=0.5,
        xaxis_title='Vulnerability Index',
        yaxis_title='CVSS Score',
        barmode='group',
        height=400,
        font=dict(size=12),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    
    return fig

def create_timeline_chart(df):
    """Create a timeline chart showing vulnerabilities by severity over time"""
    # Simulate discovery dates for demonstration
    import numpy as np
    dates = pd.date_range(start='2024-01-01', periods=len(df), freq='D')
    df_timeline = df.copy()
    df_timeline['discovery_date'] = dates
    
    fig = px.scatter(
        df_timeline, 
        x='discovery_date', 
        y='cvss_overall_score',
        color='severity',
        size='cvss_overall_score',
        hover_data=['cvss_base', 'cvss_temporal'],
        color_discrete_map={
            'critical': '#dc2626',
            'high': '#ea580c',
            'medium': '#ca8a04', 
            'low': '#16a34a',
            'info': '#2563eb'
        },
        title='Vulnerability Timeline'
    )
    
    fig.update_layout(
        title_x=0.5,
        height=400,
        font=dict(size=12),
        xaxis_title='Discovery Date',
        yaxis_title='CVSS Overall Score'
    )
    
    return fig

def render_vulnerability_card(vuln, index):
    """Render a vulnerability card"""
    severity_class = f"severity-{vuln['severity']}"
    
    st.markdown(f"""
    <div class="vulnerability-card {vuln['severity']}">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
            <h4 style="margin: 0; color: #1f2937;">Vulnerability #{index + 1}</h4>
            <span class="severity-badge {severity_class}">{vuln['severity'].upper()}</span>
        </div>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 1rem; margin: 1rem 0; background: rgba(103, 126, 234, 0.05); padding: 1rem; border-radius: 8px;">
            <div style="text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">{vuln['cvss_base']}</div>
                <div style="font-size: 0.8rem; color: #6b7280;">Base Score</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">{vuln['cvss_temporal']}</div>
                <div style="font-size: 0.8rem; color: #6b7280;">Temporal</div>
            </div>
            <div style="text-align: center;">
                <div style="font-size: 1.5rem; font-weight: bold; color: #667eea;">{vuln['cvss_overall_score']}</div>
                <div style="font-size: 0.8rem; color: #6b7280;">Overall</div>
            </div>
        </div>
        
        <div style="margin-bottom: 1rem;">
            <strong style="color: #374151;">Description:</strong><br>
            <span style="color: #6b7280; line-height: 1.6;">{vuln['description']}</span>
        </div>
        
        <div style="background: rgba(22, 163, 74, 0.05); border: 1px solid rgba(22, 163, 74, 0.2); border-radius: 8px; padding: 1rem;">
            <h5 style="color: #16a34a; margin: 0 0 0.5rem 0;">💡 Solution</h5>
            <p style="color: #374151; margin: 0; line-height: 1.5;">{vuln['solution']}</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1 style="margin: 0; font-size: 2.5rem;">🛡️ CyberOrg</h1>
        <p style="margin: 0.5rem 0 0 0; font-size: 1.2rem; opacity: 0.9;">Enterprise Vulnerability Management Dashboard</p>
        <p style="margin: 0.25rem 0 0 0; opacity: 0.8;">Securing your digital infrastructure with advanced threat analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.markdown("## 🔧 Dashboard Controls")
        
        # Load Lottie animation for sidebar
        lottie_security = load_lottie_url("https://assets2.lottiefiles.com/packages/lf20_28wvp8cg.json")
        if lottie_security:
            st_lottie(lottie_security, height=150, key="security")
        
        st.markdown("---")
        
        # Scan button
        if st.button("🔍 Start Vulnerability Scan", key="scan_btn"):
            # Show loading animation
            lottie_loading = load_lottie_url("https://assets4.lottiefiles.com/packages/lf20_szlej6bz.json")
            if lottie_loading:
                with st.spinner("Scanning vulnerabilities..."):
                    st_lottie(lottie_loading, height=100, key="loading")
                    time.sleep(2)  # Simulate scan time
            
            st.session_state['scan_complete'] = True
            st.rerun()
        
        st.markdown("---")
        
        # Filter controls
        st.markdown("### 🎛️ Filters")
        severity_filter = st.multiselect(
            "Filter by Severity",
            options=['critical', 'high', 'medium', 'low', 'info'],
            default=['critical', 'high', 'medium', 'low', 'info']
        )
        
        score_range = st.slider(
            "CVSS Score Range",
            min_value=0.0,
            max_value=10.0,
            value=(0.0, 10.0),
            step=0.1
        )
        
        st.markdown("---")
        st.markdown("### 📊 Dashboard Info")
        st.info("This dashboard provides real-time vulnerability analysis and risk assessment for your infrastructure.")
        
        # Display current time
        st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Main content
    if st.session_state.get('scan_complete', False):
        # Load vulnerability data
        vulnerabilities = load_vulnerability_data()
        df = pd.DataFrame(vulnerabilities)
        
        # Apply filters
        filtered_df = df[
            (df['severity'].isin(severity_filter)) &
            (df['cvss_overall_score'] >= score_range[0]) &
            (df['cvss_overall_score'] <= score_range[1])
        ]
        
        # Statistics section
        st.markdown("## 📊 Security Overview")
        
        col1, col2, col3, col4, col5, col6 = st.columns(6)
        
        with col1:
            total_vulns = len(filtered_df)
            st.metric("Total Vulnerabilities", total_vulns, delta=None)
        
        with col2:
            critical_count = len(filtered_df[filtered_df['severity'] == 'critical'])
            st.metric("Critical", critical_count, delta=None)
        
        with col3:
            high_count = len(filtered_df[filtered_df['severity'] == 'high'])
            st.metric("High", high_count, delta=None)
        
        with col4:
            medium_count = len(filtered_df[filtered_df['severity'] == 'medium'])
            st.metric("Medium", medium_count, delta=None)
        
        with col5:
            low_count = len(filtered_df[filtered_df['severity'] == 'low'])
            st.metric("Low", low_count, delta=None)
        
        with col6:
            info_count = len(filtered_df[filtered_df['severity'] == 'info'])
            st.metric("Info", info_count, delta=None)
        
        # Charts section
        st.markdown("## 📈 Analytics Dashboard")
        
        if len(filtered_df) > 0:
            col1, col2 = st.columns(2)
            
            with col1:
                severity_chart = create_severity_chart(filtered_df)
                st.plotly_chart(severity_chart, use_container_width=True)
            
            with col2:
                cvss_chart = create_cvss_comparison_chart(filtered_df)
                st.plotly_chart(cvss_chart, use_container_width=True)
            
            # Timeline chart
            timeline_chart = create_timeline_chart(filtered_df)
            st.plotly_chart(timeline_chart, use_container_width=True)
            
            # Vulnerability details
            st.markdown("## 🔍 Vulnerability Details")
            
            if len(filtered_df) > 0:
                for index, vuln in filtered_df.iterrows():
                    render_vulnerability_card(vuln.to_dict(), index)
            else:
                st.info("No vulnerabilities match the selected filters.")
        else:
            st.warning("No vulnerabilities found matching the current filters.")
            
            # Show some motivational animation
            lottie_empty = load_lottie_url("https://assets6.lottiefiles.com/packages/lf20_UJNc2t.json")
            if lottie_empty:
                st_lottie(lottie_empty, height=200, key="empty")
    
    else:
        # Welcome screen
        col1, col2, col3 = st.columns([1, 2, 1])
        
        with col2:
            st.markdown("## Welcome to CyberOrg")
            st.markdown("### Your Enterprise Security Command Center")
            
            # Load welcome animation
            lottie_welcome = load_lottie_url("https://assets1.lottiefiles.com/packages/lf20_V9t630.json")
            if lottie_welcome:
                st_lottie(lottie_welcome, height=300, key="welcome")
            
            st.markdown("""
            <div style="text-align: center; padding: 2rem; background: rgba(255,255,255,0.05); border-radius: 10px; margin: 2rem 0;">
                <h4>🚀 Ready to secure your infrastructure?</h4>
                <p>Click the "Start Vulnerability Scan" button in the sidebar to begin your security assessment.</p>
                <p>Our advanced scanning engine will analyze your systems and provide detailed vulnerability reports with actionable solutions.</p>
            </div>
            """, unsafe_allow_html=True)
            
            # Feature highlights
            st.markdown("### ✨ Key Features")
            
            feat_col1, feat_col2, feat_col3 = st.columns(3)
            
            with feat_col1:
                st.markdown("""
                **🔍 Advanced Scanning**
                - CVSS scoring system
                - Real-time analysis
                - Comprehensive reporting
                """)
            
            with feat_col2:
                st.markdown("""
                **📊 Visual Analytics**
                - Interactive dashboards
                - Trend analysis
                - Risk visualization
                """)
            
            with feat_col3:
                st.markdown("""
                **🛡️ Enterprise Ready**
                - Scalable architecture
                - Custom reporting
                - Integration ready
                """)

if __name__ == "__main__":
    # Initialize session state
    if 'scan_complete' not in st.session_state:
        st.session_state['scan_complete'] = False
    
    main()