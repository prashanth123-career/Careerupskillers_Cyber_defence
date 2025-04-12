import streamlit as st
import pandas as pd
import numpy as np
import re
import whois
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import socket
from datetime import datetime, timedelta
import plotly.express as px
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import nltk
from nltk.tokenize import word_tokenize
nltk.download('punkt')

# Set page config
st.set_page_config(
    page_title="CyberSecurity Tool Suite",
    page_icon="🛡️",
    layout="wide"
)

# --- Phishing Detection Component ---
class PhishingDetector:
    def __init__(self):
        # Initialize with a simple model (in production, load a trained model)
        self.model = RandomForestClassifier()
        self.vectorizer = TfidfVectorizer()
        # Simple training for demo (replace with your trained model)
        self._train_demo_model()
    
    def _train_demo_model(self):
        # This is just for demo - replace with your actual trained model
        X_train = ["https://legit.com", "https://phishing-scam.com/login", 
                  "http://bank-update.com", "https://real-site.org"]
        y_train = [0, 1, 1, 0]
        X_vec = self.vectorizer.fit_transform(X_train)
        self.model.fit(X_vec, y_train)
    
    def extract_features(self, url):
        features = {}
        
        # URL-based features
        features['length'] = len(url)
        features['has_at'] = 1 if '@' in url else 0
        features['has_hyphen'] = 1 if '-' in urlparse(url).netloc else 0
        features['num_subdomains'] = urlparse(url).netloc.count('.')
        features['is_https'] = 1 if urlparse(url).scheme == 'https' else 0
        
        # Domain age (simplified for demo)
        try:
            domain = whois.whois(urlparse(url).netloc)
            features['domain_age'] = 1 if domain.creation_date and (
                datetime.now() - domain.creation_date[0]).days > 365 else 0
        except:
            features['domain_age'] = 0
            
        # Content-based features (simplified)
        suspicious_words = ['login', 'bank', 'update', 'secure', 'account']
        features['suspicious_words'] = sum(1 for word in suspicious_words if word in url.lower())
        
        return features
    
    def predict(self, url):
        features = self.extract_features(url)
        # Convert features to vector (simplified for demo)
        feature_str = " ".join(f"{k}_{v}" for k, v in features.items())
        X = self.vectorizer.transform([feature_str])
        proba = self.model.predict_proba(X)[0][1]  # Probability of being phishing
        return proba

# --- Vulnerability Scanner Component ---
class VulnerabilityScanner:
    def __init__(self):
        self.common_vulnerabilities = {
            'SQLi': r"('|\"|--|;|UNION|SELECT|DROP|INSERT)",
            'XSS': r"(<script|alert\(|onerror|onload)",
            'CMD Injection': r"(;|\||&|`|\$\(|\n)"
        }
    
    def scan_url(self, url):
        results = {}
        
        # Check for injection patterns
        results['SQL Injection'] = bool(re.search(self.common_vulnerabilities['SQLi'], url, re.IGNORECASE))
        results['XSS'] = bool(re.search(self.common_vulnerabilities['XSS'], url, re.IGNORECASE))
        
        # Check HTTP headers if URL is accessible
        try:
            response = requests.get(url, timeout=5)
            headers = response.headers
            security_headers = ['X-XSS-Protection', 'Content-Security-Policy', 'Strict-Transport-Security']
            results['Missing Headers'] = [h for h in security_headers if h not in headers]
        except:
            results['Connection'] = "Failed to connect"
        
        return results
    
    def scan_ports(self, host, ports=None):
        if ports is None:
            ports = [21, 22, 80, 443, 3306, 3389]
            
        results = {}
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                results[port] = "Open" if result == 0 else "Closed"
        return results

# --- SIEM Component ---
class SIEMCore:
    def __init__(self):
        self.logs = pd.DataFrame(columns=['timestamp', 'source', 'event_type', 'severity', 'message'])
        self.rules = [
            {'name': 'Multiple Failed Logins', 'pattern': 'Failed login', 'threshold': 3, 'window': '5m', 'severity': 'high'},
            {'name': 'SQL Injection Attempt', 'pattern': r"('|--|;|UNION|SELECT)", 'threshold': 1, 'window': '1h', 'severity': 'critical'},
            {'name': 'Port Scanning', 'pattern': 'port scan', 'threshold': 1, 'window': '1h', 'severity': 'medium'}
        ]
    
    def ingest_log(self, log):
        new_log = pd.DataFrame([{
            'timestamp': datetime.now(),
            'source': log.get('source', 'unknown'),
            'event_type': log.get('event_type', 'unknown'),
            'severity': log.get('severity', 'low'),
            'message': log.get('message', '')
        }])
        self.logs = pd.concat([self.logs, new_log], ignore_index=True)
    
    def analyze_logs(self):
        alerts = []
        now = datetime.now()
        
        for rule in self.rules:
            # Calculate time window
            if 'm' in rule['window']:
                delta = timedelta(minutes=int(rule['window'].replace('m', '')))
            else:
                delta = timedelta(hours=int(rule['window'].replace('h', '')))
            
            # Filter logs in time window
            window_logs = self.logs[self.logs['timestamp'] >= now - delta]
            
            # Count pattern matches
            matches = window_logs['message'].str.contains(rule['pattern'], regex=True, case=False)
            count = matches.sum()
            
            if count >= rule['threshold']:
                alerts.append({
                    'rule': rule['name'],
                    'count': count,
                    'severity': rule['severity'],
                    'sample': window_logs[matches]['message'].head(3).tolist()
                })
        
        return alerts
    
    def get_events(self, hours=24):
        return self.logs[self.logs['timestamp'] >= datetime.now() - timedelta(hours=hours)]

# --- Initialize Components ---
phishing_detector = PhishingDetector()
vuln_scanner = VulnerabilityScanner()
siem = SIEMCore()

# --- Streamlit UI ---
st.title("🛡️ CyberSecurity Tool Suite")
st.markdown("Phishing Detection | Vulnerability Scanning | SIEM Monitoring")

# Create tabs
tab1, tab2, tab3 = st.tabs(["Phishing Detection", "Vulnerability Scanner", "SIEM Dashboard"])

# Tab 1: Phishing Detection
with tab1:
    st.header("🔍 Phishing URL Detection")
    col1, col2 = st.columns([3, 2])
    
    with col1:
        url = st.text_input("Enter URL to analyze:", placeholder="https://example.com")
        if url:
            with st.spinner("Analyzing URL..."):
                try:
                    proba = phishing_detector.predict(url)
                    features = phishing_detector.extract_features(url)
                    
                    st.metric("Phishing Probability", f"{proba*100:.1f}%")
                    if proba > 0.7:
                        st.error("⚠️ High probability of phishing!")
                    elif proba > 0.4:
                        st.warning("⚠️ Suspicious URL detected")
                    else:
                        st.success("✅ URL appears safe")
                    
                    with st.expander("View extracted features"):
                        st.json(features)
                except Exception as e:
                    st.error(f"Error analyzing URL: {str(e)}")
    
    with col2:
        st.markdown("""
        ### About Phishing Detection
        This tool analyzes URLs for phishing indicators:
        - Suspicious domain characteristics
        - Unusual URL structure
        - Known phishing patterns
        - Domain age and reputation
        
        **How to use:**
        1. Enter a URL in the input field
        2. View the phishing probability score
        3. Check feature details for insights
        """)

# Tab 2: Vulnerability Scanner
with tab2:
    st.header("🔧 Vulnerability Scanner")
    scan_type = st.radio("Select scan type:", ["URL Scan", "Port Scan"], horizontal=True)
    
    if scan_type == "URL Scan":
        url = st.text_input("Enter target URL:", placeholder="https://example.com")
        if st.button("Scan URL") and url:
            with st.spinner("Scanning for vulnerabilities..."):
                try:
                    results = vuln_scanner.scan_url(url)
                    
                    st.subheader("Scan Results")
                    cols = st.columns(3)
                    
                    # Display vulnerability findings
                    for i, (vuln, result) in enumerate(results.items()):
                        with cols[i % 3]:
                            if isinstance(result, bool):
                                st.metric(
                                    vuln,
                                    "Detected" if result else "Not Detected",
                                    delta=None,
                                    delta_color="normal",
                                    help=f"{vuln} vulnerability detection"
                                )
                            elif isinstance(result, list):
                                st.metric(
                                    vuln,
                                    f"Missing {len(result)}" if result else "All Present",
                                    delta=None,
                                    delta_color="normal",
                                    help="Security headers check"
                                )
                                if result:
                                    st.warning(f"Missing: {', '.join(result)}")
                            else:
                                st.text(f"{vuln}: {result}")
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
    
    else:  # Port Scan
        col1, col2 = st.columns(2)
        with col1:
            host = st.text_input("Enter target host/IP:", placeholder="example.com or 192.168.1.1")
            ports = st.text_input("Custom ports (comma separated):", placeholder="80,443,22")
        
        if st.button("Scan Ports") and host:
            with st.spinner("Scanning ports..."):
                try:
                    port_list = [int(p.strip()) for p in ports.split(',')] if ports else None
                    results = vuln_scanner.scan_ports(host, port_list)
                    
                    st.subheader("Port Scan Results")
                    df = pd.DataFrame(list(results.items()), columns=['Port', 'Status'])
                    
                    # Color coding
                    def color_status(val):
                        color = 'red' if val == 'Open' else 'green'
                        return f'color: {color}'
                    
                    st.dataframe(df.style.applymap(color_status, subset=['Status']))
                    
                    # Add to SIEM logs
                    open_ports = [port for port, status in results.items() if status == 'Open']
                    if open_ports:
                        siem.ingest_log({
                            'source': 'port-scanner',
                            'event_type': 'scan',
                            'severity': 'medium',
                            'message': f"Port scan detected open ports: {', '.join(map(str, open_ports))}"
                        })
                except Exception as e:
                    st.error(f"Port scan failed: {str(e)}")

# Tab 3: SIEM Dashboard
with tab3:
    st.header("📊 SIEM Dashboard")
    
    # Add sample logs button
    if st.button("Add Sample Logs"):
        sample_logs = [
            {'source': 'web-server', 'event_type': 'auth', 'severity': 'low', 
             'message': 'User admin logged in successfully'},
            {'source': 'web-server', 'event_type': 'auth', 'severity': 'medium', 
             'message': 'Failed login attempt for user admin'},
            {'source': 'db-server', 'event_type': 'query', 'severity': 'high', 
             'message': "Suspicious query detected: SELECT * FROM users WHERE username='admin'--"},
            {'source': 'firewall', 'event_type': 'network', 'severity': 'high', 
             'message': 'Blocked connection attempt to port 22 from 1.2.3.4'},
        ]
        for log in sample_logs:
            siem.ingest_log(log)
        st.success("Added sample logs to SIEM")
    
    # Manual log entry
    with st.expander("➕ Add Custom Log Entry"):
        with st.form("log_form"):
            source = st.text_input("Source", "web-server")
            event_type = st.selectbox("Event Type", ["auth", "network", "query", "system"])
            severity = st.select_slider("Severity", ["low", "medium", "high", "critical"])
            message = st.text_area("Message", "Sample event message")
            
            if st.form_submit_button("Add Log"):
                siem.ingest_log({
                    'source': source,
                    'event_type': event_type,
                    'severity': severity,
                    'message': message
                })
                st.success("Log added successfully")
    
    # Display logs and analysis
    st.subheader("Recent Security Events")
    time_range = st.select_slider("Time range", ["1h", "24h", "7d"], value="24h")
    hours = 1 if time_range == "1h" else 24 if time_range == "24h" else 168
    
    events = siem.get_events(hours)
    if not events.empty:
        # Show events table
        st.dataframe(events.sort_values('timestamp', ascending=False))
        
        # Show charts
        col1, col2 = st.columns(2)
        with col1:
            fig1 = px.pie(events, names='severity', title='Event Severity Distribution')
            st.plotly_chart(fig1, use_container_width=True)
        
        with col2:
            fig2 = px.histogram(events, x='source', color='severity', title='Events by Source')
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No events found in selected time range")
    
    # Run correlation analysis
    if st.button("Run Correlation Analysis"):
        alerts = siem.analyze_logs()
        
        if alerts:
            st.subheader("🚨 Security Alerts")
            for alert in alerts:
                with st.expander(f"{alert['rule']} ({alert['severity'].upper()}) - Count: {alert['count']}"):
                    st.write("Sample events:")
                    for msg in alert['sample']:
                        st.write(f"- {msg}")
        else:
            st.success("No alerts detected")

# Footer
st.markdown("---")
st.markdown("""
### About This Tool
This cybersecurity suite combines:
- **Phishing Detection**: Machine learning-based URL analysis
- **Vulnerability Scanner**: Web and network vulnerability checks
- **SIEM Dashboard**: Security event monitoring and correlation

*Note: This is a demo tool. For production use, enhance with proper authentication and additional security measures.*
""")
