import streamlit as st
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="CyberGuard | Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ADVANCED HACKER UI STYLING (CSS) ---
st.markdown("""
    <style>
    /* Main Background & Text */
    .stApp {
        background-color: #0E1117;
        color: #00FF41;
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Input Field Styling */
    .stTextInput>div>div>input {
        background-color: #161B22;
        color: #00FF41;
        border: 1px solid #00FF41;
        border-radius: 5px;
    }
    
    /* Button Styling */
    .stButton>button {
        background-color: #00FF41;
        color: black;
        font-weight: bold;
        border: none;
        border-radius: 5px;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background-color: #00CC33;
        box-shadow: 0 0 10px #00FF41;
    }
    
    /* Metrics Box */
    div[data-testid="stMetricValue"] {
        color: #FF4B4B;
        font-size: 3rem;
    }
    
    /* Custom Card for Results */
    .vuln-card {
        padding: 15px;
        border-left: 5px solid #FF4B4B;
        background-color: #262730;
        margin-bottom: 10px;
        border-radius: 5px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- LOGIC FUNCTIONS (No Changes Here) ---
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"

def get_all_forms(url):
    try:
        content = s.get(url).content
    except: return None
    soup = bs(content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try: action = form.attrs.get("action").lower()
    except: action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable_to_sqli(response):
    errors = {"you have an error in your sql syntax;", "warning: mysql", "unclosed quotation mark after the character string", "quoted string not properly terminated"}
    for error in errors:
        if error in response.content.decode().lower(): return True
    return False

def scan_sql_injection(url):
    forms = get_all_forms(url)
    if not forms: return False, []
    vulnerable_links = []
    is_vulnerable = False
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                input_val = input_tag.get("value", "")
                input_name = input_tag.get("name")
                if input_tag["type"] == "hidden" or input_val:
                    try: data[input_name] = input_val + c
                    except: pass
                elif input_tag["type"] != "submit":
                    data[input_name] = f"test{c}"
            action_url = form_details["action"]
            if action_url: url_target = urljoin(url, action_url)
            else: url_target = url
            try:
                if form_details["method"] == "post": res = s.post(url_target, data=data)
                else: res = s.get(url_target, params=data)
                if is_vulnerable_to_sqli(res):
                    vulnerable_links.append(url_target)
                    is_vulnerable = True
                    break
            except: pass
    return is_vulnerable, vulnerable_links

def scan_xss(url):
    forms = get_all_forms(url)
    if not forms: return False, []
    vulnerable_links = []
    is_vulnerable = False
    xss_payload = "<script>alert('XSS')</script>"
    for form in forms:
        form_details = get_form_details(form)
        data = {}
        for input_tag in form_details["inputs"]:
            if input_tag["type"] == "text" or input_tag["type"] == "search":
                input_name = input_tag.get("name")
                if input_name: data[input_name] = xss_payload
        action_url = form_details["action"]
        if action_url: url_target = urljoin(url, action_url)
        else: url_target = url
        try:
            if form_details["method"] == "post": res = s.post(url_target, data=data)
            else: res = s.get(url_target, params=data)
            if xss_payload in res.content.decode():
                vulnerable_links.append(url_target)
                is_vulnerable = True
        except: pass
    return is_vulnerable, vulnerable_links

# --- GUI LAYOUT ---

# Sidebar
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/2092/2092663.png", width=100)
    st.title("CyberGuard")
    st.caption("Automated Web Penetration Tool")
    st.markdown("---")
    st.info("💡 **Tip:** Use `http://testphp.vulnweb.com` for testing.")
    st.markdown("---")
    st.write("Developed by: **[Your Name Here]**")
    st.write("Project: **MCA Final Year**")

# Main Content
st.title("💀 Web Vulnerability Analyser")
st.markdown("### 🔍 Target Reconnaissance & Vulnerability Assessment")

# --- SEARCH FORM (This enables Enter Key) ---
with st.form(key='search_form'):
    col1, col2 = st.columns([3, 1])
    
    with col1:
        target_url = st.text_input("Target URL:", placeholder="http://testphp.vulnweb.com", label_visibility="collapsed")
    
    with col2:
        # Form Submit Button (Triggers on Enter)
        submit_button = st.form_submit_button(label='🚀 Initialize Scan')

# --- SCANNING LOGIC ---
if submit_button:
    if not target_url:
        st.warning("⚠️ Please input a valid URL target.")
    else:
        # Simulating Hacker Console Effect
        with st.status("🔄 Initializing Cyber Scan Protocol...", expanded=True) as status:
            st.write("⚡ Establishing connection with target...")
            time.sleep(1)
            
            st.write("🕵️‍♂️ Crawling DOM elements...")
            sqli_detected, sqli_links = scan_sql_injection(target_url)
            
            st.write("💉 Injecting SQL Payloads...")
            time.sleep(0.5)
            
            st.write("🦠 Testing Cross-Site Scripting (XSS)...")
            xss_detected, xss_links = scan_xss(target_url)
            
            status.update(label="✅ Scan Complete", state="complete", expanded=False)
        
        # --- REPORT SECTION ---
        st.markdown("---")
        st.subheader("📊 Security Analysis Report")
        
        security_score = 100
        
        col_res1, col_res2 = st.columns(2)
        
        # SQLi Card
        with col_res1:
            if sqli_detected:
                security_score -= 50
                st.markdown("""
                <div class="vuln-card">
                    <h3 style="color:#FF4B4B;">❌ SQL Injection Detected</h3>
                    <p>Target Database is exposed.</p>
                </div>
                """, unsafe_allow_html=True)
                with st.expander("View Vulnerable Endpoints"):
                    for link in sqli_links:
                        st.code(link, language="http")
            else:
                st.success("✅ Database Secure (No SQLi)")

        # XSS Card
        with col_res2:
            if xss_detected:
                security_score -= 30
                st.markdown("""
                <div class="vuln-card">
                    <h3 style="color:#FFA500;">⚠️ XSS Vulnerability Detected</h3>
                    <p>Client-side script execution possible.</p>
                </div>
                """, unsafe_allow_html=True)
                with st.expander("View Payloads"):
                    for link in xss_links:
                        st.code(f"{link}\nPayload: <script>alert('XSS')</script>", language="http")
            else:
                st.success("✅ Client-Side Secure (No XSS)")

        st.markdown("---")
        
        # --- FINAL SCORE ---
        col_metric1, col_metric2 = st.columns([1, 2])
        
        with col_metric1:
            st.metric(label="Security Integrity Score", value=f"{security_score}%", delta="-CRITICAL RISK" if security_score < 50 else "SECURE")
            
        with col_metric2:
            if security_score == 100:
                st.info("### 🛡️ Security Level: HIGH (SECURE)")
            elif security_score >= 50:
                st.warning("### ⚠️ Security Level: MEDIUM (RISK)")
            else:
                st.error("### ☠️ Security Level: LOW (CRITICAL)")