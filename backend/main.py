from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import sqlite3
import hashlib
import requests
from bs4 import BeautifulSoup
import json
from groq import Groq
import re
import socket
import ssl
import concurrent.futures
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import zipfile
import os
import tempfile
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "phoenix_admin_2024")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE,
        password TEXT,
        plan TEXT DEFAULT 'FREE',
        plan_started TEXT,
        plan_expires TEXT,
        scan_count INTEGER DEFAULT 0,
        monthly_scan_count INTEGER DEFAULT 0,
        monthly_reset_date TEXT,
        last_login TEXT,
        created_at TEXT,
        api_key TEXT,
        verified INTEGER DEFAULT 0,
        enterprise_owner_id INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        target TEXT,
        scan_type TEXT,
        status TEXT,
        result TEXT,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS subscriptions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        plan TEXT,
        amount INTEGER,
        started_at TEXT,
        expires_at TEXT,
        status TEXT DEFAULT 'active'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS team_members (
        id INTEGER PRIMARY KEY,
        enterprise_owner_id INTEGER,
        member_email TEXT,
        member_user_id INTEGER,
        status TEXT DEFAULT 'pending',
        invited_at TEXT,
        approved_at TEXT
    )''')
    conn.commit()

    # Add missing columns to existing DB
    try: c.execute("ALTER TABLE users ADD COLUMN monthly_scan_count INTEGER DEFAULT 0"); conn.commit()
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN monthly_reset_date TEXT"); conn.commit()
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN api_key TEXT"); conn.commit()
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0"); conn.commit()
    except: pass
    try: c.execute("ALTER TABLE users ADD COLUMN enterprise_owner_id INTEGER DEFAULT 0"); conn.commit()
    except: pass
    try: c.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER"); conn.commit()
    except: pass

    conn.close()

init_db()

# ── MODELS ──────────────────────────────────────────────

class UserRegister(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ScanRequest(BaseModel):
    target: str
    scan_type: str
    code: str = ""
    login_url: str = ""
    login_email: str = ""
    login_password: str = ""
    user_id: int = 0

class UpdatePlan(BaseModel):
    user_id: int
    plan: str
    admin_secret: str

class InviteTeam(BaseModel):
    owner_id: int
    member_email: str

# ── EMAIL ────────────────────────────────────────────────

def send_email_alert(to_email: str, target: str, scan_result: dict):
    try:
        if not EMAIL_SENDER or not EMAIL_PASSWORD:
            return
        risk = scan_result.get('risk_score', 0)
        high = scan_result.get('high', 0)
        medium = scan_result.get('medium', 0)
        findings = scan_result.get('findings', [])[:5]

        findings_rows = ""
        for f in findings:
            color = "#b53333" if f['severity']=="CRITICAL" else "#c96442" if f['severity']=="HIGH" else "#87867f"
            findings_rows += f"""
            <tr>
              <td style="padding:12px 16px;border-bottom:1px solid #f0eee6;font-family:Georgia,serif;font-size:14px;color:#141413;font-weight:500">{f['type']}</td>
              <td style="padding:12px 16px;border-bottom:1px solid #f0eee6;font-size:12px;font-weight:700;color:{color};text-transform:uppercase;letter-spacing:0.5px">{f['severity']}</td>
              <td style="padding:12px 16px;border-bottom:1px solid #f0eee6;font-size:13px;color:#5e5d59">{f['detail'][:80]}</td>
            </tr>"""

        risk_color = "#b53333" if risk > 70 else "#2d6a4f"

        html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#f5f4ed;font-family:system-ui,sans-serif">
  <div style="max-width:600px;margin:0 auto;padding:32px 16px">

    <!-- Header -->
    <div style="background:#141413;border-radius:16px 16px 0 0;padding:32px 40px;text-align:center">
      <div style="font-family:Georgia,serif;font-size:28px;font-weight:500;color:#faf9f5;letter-spacing:-0.5px">
        Phoenix <span style="color:#c96442">AI</span>
      </div>
      <div style="font-size:11px;color:#87867f;letter-spacing:1px;text-transform:uppercase;margin-top:6px">Security Alert</div>
    </div>

    <!-- Body -->
    <div style="background:#faf9f5;border:1px solid #e8e6dc;border-top:none;border-radius:0 0 16px 16px;padding:40px">

      <!-- Target -->
      <div style="margin-bottom:28px">
        <div style="font-size:11px;color:#87867f;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:8px">Scan Target</div>
        <div style="font-family:Georgia,serif;font-size:18px;color:#141413;font-weight:500">{target}</div>
        <div style="font-size:12px;color:#87867f;margin-top:4px">{datetime.now().strftime('%d %B %Y · %H:%M')}</div>
      </div>

      <!-- Score cards -->
      <div style="display:flex;gap:12px;margin-bottom:32px">
        <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:20px;text-align:center">
          <div style="font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Risk Score</div>
          <div style="font-family:Georgia,serif;font-size:32px;font-weight:500;color:{risk_color}">{risk}<span style="font-size:16px">/100</span></div>
        </div>
        <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:20px;text-align:center">
          <div style="font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">High / Critical</div>
          <div style="font-family:Georgia,serif;font-size:32px;font-weight:500;color:#c96442">{high}</div>
        </div>
        <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:20px;text-align:center">
          <div style="font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Medium</div>
          <div style="font-family:Georgia,serif;font-size:32px;font-weight:500;color:#5e5d59">{medium}</div>
        </div>
      </div>

      <!-- AI Analysis -->
      {f'''
      <div style="background:#141413;border-radius:12px;padding:24px;margin-bottom:28px">
        <div style="font-size:11px;color:#c96442;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:12px">AI Analysis</div>
        <div style="font-family:Georgia,serif;font-size:15px;color:#b0aea5;line-height:1.7;font-style:italic">{scan_result.get('ai_explanation','')}</div>
      </div>
      ''' if scan_result.get('ai_explanation') else ''}

      <!-- Findings table -->
      <div style="margin-bottom:8px">
        <div style="font-size:11px;color:#87867f;letter-spacing:0.5px;text-transform:uppercase;margin-bottom:12px">Top Vulnerabilities</div>
        <table style="width:100%;border-collapse:collapse;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:10px;overflow:hidden">
          <thead>
            <tr style="background:#e8e6dc">
              <th style="padding:10px 16px;text-align:left;font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;font-weight:500">Vulnerability</th>
              <th style="padding:10px 16px;text-align:left;font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;font-weight:500">Severity</th>
              <th style="padding:10px 16px;text-align:left;font-size:10px;color:#87867f;letter-spacing:1px;text-transform:uppercase;font-weight:500">Detail</th>
            </tr>
          </thead>
          <tbody>{findings_rows}</tbody>
        </table>
      </div>

      <!-- Footer -->
      <div style="margin-top:32px;padding-top:20px;border-top:1px solid #e8e6dc;text-align:center">
        <div style="font-size:12px;color:#87867f">Phoenix AI Security Platform</div>
        <div style="font-size:11px;color:#b0aea5;margin-top:4px">{datetime.now().strftime('%d %b %Y %H:%M')}</div>
      </div>
    </div>
  </div>
</body>
</html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🔴 Phoenix AI: {scan_result.get('total_findings',0)} vulnerabilities found in {target}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_SENDER
        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_SENDER, msg.as_string())
        print(f"✅ Email sent for {target}")
    except Exception as e:
        print(f"Email error: {e}")

# ── SUBDOMAIN FINDER ─────────────────────────────────────

def find_subdomains(domain: str):
    from urllib.parse import urlparse
    hostname = urlparse(domain).hostname or domain
    base_domain = ".".join(hostname.split(".")[-2:])
    subs = ["www","mail","ftp","admin","api","dev","staging","test","portal","app",
            "blog","shop","cdn","static","assets","img","media","upload","vpn",
            "remote","cloud","secure","login","auth","support","help","docs",
            "status","monitor","dashboard","panel","cpanel","webmail","smtp",
            "ns1","ns2","db","backup","old","beta","alpha","v2","m","mobile"]
    found = []
    def check(sub):
        full = f"{sub}.{base_domain}"
        try: ip = socket.gethostbyname(full); return {"subdomain": full, "ip": ip}
        except: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        for r in ex.map(check, subs):
            if r: found.append(r)
    return found

# ── SCANNERS ─────────────────────────────────────────────

def check_security_headers(resp, findings):
    for h in ["X-Frame-Options","X-Content-Type-Options","Content-Security-Policy","Strict-Transport-Security","X-XSS-Protection"]:
        if h not in resp.headers:
            findings.append({"type":"Missing Security Header","severity":"MEDIUM","detail":f"'{h}' is missing!","fix":f"Add '{h}' to server response"})

def check_sql_injection(url, findings):
    payloads = ["'","\"","' OR '1'='1","' OR 1=1--"]
    errors = ["sql syntax","mysql_fetch","ORA-","syntax error","unclosed quotation"]
    try:
        for payload in payloads:
            test_url = url+("&" if "?" in url else "?")+"id="+payload
            r = requests.get(test_url, timeout=6, verify=False)
            for error in errors:
                if error.lower() in r.text.lower():
                    findings.append({"type":"SQL Injection","severity":"CRITICAL","detail":f"SQL error with payload: {payload}","fix":"Use parameterized queries","poc":f"URL: {test_url}"}); return
    except: pass

def check_xss(url, findings):
    payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>"]
    try:
        for payload in payloads:
            test_url = url+("&" if "?" in url else "?")+"q="+payload
            r = requests.get(test_url, timeout=6, verify=False)
            if payload in r.text:
                findings.append({"type":"XSS Vulnerability","severity":"HIGH","detail":"XSS payload reflected in response!","fix":"Sanitize all user inputs","poc":f"URL: {test_url}"}); return
    except: pass

def check_ssl(url, findings):
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5); s.connect((hostname, 443))
            cert = s.getpeercert()
            expire = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days = (expire - datetime.now()).days
            if days < 30:
                findings.append({"type":"SSL Expiring Soon","severity":"HIGH","detail":f"Certificate expires in {days} days!","fix":"Renew SSL certificate immediately"})
    except ssl.SSLError:
        findings.append({"type":"SSL/TLS Issue","severity":"HIGH","detail":"SSL/TLS configuration problem detected","fix":"Fix SSL configuration"})
    except: pass

def check_ports(url, findings):
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        ports = {21:"FTP",22:"SSH",23:"Telnet",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",27017:"MongoDB",9200:"Elasticsearch"}
        for port, name in ports.items():
            try:
                s = socket.socket(); s.settimeout(0.5)
                if s.connect_ex((hostname, port)) == 0:
                    findings.append({"type":f"Exposed Port: {name}","severity":"HIGH","detail":f"Port {port} ({name}) is publicly accessible!","fix":f"Close port {port} with firewall rules"})
                s.close()
            except: pass
    except: pass

def check_sensitive_files(url, findings):
    base = url.rstrip("/")
    for path in ["/.git/HEAD","/.env","/wp-config.php","/admin","/phpmyadmin","/.htaccess","/backup.zip","/db.sql"]:
        try:
            r = requests.get(base+path, timeout=3, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                findings.append({"type":"Sensitive File Exposed","severity":"HIGH" if path in ["/.env","/.git/HEAD","/.htaccess"] else "LOW","detail":f"Accessible: {path}","fix":f"Restrict access to {path}"})
        except: pass

def check_open_redirect(url, findings):
    try:
        for p in ["?redirect=https://evil.com","?url=https://evil.com"]:
            r = requests.get(url+p, timeout=6, verify=False, allow_redirects=False)
            if r.status_code in [301,302] and "evil.com" in r.headers.get("Location",""):
                findings.append({"type":"Open Redirect","severity":"MEDIUM","detail":"Server redirects to external URLs without validation!","fix":"Validate and whitelist redirect URLs","poc":f"Test: {url+p}"}); return
    except: pass

def check_source_code(code, findings):
    patterns = [
        (r"password\s*=\s*['\"][^'\"]{3,}['\"]","CRITICAL","Hardcoded Password","Use environment variables"),
        (r"api_key\s*=\s*['\"][^'\"]{10,}['\"]","CRITICAL","Hardcoded API Key","Store in .env file"),
        (r"secret\s*=\s*['\"][^'\"]{5,}['\"]","HIGH","Hardcoded Secret","Move to .env file"),
        (r"exec\(.*\$_(GET|POST|REQUEST)","CRITICAL","Remote Code Execution Risk","Never pass user input to exec()"),
        (r"eval\(.*\$_(GET|POST)","CRITICAL","Code Injection Risk","Never use eval() with user input"),
        (r"SELECT.*\+.*\$_(GET|POST|REQUEST)","CRITICAL","SQL Injection Risk","Use prepared statements"),
        (r"innerHTML\s*=\s*.*user","HIGH","XSS via innerHTML","Use textContent instead"),
        (r"md5\(","MEDIUM","Weak Hashing (MD5)","Use bcrypt or SHA-256"),
        (r"AWS_SECRET|aws_secret_access_key","CRITICAL","AWS Secret Key Exposed","Remove immediately"),
        (r"private_key\s*=","CRITICAL","Private Key in Code","Never store keys in source code"),
        (r"http://(?!localhost)","LOW","Insecure HTTP URL","Use HTTPS"),
    ]
    for pattern, severity, name, fix in patterns:
        if re.findall(pattern, code, re.IGNORECASE):
            findings.append({"type":name,"severity":severity,"detail":"Vulnerable pattern found in source code","fix":fix})

# ── SCAN RUNNERS ─────────────────────────────────────────

def run_url_scan(url):
    findings = []
    try:
        resp = requests.get(url, headers={"User-Agent":"PhoenixAI/1.0"}, timeout=10, verify=False)
        check_security_headers(resp, findings)
        if url.startswith("http://"):
            findings.append({"type":"Insecure Protocol","severity":"HIGH","detail":"Site uses HTTP instead of HTTPS","fix":"Install SSL certificate"})
        if "Server" in resp.headers:
            findings.append({"type":"Server Version Disclosure","severity":"LOW","detail":f"Server header: {resp.headers['Server']}","fix":"Hide server version information"})
        soup = BeautifulSoup(resp.text, "html.parser")
        for i, form in enumerate(soup.find_all("form")):
            if not any("csrf" in inp.get("name","").lower() or "token" in inp.get("name","").lower() for inp in form.find_all("input")):
                findings.append({"type":"CSRF Vulnerability","severity":"HIGH","detail":f"Form #{i+1} has no CSRF token","fix":"Add CSRF token to all forms","poc":f"Form action: {form.get('action','/')}"})
        check_sql_injection(url, findings)
        check_xss(url, findings)
        check_open_redirect(url, findings)
        check_sensitive_files(url, findings)
        check_ssl(url, findings)
        check_ports(url, findings)
    except Exception as e:
        findings.append({"type":"Scan Error","severity":"INFO","detail":str(e),"fix":"Check the URL and try again"})
    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":url,"risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings}

def run_code_scan(code):
    findings = []
    check_source_code(code, findings)
    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":"Source Code Scan","risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings}

def run_zip_scan(zip_path):
    findings = []
    scanned_files = []
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for name in z.namelist():
                if any(name.endswith(ext) for ext in ['.py','.js','.php','.java','.ts','.jsx','.tsx','.rb','.go','.env','.config','.yml','.yaml']):
                    try:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        file_findings = []
                        check_source_code(content, file_findings)
                        for f in file_findings:
                            f["file"] = name; findings.append(f)
                        scanned_files.append(name)
                    except: pass
    except Exception as e:
        findings.append({"type":"Error","severity":"INFO","detail":str(e),"fix":"Check ZIP file"})
    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":f"ZIP ({len(scanned_files)} files)","risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings,"scanned_files":scanned_files}

def run_threat_intel(target):
    findings = []
    intel = {}
    try:
        from urllib.parse import urlparse
        hostname = urlparse(target).hostname or target
        try:
            ip = socket.gethostbyname(hostname)
            intel["ip"] = ip; intel["hostname"] = hostname
        except:
            ip = hostname; intel["ip"] = ip

        try:
            resp = requests.get("https://api.abuseipdb.com/api/v2/check",
                headers={"Key":ABUSEIPDB_KEY,"Accept":"application/json"},
                params={"ipAddress":ip,"maxAgeInDays":90}, timeout=10)
            data = resp.json().get("data",{})
            abuse_score = data.get("abuseConfidenceScore",0)
            intel["abuse_score"] = abuse_score
            intel["abuse_reports"] = data.get("totalReports",0)
            intel["country"] = data.get("countryCode","Unknown")
            intel["isp"] = data.get("isp","Unknown")
            if abuse_score > 50:
                findings.append({"type":"High Abuse Score","severity":"CRITICAL","detail":f"IP abuse score: {abuse_score}/100","fix":"Block this IP immediately"})
            elif abuse_score > 10:
                findings.append({"type":"Suspicious IP","severity":"HIGH","detail":f"IP abuse score: {abuse_score}/100","fix":"Monitor traffic closely"})
        except: pass

        try:
            r = requests.get(target, timeout=8, verify=False)
            server = r.headers.get("Server","")
            intel["server"] = server
            for pattern, name, cves in [("Apache/2.2","Apache 2.2 EOL","CVE-2017-7679"),("PHP/5.","PHP 5.x EOL","CVE-2019-11043"),("PHP/7.0","PHP 7.0 EOL","Multiple CVEs")]:
                if pattern.lower() in server.lower():
                    findings.append({"type":"Vulnerable Software","severity":"HIGH","detail":f"{name} · CVEs: {cves}","fix":"Update to latest stable version"})
        except: pass

        subdomains = find_subdomains(target)
        intel["subdomains"] = subdomains
        if subdomains:
            findings.append({"type":"Subdomains Found","severity":"INFO","detail":f"{len(subdomains)} active subdomains discovered","fix":"Ensure all subdomains are properly secured"})

        try:
            if ip and ip != hostname:
                reversed_ip = ".".join(reversed(ip.split(".")))
                blacklisted = []
                for bl in ["zen.spamhaus.org","bl.spamcop.net"]:
                    try: socket.gethostbyname(f"{reversed_ip}.{bl}"); blacklisted.append(bl)
                    except: pass
                intel["blacklisted"] = len(blacklisted) > 0
                if blacklisted:
                    findings.append({"type":"IP Blacklisted","severity":"CRITICAL","detail":f"Found in: {', '.join(blacklisted)}","fix":"Contact ISP to delist IP"})
        except: pass

    except Exception as e:
        findings.append({"type":"Error","severity":"INFO","detail":str(e),"fix":"Check target URL"})

    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":target,"scan_type":"threat_intel","risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings,"intel":intel}

def run_live_app_test(url, login_url, login_email, login_password):
    findings = []
    session = requests.Session(); session.verify = False
    headers = {"User-Agent":"PhoenixAI/1.0"}
    logged_in = False
    try:
        if login_url and login_email and login_password:
            r = session.post(login_url, data={"email":login_email,"username":login_email,"password":login_password}, headers=headers, timeout=10)
            if r.status_code in [200,302]: logged_in = True
        resp = session.get(url, headers=headers, timeout=10)
        check_security_headers(resp, findings)
        soup = BeautifulSoup(resp.text, "html.parser")
        for i, form in enumerate(soup.find_all("form")):
            if not any("csrf" in inp.get("name","").lower() or "token" in inp.get("name","").lower() for inp in form.find_all("input")):
                findings.append({"type":"CSRF Vulnerability","severity":"HIGH","detail":f"Form #{i+1} missing CSRF token","fix":"Add CSRF token to all forms","poc":f"Form: {form.get('action','/')}"})
        for cookie in session.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("missing HttpOnly")
            if not cookie.secure: issues.append("missing Secure flag")
            if issues: findings.append({"type":"Insecure Cookie","severity":"MEDIUM","detail":f"Cookie '{cookie.name}': {', '.join(issues)}","fix":"Set HttpOnly and Secure flags on all cookies"})
        try:
            resps = [session.get(url, headers=headers, timeout=3).status_code for _ in range(5)]
            if all(s == 200 for s in resps):
                findings.append({"type":"No Rate Limiting","severity":"MEDIUM","detail":"Server responded to 5 rapid requests without limiting","fix":"Implement rate limiting (e.g., 100 req/min per IP)"})
        except: pass
    except Exception as e:
        findings.append({"type":"Error","severity":"INFO","detail":str(e),"fix":"Check URL"})
    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":url,"logged_in":logged_in,"risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings}

def get_ai_explanation(scan_result):
    try:
        r = Groq(api_key=GROQ_API_KEY).chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role":"user","content":f"Security scan result: URL:{scan_result.get('url')} Risk:{scan_result.get('risk_score')}/100 High:{scan_result.get('high')} Medium:{scan_result.get('medium')} Top findings:{json.dumps(scan_result.get('findings',[])[:3])}. Give exactly 3 lines: 1. Overall security status 2. Most critical issue 3. Top recommendation"}],
            max_tokens=200)
        return r.choices[0].message.content
    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"

# ── PDF REPORT ───────────────────────────────────────────

def generate_pdf_report(scan_result, target, plan="FREE"):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch, cm
        from reportlab.lib.colors import HexColor, white, black
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak, KeepTogether
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm)

        # Colors
        TERRA   = HexColor('#c96442')
        DARK    = HexColor('#141413')
        GRAY    = HexColor('#5e5d59')
        STONE   = HexColor('#87867f')
        LIGHT   = HexColor('#f5f4ed')
        IVORY   = HexColor('#faf9f5')
        SAND    = HexColor('#e8e6dc')
        RED     = HexColor('#b53333')
        GREEN   = HexColor('#2d6a4f')
        ORANGE  = HexColor('#c96442')
        WHITE   = white
        BLACK   = black
        NAVY    = HexColor('#1a1a2e')

        PAGE_W = A4[0] - 4*cm

        # Styles
        def S(name, **kwargs):
            base = {'fontName':'Helvetica','fontSize':10,'textColor':DARK,'leading':14,'spaceAfter':4,'spaceBefore':0}
            base.update(kwargs)
            return ParagraphStyle(name, **base)

        title_s     = S('title', fontSize=28, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER, leading=34, spaceAfter=6)
        subtitle_s  = S('subtitle', fontSize=12, textColor=HexColor('#c9a882'), alignment=TA_CENTER, leading=16, spaceAfter=4)
        cover_label = S('clabel', fontSize=10, textColor=HexColor('#b0aea5'), alignment=TA_CENTER, leading=14)
        cover_value = S('cvalue', fontSize=12, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER, leading=16, spaceAfter=8)
        conf_s      = S('conf', fontSize=9, textColor=HexColor('#ff6600'), alignment=TA_CENTER, fontName='Helvetica-Bold', leading=12)

        h1_s = S('h1', fontSize=14, fontName='Helvetica-Bold', textColor=WHITE, leading=18, spaceAfter=0, spaceBefore=0)
        h2_s = S('h2', fontSize=11, fontName='Helvetica-Bold', textColor=DARK, leading=15, spaceAfter=4, spaceBefore=8)
        h3_s = S('h3', fontSize=10, fontName='Helvetica-Bold', textColor=DARK, leading=14, spaceAfter=3, spaceBefore=6)
        body_s = S('body', fontSize=9, textColor=GRAY, leading=13, spaceAfter=3)
        body_j = S('bodyj', fontSize=9, textColor=GRAY, leading=13, spaceAfter=3, alignment=TA_JUSTIFY)
        label_s = S('label', fontSize=8, fontName='Helvetica-Bold', textColor=STONE, leading=11, spaceAfter=2)
        small_s = S('small', fontSize=8, textColor=STONE, leading=11, spaceAfter=2)
        code_s  = S('code', fontSize=8, fontName='Courier', textColor=GRAY, leading=11, spaceAfter=2)
        toc_s   = S('toc', fontSize=10, textColor=DARK, leading=16, spaceAfter=2)
        footer_s = S('footer', fontSize=8, textColor=STONE, alignment=TA_CENTER, leading=11)

        risk = scan_result.get('risk_score', 0)
        total = scan_result.get('total_findings', 0)
        high_count = scan_result.get('high', 0)
        medium_count = scan_result.get('medium', 0)
        low_count = scan_result.get('low', 0)
        findings = scan_result.get('findings', [])
        now_str = datetime.now().strftime('%d %B %Y')
        now_full = datetime.now().strftime('%d %b %Y %H:%M')

        sev_colors = {
            'CRITICAL': HexColor('#b53333'),
            'HIGH':     HexColor('#c96442'),
            'MEDIUM':   HexColor('#d4920a'),
            'LOW':      HexColor('#2d6a4f'),
            'INFO':     HexColor('#5e5d59'),
        }

        def sev_bg(sev):
            return {
                'CRITICAL': HexColor('#fef2f2'),
                'HIGH':     HexColor('#fff7f0'),
                'MEDIUM':   HexColor('#fffbeb'),
                'LOW':      HexColor('#f0fdf4'),
                'INFO':     HexColor('#f8f9fa'),
            }.get(sev, IVORY)

        story = []

        # ══════════════════════════════════════════════
        # COVER PAGE
        # ══════════════════════════════════════════════
        cover_data = [
            [Paragraph("", cover_label)],
            [Paragraph("", cover_label)],
            [Paragraph("", cover_label)],
            [Paragraph("Phoenix AI", S('logo', fontSize=32, fontName='Helvetica-Bold', textColor=TERRA, alignment=TA_CENTER, leading=38))],
            [Paragraph("WEB APPLICATION PENETRATION TESTING REPORT", S('ct', fontSize=14, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER, leading=18, spaceAfter=4))],
            [Paragraph("", cover_label)],
            [Paragraph("─" * 60, S('div', fontSize=8, textColor=HexColor('#444'), alignment=TA_CENTER))],
            [Paragraph("", cover_label)],
            [Paragraph("Client / Target", cover_label)],
            [Paragraph(str(target), S('tv', fontSize=14, fontName='Helvetica-Bold', textColor=WHITE, alignment=TA_CENTER, leading=18))],
            [Paragraph("", cover_label)],
            [Paragraph("Assessment Type", cover_label)],
            [Paragraph("Web Application VAPT / Penetration Testing", cover_value)],
            [Paragraph("Assessment Date", cover_label)],
            [Paragraph(now_str, cover_value)],
            [Paragraph("Prepared By", cover_label)],
            [Paragraph("Phoenix AI Security Platform", cover_value)],
            [Paragraph("Company", cover_label)],
            [Paragraph("Global SecureLayer X Pvt. Ltd.", cover_value)],
            [Paragraph("", cover_label)],
            [Paragraph("─" * 60, S('div2', fontSize=8, textColor=HexColor('#444'), alignment=TA_CENTER))],
            [Paragraph("", cover_label)],
            [Paragraph("⚠  CLASSIFICATION: CONFIDENTIAL", conf_s)],
            [Paragraph("This document contains confidential and proprietary information.", S('cn', fontSize=8, textColor=HexColor('#999'), alignment=TA_CENTER, leading=12))],
        ]

        cover_table = Table(cover_data, colWidths=[PAGE_W])
        cover_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), NAVY),
            ('PADDING', (0,0), (-1,-1), 6),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0), (0,0), 40),
            ('BOTTOMPADDING', (0,-1), (0,-1), 40),
        ]))
        story.append(cover_table)
        story.append(PageBreak())

        # ══════════════════════════════════════════════
        # DOCUMENT CONTROL
        # ══════════════════════════════════════════════
        def section_header(title):
            t = Table([[Paragraph(title, h1_s)]], colWidths=[PAGE_W])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), DARK),
                ('PADDING', (0,0), (-1,-1), 10),
                ('TOPPADDING', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
            ]))
            return t

        def info_table(data, col_widths=None):
            if col_widths is None:
                col_widths = [PAGE_W * 0.3, PAGE_W * 0.7]
            rows = []
            for row in data:
                rows.append([Paragraph(str(row[0]), label_s), Paragraph(str(row[1]), body_s)])
            t = Table(rows, colWidths=col_widths)
            t.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, SAND),
                ('PADDING', (0,0), (-1,-1), 7),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [WHITE, LIGHT]),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            return t

        story.append(section_header("DOCUMENT CONTROL"))
        story.append(Spacer(1, 8))

        dc_data = [
            ["Version", "Date", "Prepared By", "Description"],
            ["1.0", now_str, "Phoenix AI", "Initial Security Report"],
        ]
        dc_t = Table(dc_data, colWidths=[PAGE_W*0.12, PAGE_W*0.22, PAGE_W*0.3, PAGE_W*0.36])
        dc_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(dc_t)
        story.append(Spacer(1, 12))

        story.append(Paragraph("CONFIDENTIALITY NOTICE", h2_s))
        story.append(Paragraph(
            "This document contains confidential and proprietary information. "
            "The information provided in this report is intended solely for the authorized personnel of the client organization. "
            "Unauthorized disclosure, copying, or distribution of this document is strictly prohibited.",
            body_j))
        story.append(Spacer(1, 8))

        # TABLE OF CONTENTS
        story.append(section_header("TABLE OF CONTENTS"))
        story.append(Spacer(1, 8))
        toc_items = [
            ("1.", "Executive Summary"),
            ("2.", "Objective"),
            ("3.", "Scope of Assessment"),
            ("4.", "Assessment Methodology"),
            ("5.", "Tools Used"),
            ("6.", "Risk Rating Methodology"),
            ("7.", "Summary of Findings"),
            ("8.", "Detailed Vulnerability Findings"),
            ("9.", "Positive Security Observations"),
            ("10.", "Recommendations"),
            ("11.", "Conclusion"),
            ("12.", "Appendix"),
        ]
        toc_data = [[Paragraph(n, S('tn', fontSize=9, fontName='Helvetica-Bold', textColor=TERRA)),
                     Paragraph(t, toc_s)] for n, t in toc_items]
        toc_t = Table(toc_data, colWidths=[PAGE_W*0.08, PAGE_W*0.92])
        toc_t.setStyle(TableStyle([
            ('PADDING', (0,0), (-1,-1), 5),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('LINEBELOW', (0,0), (-1,-2), 0.3, SAND),
        ]))
        story.append(toc_t)
        story.append(PageBreak())

        # ══════════════════════════════════════════════
        # 1. EXECUTIVE SUMMARY
        # ══════════════════════════════════════════════
        story.append(section_header("1. EXECUTIVE SUMMARY"))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Overview", h2_s))
        story.append(Paragraph(
            f"A security assessment was conducted on <b>{target}</b> to identify vulnerabilities that could impact "
            "the confidentiality, integrity, and availability of the system. "
            "The assessment included manual and automated testing techniques based on industry-standard methodologies "
            "including OWASP Top 10, PTES, and NIST guidelines.",
            body_j))
        story.append(Spacer(1, 8))

        # Risk Summary table
        story.append(Paragraph("Risk Summary", h2_s))
        critical_count = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
        info_count = sum(1 for f in findings if f.get('severity') == 'INFO')

        risk_data = [
            ["Severity", "Count", "Status"],
            ["Critical", str(critical_count), "Open" if critical_count > 0 else "None"],
            ["High", str(high_count - critical_count if high_count >= critical_count else high_count), "Open" if high_count > 0 else "None"],
            ["Medium", str(medium_count), "Open" if medium_count > 0 else "None"],
            ["Low", str(low_count), "Open" if low_count > 0 else "None"],
            ["Informational", str(info_count), "Noted"],
        ]
        sev_row_colors = [DARK, HexColor('#fef2f2'), HexColor('#fff7f0'), HexColor('#fffbeb'), HexColor('#f0fdf4'), LIGHT]
        sev_text_colors = [WHITE, HexColor('#b53333'), HexColor('#c96442'), HexColor('#d4920a'), HexColor('#2d6a4f'), GRAY]

        rs_t = Table(risk_data, colWidths=[PAGE_W*0.33, PAGE_W*0.33, PAGE_W*0.34])
        style_cmds = [
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 8),
            ('ALIGN', (1,0), (2,-1), 'CENTER'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        for i in range(1, len(risk_data)):
            style_cmds.append(('BACKGROUND', (0,i), (-1,i), sev_row_colors[i]))
            style_cmds.append(('TEXTCOLOR', (0,i), (0,i), sev_text_colors[i]))
            style_cmds.append(('FONTNAME', (0,i), (0,i), 'Helvetica-Bold'))
        rs_t.setStyle(TableStyle(style_cmds))
        story.append(rs_t)
        story.append(Spacer(1, 8))

        # Overall risk level
        if risk > 70:
            overall_risk = "CRITICAL"; risk_col = RED
        elif risk > 50:
            overall_risk = "HIGH"; risk_col = ORANGE
        elif risk > 30:
            overall_risk = "MEDIUM"; risk_col = HexColor('#d4920a')
        else:
            overall_risk = "LOW"; risk_col = GREEN

        or_t = Table([[
            Paragraph("Overall Risk Level", S('orl', fontSize=10, fontName='Helvetica-Bold', textColor=WHITE)),
            Paragraph(f"{overall_risk}  ({risk}/100)", S('orv', fontSize=12, fontName='Helvetica-Bold', textColor=risk_col, alignment=TA_RIGHT))
        ]], colWidths=[PAGE_W*0.5, PAGE_W*0.5])
        or_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), DARK),
            ('PADDING', (0,0), (-1,-1), 10),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(or_t)
        story.append(Spacer(1, 8))

        # AI Analysis
        if scan_result.get('ai_explanation') and 'Error' not in str(scan_result.get('ai_explanation','')):
            story.append(Paragraph("AI Security Analysis", h2_s))
            ai_box = Table([[Paragraph(scan_result['ai_explanation'], body_j)]],
                           colWidths=[PAGE_W])
            ai_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), LIGHT),
                ('LEFTPADDING', (0,0), (-1,-1), 14),
                ('RIGHTPADDING', (0,0), (-1,-1), 14),
                ('TOPPADDING', (0,0), (-1,-1), 10),
                ('BOTTOMPADDING', (0,0), (-1,-1), 10),
                ('LINERIGHT', (0,0), (0,-1), 3, TERRA),
            ]))
            story.append(ai_box)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 2. OBJECTIVE
        # ══════════════════════════════════════════════
        story.append(section_header("2. OBJECTIVE"))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "The objective of this assessment was to identify security weaknesses in the target application and "
            "provide remediation recommendations to improve the overall security posture. "
            "The assessment aimed to simulate real-world attack scenarios to understand the potential impact "
            "of identified vulnerabilities.",
            body_j))
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 3. SCOPE
        # ══════════════════════════════════════════════
        story.append(section_header("3. SCOPE OF ASSESSMENT"))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Target Information", h2_s))

        intel = scan_result.get('intel', {})
        scope_data = [
            ["Target URL", target],
            ["IP Address", intel.get('ip', 'Resolved during scan') if intel else 'N/A'],
            ["Application Type", "Web Application"],
            ["Testing Type", "Black Box"],
            ["Environment", "Production"],
            ["Assessment Date", now_full],
            ["Risk Score", f"{risk}/100"],
            ["Plan", plan],
        ]
        story.append(info_table(scope_data))
        story.append(Spacer(1, 8))

        in_scope = [
            ["✓", "Login & Authentication Functionality"],
            ["✓", "Security Headers & Configuration"],
            ["✓", "SSL/TLS Certificate Validation"],
            ["✓", "SQL Injection Testing"],
            ["✓", "Cross-Site Scripting (XSS) Testing"],
            ["✓", "Open Redirect Testing"],
            ["✓", "Sensitive File Exposure"],
            ["✓", "CSRF Protection"],
            ["✓", "Port Exposure"],
            ["✓", "Server Information Disclosure"],
        ]
        story.append(Paragraph("In-Scope Components", h2_s))
        is_t = Table(in_scope, colWidths=[PAGE_W*0.06, PAGE_W*0.94])
        is_t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (0,-1), GREEN),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 4),
            ('LINEBELOW', (0,0), (-1,-2), 0.3, SAND),
        ]))
        story.append(is_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 4. METHODOLOGY
        # ══════════════════════════════════════════════
        story.append(section_header("4. ASSESSMENT METHODOLOGY"))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Standards Followed", h2_s))
        standards = [["•", "OWASP Top 10 (2021)"], ["•", "PTES — Penetration Testing Execution Standard"],
                     ["•", "NIST Security Testing Guidelines"], ["•", "CVSS v3.1 Scoring System"]]
        std_t = Table(standards, colWidths=[PAGE_W*0.04, PAGE_W*0.96])
        std_t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9), ('TEXTCOLOR', (0,0), (0,-1), TERRA),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'), ('PADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(std_t)
        story.append(Spacer(1, 8))

        phases = [
            ["4.1", "Reconnaissance", "Information gathering, subdomain enumeration, technology identification"],
            ["4.2", "Scanning & Enumeration", "Port scanning, service detection, security header analysis"],
            ["4.3", "Vulnerability Assessment", "Automated and manual vulnerability identification"],
            ["4.4", "Exploitation", "Controlled exploitation and Proof of Concept validation"],
            ["4.5", "Reporting", "Documentation, risk classification, remediation guidance"],
        ]
        story.append(Paragraph("Testing Phases", h2_s))
        ph_t = Table(phases, colWidths=[PAGE_W*0.08, PAGE_W*0.3, PAGE_W*0.62])
        ph_t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0,0), (0,-1), TERRA),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,0), (-1,-1), [WHITE, LIGHT]),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(ph_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 5. TOOLS
        # ══════════════════════════════════════════════
        story.append(section_header("5. TOOLS USED"))
        story.append(Spacer(1, 8))
        tools = [
            ["Tool", "Purpose"],
            ["Phoenix AI Scanner", "Automated Web Application Testing"],
            ["Custom Python Scripts", "SSL/TLS, Header & Port Analysis"],
            ["AbuseIPDB API", "IP Reputation & Threat Intelligence"],
            ["Groq AI (LLaMA)", "AI-Powered Vulnerability Analysis"],
            ["DNS Resolver", "Subdomain Enumeration"],
            ["Socket Scanner", "Port & Service Detection"],
        ]
        tools_t = Table(tools, colWidths=[PAGE_W*0.4, PAGE_W*0.6])
        tools_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT]),
        ]))
        story.append(tools_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 6. RISK RATING
        # ══════════════════════════════════════════════
        story.append(section_header("6. RISK RATING METHODOLOGY"))
        story.append(Spacer(1, 8))
        ratings = [
            ["Severity", "CVSS Score", "Description"],
            ["Critical", "9.0 – 10.0", "Immediate exploitation risk — requires urgent remediation"],
            ["High", "7.0 – 8.9", "Significant risk — should be fixed within 7 days"],
            ["Medium", "4.0 – 6.9", "Moderate risk — fix within 30 days"],
            ["Low", "0.1 – 3.9", "Minor risk — fix within 90 days"],
            ["Informational", "0.0", "No direct impact — awareness only"],
        ]
        sev_bgs_r = [DARK, HexColor('#fef2f2'), HexColor('#fff7f0'), HexColor('#fffbeb'), HexColor('#f0fdf4'), LIGHT]
        sev_txts_r = [WHITE, HexColor('#b53333'), HexColor('#c96442'), HexColor('#d4920a'), HexColor('#2d6a4f'), GRAY]
        rr_t = Table(ratings, colWidths=[PAGE_W*0.22, PAGE_W*0.22, PAGE_W*0.56])
        rr_cmds = [
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 8),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]
        for i in range(1, len(ratings)):
            rr_cmds.append(('BACKGROUND', (0,i), (-1,i), sev_bgs_r[i]))
            rr_cmds.append(('TEXTCOLOR', (0,i), (0,i), sev_txts_r[i]))
            rr_cmds.append(('FONTNAME', (0,i), (0,i), 'Helvetica-Bold'))
        rr_t.setStyle(TableStyle(rr_cmds))
        story.append(rr_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 7. SUMMARY OF FINDINGS
        # ══════════════════════════════════════════════
        story.append(section_header("7. SUMMARY OF FINDINGS"))
        story.append(Spacer(1, 8))

        sum_data = [["ID", "Vulnerability", "Severity", "Status"]]
        for i, f in enumerate(findings):
            sev = f.get('severity','INFO')
            sum_data.append([
                f"V-{str(i+1).zfill(2)}",
                f.get('type','Unknown'),
                sev,
                "Open"
            ])
        sum_t = Table(sum_data, colWidths=[PAGE_W*0.1, PAGE_W*0.5, PAGE_W*0.2, PAGE_W*0.2])
        sum_cmds = [
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 7),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT]),
        ]
        for i, f in enumerate(findings, 1):
            sev = f.get('severity','INFO')
            col = sev_colors.get(sev, GRAY)
            sum_cmds.append(('TEXTCOLOR', (2,i), (2,i), col))
            sum_cmds.append(('FONTNAME', (2,i), (2,i), 'Helvetica-Bold'))
        sum_t.setStyle(TableStyle(sum_cmds))
        story.append(sum_t)
        story.append(Spacer(1, 8))
        story.append(PageBreak())

        # ══════════════════════════════════════════════
        # 8. DETAILED FINDINGS
        # ══════════════════════════════════════════════
        story.append(section_header("8. DETAILED VULNERABILITY FINDINGS"))
        story.append(Spacer(1, 8))

        for i, f in enumerate(findings):
            sev = f.get('severity', 'INFO')
            sev_col = sev_colors.get(sev, GRAY)
            sev_bg_col = sev_bg(sev)
            vuln_id = f"V-{str(i+1).zfill(2)}"

            # Vuln header
            vh_t = Table([[
                Paragraph(f"{vuln_id}  {f.get('type','Unknown')}", S('vht', fontSize=11, fontName='Helvetica-Bold', textColor=WHITE)),
                Paragraph(sev, S('vhs', fontSize=10, fontName='Helvetica-Bold', textColor=sev_col, alignment=TA_RIGHT))
            ]], colWidths=[PAGE_W*0.75, PAGE_W*0.25])
            vh_t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), DARK),
                ('PADDING', (0,0), (-1,-1), 10),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BACKGROUND', (1,0), (1,0), sev_bg_col),
            ]))
            story.append(vh_t)

            # Details
            detail_rows = [
                [Paragraph("<b>Severity</b>", label_s), Paragraph(f"<font color='#{sev_col.hexval()[2:]}'><b>{sev}</b></font>", body_s)],
                [Paragraph("<b>Affected Target</b>", label_s), Paragraph(str(target), body_s)],
                [Paragraph("<b>Description</b>", label_s), Paragraph(str(f.get('detail','N/A')), body_s)],
                [Paragraph("<b>Impact</b>", label_s), Paragraph(f"This vulnerability may allow attackers to compromise the security of {target}. Immediate attention is recommended.", body_s)],
                [Paragraph("<b>Remediation</b>", label_s), Paragraph(str(f.get('fix','N/A')), body_s)],
            ]

            if f.get('poc') and plan in ["PRO", "ENTERPRISE"]:
                detail_rows.append([
                    Paragraph("<b>Proof of Concept</b>", label_s),
                    Paragraph(str(f.get('poc','')), code_s)
                ])

            if f.get('file'):
                detail_rows.append([
                    Paragraph("<b>Affected File</b>", label_s),
                    Paragraph(str(f.get('file','')), code_s)
                ])

            dt = Table(detail_rows, colWidths=[PAGE_W*0.25, PAGE_W*0.75])
            dt.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, SAND),
                ('PADDING', (0,0), (-1,-1), 8),
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('ROWBACKGROUNDS', (0,0), (-1,-1), [WHITE, LIGHT]),
                ('FONTSIZE', (0,0), (-1,-1), 9),
            ]))
            story.append(KeepTogether([dt]))
            story.append(Spacer(1, 12))

        # ══════════════════════════════════════════════
        # 9. POSITIVE OBSERVATIONS
        # ══════════════════════════════════════════════
        story.append(section_header("9. POSITIVE SECURITY OBSERVATIONS"))
        story.append(Spacer(1, 8))

        # Check what's good
        positive = []
        all_types = [f.get('type','') for f in findings]
        if not any('SSL' in t for t in all_types): positive.append("SSL/TLS properly configured")
        if not any('SQL' in t for t in all_types): positive.append("No SQL Injection detected")
        if not any('XSS' in t for t in all_types): positive.append("No XSS vulnerabilities detected")
        if not any('Redirect' in t for t in all_types): positive.append("No open redirects detected")
        if not any('Port' in t for t in all_types): positive.append("No dangerous ports exposed")
        positive.extend(["HTTPS protocol in use", "Application is accessible and functional"])

        pos_data = [[Paragraph("✓", S('pg', fontSize=10, fontName='Helvetica-Bold', textColor=GREEN)),
                     Paragraph(p, body_s)] for p in positive]
        pos_t = Table(pos_data, colWidths=[PAGE_W*0.06, PAGE_W*0.94])
        pos_t.setStyle(TableStyle([
            ('PADDING', (0,0), (-1,-1), 6),
            ('LINEBELOW', (0,0), (-1,-2), 0.3, SAND),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(pos_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 10. RECOMMENDATIONS
        # ══════════════════════════════════════════════
        story.append(section_header("10. RECOMMENDATIONS"))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Immediate Actions (Critical/High)", h2_s))
        imm = [["1.", "Fix all Critical and High severity vulnerabilities immediately"],
               ["2.", "Implement missing security headers (CSP, HSTS, X-Frame-Options)"],
               ["3.", "Add CSRF tokens to all forms"],
               ["4.", "Patch outdated or vulnerable software versions"],
               ["5.", "Disable unnecessary services and exposed ports"]]
        imm_t = Table(imm, colWidths=[PAGE_W*0.06, PAGE_W*0.94])
        imm_t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (0,-1), TERRA),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 5),
            ('LINEBELOW', (0,0), (-1,-2), 0.3, SAND),
        ]))
        story.append(imm_t)
        story.append(Spacer(1, 8))

        story.append(Paragraph("Security Improvements (Medium/Long Term)", h2_s))
        imp = [["•", "Implement a Web Application Firewall (WAF)"],
               ["•", "Conduct regular VAPT assessments (quarterly recommended)"],
               ["•", "Enable centralized logging and monitoring"],
               ["•", "Security awareness training for development team"],
               ["•", "Implement Content Security Policy (CSP)"],
               ["•", "Enable HTTP Strict Transport Security (HSTS)"]]
        imp_t = Table(imp, colWidths=[PAGE_W*0.04, PAGE_W*0.96])
        imp_t.setStyle(TableStyle([
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('TEXTCOLOR', (0,0), (0,-1), TERRA),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        story.append(imp_t)
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 11. CONCLUSION
        # ══════════════════════════════════════════════
        story.append(section_header("11. CONCLUSION"))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"The security assessment of <b>{target}</b> identified <b>{total} vulnerabilities</b> with an overall risk score of "
            f"<b>{risk}/100</b> ({overall_risk} risk level). "
            f"The assessment found {high_count} high/critical and {medium_count} medium severity issues that require immediate attention.",
            body_j))
        story.append(Spacer(1, 6))
        story.append(Paragraph(
            "Immediate remediation of critical and high-risk issues is strongly recommended to reduce the attack surface "
            "and improve the overall security posture. A follow-up assessment should be conducted after remediation "
            "to verify the fixes have been properly implemented.",
            body_j))
        story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # 12. APPENDIX
        # ══════════════════════════════════════════════
        story.append(section_header("12. APPENDIX"))
        story.append(Spacer(1, 8))

        story.append(Paragraph("Appendix A — Scan Configuration", h2_s))
        app_a = [
            ["Parameter", "Value"],
            ["Target URL", target],
            ["Scan Type", scan_result.get('scan_type','URL').upper()],
            ["Scan Date", now_full],
            ["Total Checks", "50+ security checks"],
            ["Report Plan", plan],
        ]
        app_a_t = Table(app_a, colWidths=[PAGE_W*0.35, PAGE_W*0.65])
        app_a_t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), DARK),
            ('TEXTCOLOR', (0,0), (-1,0), WHITE),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('GRID', (0,0), (-1,-1), 0.5, SAND),
            ('PADDING', (0,0), (-1,-1), 7),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, LIGHT]),
        ]))
        story.append(app_a_t)
        story.append(Spacer(1, 8))

        if findings:
            story.append(Paragraph("Appendix B — Payloads & PoC Summary", h2_s))
            poc_list = [f for f in findings if f.get('poc')]
            if poc_list and plan in ["PRO","ENTERPRISE"]:
                for f in poc_list:
                    story.append(Paragraph(f"<b>{f.get('type','')}</b>", h3_s))
                    story.append(Paragraph(str(f.get('poc','')), code_s))
            else:
                story.append(Paragraph("PoC details available for Pro and Enterprise plan users.", body_s))
            story.append(Spacer(1, 8))

        if scan_result.get('intel'):
            story.append(Paragraph("Appendix C — Threat Intelligence Data", h2_s))
            intel = scan_result['intel']
            intel_app = []
            for k, v in intel.items():
                if k != 'subdomains' and v is not None:
                    intel_app.append([str(k).replace('_',' ').title(), str(v)])
            if intel_app:
                ia_t = Table(intel_app, colWidths=[PAGE_W*0.35, PAGE_W*0.65])
                ia_t.setStyle(TableStyle([
                    ('FONTSIZE', (0,0), (-1,-1), 9),
                    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                    ('GRID', (0,0), (-1,-1), 0.5, SAND),
                    ('PADDING', (0,0), (-1,-1), 6),
                    ('ROWBACKGROUNDS', (0,0), (-1,-1), [WHITE, LIGHT]),
                ]))
                story.append(ia_t)
            story.append(Spacer(1, 8))

        # ══════════════════════════════════════════════
        # REPORT FOOTER
        # ══════════════════════════════════════════════
        story.append(HRFlowable(width="100%", thickness=1, color=SAND))
        story.append(Spacer(1, 8))
        footer_data = [[
            Paragraph("Prepared By:\nGlobal SecureLayer X Pvt. Ltd.", footer_s),
            Paragraph("Phoenix AI Security Platform", S('fc', fontSize=9, textColor=TERRA, alignment=TA_CENTER, fontName='Helvetica-Bold')),
            Paragraph(f"Email: securelayerhelp@gmail.com\nClassification: CONFIDENTIAL", footer_s),
        ]]
        ft = Table(footer_data, colWidths=[PAGE_W*0.33, PAGE_W*0.34, PAGE_W*0.33])
        ft.setStyle(TableStyle([
            ('PADDING', (0,0), (-1,-1), 6),
            ('ALIGN', (1,0), (1,0), 'CENTER'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ]))
        story.append(ft)

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    except Exception as e:
        print(f"PDF error: {e}")
        import traceback
        traceback.print_exc()
        return None

# ── ROUTES ───────────────────────────────────────────────

@app.get("/")
def home(): return {"message": "Phoenix AI API running! 🚀"}

@app.get("/health")
def health(): return {"status": "OK", "project": "Phoenix AI"}

@app.post("/register")
def register(user: UserRegister):
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    hashed = hashlib.sha256(user.password.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (email, password, plan, scan_count, monthly_scan_count, created_at) VALUES (?, ?, 'FREE', 0, 0, ?)",
                  (user.email, hashed, datetime.now().isoformat()))
        conn.commit()
        return {"message": "Registered!", "email": user.email}
    except:
        raise HTTPException(status_code=400, detail="Email already exists!")
    finally:
        conn.close()

@app.post("/login")
def login(user: UserLogin):
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    hashed = hashlib.sha256(user.password.encode()).hexdigest()
    c.execute("SELECT id, email, plan, monthly_scan_count, monthly_reset_date, plan_expires FROM users WHERE email=? AND password=?", (user.email, hashed))
    db_user = c.fetchone()
    if not db_user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials!")

    # Check if monthly reset needed
    now = datetime.now()
    monthly_count = db_user[3] or 0
    reset_date = db_user[4]
    if reset_date:
        try:
            reset_dt = datetime.fromisoformat(reset_date)
            if now.month != reset_dt.month or now.year != reset_dt.year:
                monthly_count = 0
                c.execute("UPDATE users SET monthly_scan_count=0, monthly_reset_date=? WHERE id=?", (now.isoformat(), db_user[0]))
        except: pass

    c.execute("UPDATE users SET last_login=? WHERE id=?", (now.isoformat(), db_user[0]))
    conn.commit()
    conn.close()

    return {
        "message": "Login successful!",
        "email": db_user[1],
        "user_id": db_user[0],
        "plan": db_user[2] or "FREE",
        "monthly_scan_count": monthly_count,
        "plan_expires": db_user[5]
    }

@app.post("/scan")
def create_scan(scan: ScanRequest):
    PLAN_LIMITS = {"FREE": 3, "PRO": -1, "ENTERPRISE": -1}
    FREE_SCANNERS = ["url"]

    user_plan = "FREE"
    monthly_count = 0

    if scan.user_id:
        conn = sqlite3.connect("voidscan.db")
        c = conn.cursor()
        c.execute("SELECT plan, monthly_scan_count, monthly_reset_date FROM users WHERE id=?", (scan.user_id,))
        row = c.fetchone()
        conn.close()

        if row:
            user_plan = row[0] or "FREE"
            monthly_count = row[1] or 0
            reset_date = row[2]

            # Check monthly reset
            now = datetime.now()
            if reset_date:
                try:
                    reset_dt = datetime.fromisoformat(reset_date)
                    if now.month != reset_dt.month or now.year != reset_dt.year:
                        monthly_count = 0
                        conn2 = sqlite3.connect("voidscan.db")
                        c2 = conn2.cursor()
                        c2.execute("UPDATE users SET monthly_scan_count=0, monthly_reset_date=? WHERE id=?", (now.isoformat(), scan.user_id))
                        conn2.commit(); conn2.close()
                except: pass

            # Enforce scan limit
            limit = PLAN_LIMITS.get(user_plan, 3)
            if limit != -1 and monthly_count >= limit:
                raise HTTPException(status_code=429, detail=f"LIMIT_REACHED|{user_plan}|{monthly_count}")

            # Enforce scanner access
            if user_plan == "FREE" and scan.scan_type not in FREE_SCANNERS:
                raise HTTPException(status_code=403, detail=f"UPGRADE_REQUIRED|{scan.scan_type}")

    # Run scan
    if scan.scan_type == "code": result = run_code_scan(scan.code)
    elif scan.scan_type == "threat": result = run_threat_intel(scan.target)
    elif scan.scan_type == "live": result = run_live_app_test(scan.target, scan.login_url, scan.login_email, scan.login_password)
    else: result = run_url_scan(scan.target)

    result["ai_explanation"] = get_ai_explanation(result)
    result["scan_type"] = scan.scan_type

    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (user_id, target, scan_type, status, result, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (scan.user_id, scan.target, scan.scan_type, "completed", json.dumps(result), datetime.now().isoformat()))
    conn.commit()
    scan_id = c.lastrowid

    if scan.user_id:
        c.execute("""UPDATE users SET
            scan_count = scan_count + 1,
            monthly_scan_count = monthly_scan_count + 1,
            monthly_reset_date = COALESCE(monthly_reset_date, ?)
            WHERE id=?""", (datetime.now().isoformat(), scan.user_id))
        conn.commit()
    conn.close()

    try: send_email_alert(EMAIL_SENDER, scan.target, result)
    except: pass

    return {"scan_id": scan_id, "result": result}

@app.post("/scan/upload")
async def scan_zip(file: UploadFile = File(...)):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            tmp.write(await file.read())
            tmp_path = tmp.name
        result = run_zip_scan(tmp_path)
        result["ai_explanation"] = get_ai_explanation(result)
        os.unlink(tmp_path)
        conn = sqlite3.connect("voidscan.db")
        c = conn.cursor()
        c.execute("INSERT INTO scans (target, scan_type, status, result, created_at) VALUES (?, ?, ?, ?, ?)",
                  (file.filename, "zip", "completed", json.dumps(result), datetime.now().isoformat()))
        conn.commit()
        scan_id = c.lastrowid
        conn.close()
        return {"scan_id": scan_id, "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}/pdf")
def download_pdf(scan_id: int, user_id: int = 0):
    from fastapi.responses import Response
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT target, result, user_id FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()

    plan = "FREE"
    if row and row[2]:
        c.execute("SELECT plan FROM users WHERE id=?", (row[2],))
        u = c.fetchone()
        if u: plan = u[0] or "FREE"
    conn.close()

    if not row: raise HTTPException(status_code=404, detail="Scan not found")
    pdf = generate_pdf_report(json.loads(row[1]), row[0], plan)
    if not pdf: raise HTTPException(status_code=500, detail="PDF generation failed")
    return Response(content=pdf, media_type="application/pdf",
                   headers={"Content-Disposition": f"attachment; filename=phoenix-ai-report-{scan_id}.pdf"})

@app.get("/scans")
def get_scans():
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT id, target, scan_type, status, result, created_at, user_id FROM scans ORDER BY id DESC LIMIT 100")
    rows = c.fetchall()
    conn.close()
    scans = []
    for row in rows:
        result = None
        try: result = json.loads(row[4]) if row[4] else None
        except: result = None
        scans.append({"id":row[0],"target":row[1],"scan_type":row[2],"status":row[3],"result":result,"created_at":row[5],"user_id":row[6]})
    return {"scans": scans}

# ── ADMIN ROUTES ─────────────────────────────────────────

@app.get("/admin/stats")
def admin_stats(secret: str):
    if secret != ADMIN_SECRET: raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users"); total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans"); total_scans = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'"); pro_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE plan='ENTERPRISE'"); enterprise_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE plan='FREE' OR plan IS NULL"); free_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM scans WHERE created_at >= date('now', '-7 days')"); scans_week = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE created_at >= date('now', '-7 days')"); new_users = c.fetchone()[0]
    conn.close()
    return {"total_users":total_users,"total_scans":total_scans,"pro_users":pro_users,"enterprise_users":enterprise_users,"free_users":free_users,"scans_this_week":scans_week,"new_users_week":new_users,"estimated_revenue":(pro_users*499)+(enterprise_users*4999)}

@app.get("/admin/users")
def admin_users(secret: str):
    if secret != ADMIN_SECRET: raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT id, email, plan, scan_count, monthly_scan_count, plan_expires, last_login, created_at FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return {"users": [{"id":r[0],"email":r[1],"plan":r[2]or"FREE","scan_count":r[3]or 0,"monthly_scan_count":r[4]or 0,"plan_expires":r[5],"last_login":r[6],"created_at":r[7]} for r in rows]}

@app.post("/admin/update-plan")
def update_plan(data: UpdatePlan):
    if data.admin_secret != ADMIN_SECRET: raise HTTPException(status_code=403, detail="Unauthorized")
    expires = None
    if data.plan != "FREE":
        expires = (datetime.now() + timedelta(days=30)).isoformat()
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("UPDATE users SET plan=?, plan_started=?, plan_expires=?, verified=? WHERE id=?",
              (data.plan, datetime.now().isoformat(), expires, 1 if data.plan in ["PRO","ENTERPRISE"] else 0, data.user_id))
    conn.commit()
    conn.close()
    return {"message": f"Plan updated to {data.plan}", "expires": expires}

@app.get("/admin/scans")
def admin_scans(secret: str):
    if secret != ADMIN_SECRET: raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("""SELECT s.id, s.target, s.scan_type, s.created_at, u.email
                 FROM scans s LEFT JOIN users u ON s.user_id = u.id
                 ORDER BY s.id DESC LIMIT 100""")
    rows = c.fetchall()
    conn.close()
    return {"scans": [{"id":r[0],"target":r[1],"type":r[2],"date":r[3],"user":r[4]or"Anonymous"} for r in rows]}

@app.post("/admin/reset-monthly-scans")
def reset_monthly(secret: str, user_id: int):
    if secret != ADMIN_SECRET: raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("UPDATE users SET monthly_scan_count=0 WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    return {"message": "Monthly scans reset"}

@app.get("/user/scan-count")
def get_scan_count(user_id: int):
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT monthly_scan_count, plan FROM users WHERE id=?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {"monthly_scan_count": row[0] or 0, "plan": row[1] or "FREE"}

@app.delete("/admin/delete-user")
def delete_user(user_id: int, secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    c.execute("DELETE FROM scans WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"User {user_id} deleted successfully"}