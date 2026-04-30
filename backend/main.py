import os
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
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

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
ADMIN_SECRET = os.getenv("ADMIN_SECRET")

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
        last_login TEXT,
        created_at TEXT
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
    conn.commit()
    conn.close()

init_db()

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

# ─── EMAIL ───────────────────────────────────────────────

def send_email_alert(to_email: str, target: str, scan_result: dict):
    try:
        if not EMAIL_SENDER or not EMAIL_PASSWORD:
            return
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🔴 Phoenix AI Alert: {scan_result.get('total_findings',0)} vulnerabilities in {target}"
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_SENDER

        risk = scan_result.get('risk_score', 0)
        high = scan_result.get('high', 0)
        medium = scan_result.get('medium', 0)
        findings = scan_result.get('findings', [])[:5]

        findings_html = ""
        for f in findings:
            color = "#b53333" if f['severity'] == "CRITICAL" else "#c96442" if f['severity'] == "HIGH" else "#87867f"
            findings_html += f"""
            <tr>
              <td style="padding:10px;border-bottom:1px solid #e8e6dc;color:#141413;font-weight:600">{f['type']}</td>
              <td style="padding:10px;border-bottom:1px solid #e8e6dc;color:{color};font-weight:700">{f['severity']}</td>
              <td style="padding:10px;border-bottom:1px solid #e8e6dc;color:#5e5d59">{f['detail'][:80]}</td>
            </tr>"""

        html = f"""
        <html><body style="background:#f5f4ed;font-family:'Segoe UI',sans-serif;margin:0;padding:20px">
          <div style="max-width:600px;margin:0 auto">
            <div style="background:#faf9f5;border:1px solid #e8e6dc;border-radius:16px;overflow:hidden">
              <div style="background:#141413;padding:32px;text-align:center">
                <div style="font-size:28px;font-weight:500;font-family:Georgia,serif;color:#faf9f5">
                  Phoenix <span style="color:#c96442">AI</span>
                </div>
                <div style="color:#87867f;font-size:12px;letter-spacing:1px;margin-top:4px">SECURITY ALERT</div>
              </div>
              <div style="padding:32px">
                <div style="color:#87867f;font-size:11px;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Scan Target</div>
                <div style="color:#141413;font-size:16px;font-weight:500;margin-bottom:24px;font-family:Georgia,serif">{target}</div>
                <div style="display:flex;gap:16px;margin-bottom:24px">
                  <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:16px;text-align:center">
                    <div style="font-size:10px;color:#87867f;letter-spacing:1px;margin-bottom:8px">RISK SCORE</div>
                    <div style="font-size:28px;font-weight:500;font-family:Georgia,serif;color:{'#b53333' if risk>70 else '#2d6a4f'}">{risk}/100</div>
                  </div>
                  <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:16px;text-align:center">
                    <div style="font-size:10px;color:#87867f;letter-spacing:1px;margin-bottom:8px">HIGH/CRITICAL</div>
                    <div style="font-size:28px;font-weight:500;font-family:Georgia,serif;color:#c96442">{high}</div>
                  </div>
                  <div style="flex:1;background:#f5f4ed;border:1px solid #e8e6dc;border-radius:12px;padding:16px;text-align:center">
                    <div style="font-size:10px;color:#87867f;letter-spacing:1px;margin-bottom:8px">MEDIUM</div>
                    <div style="font-size:28px;font-weight:500;font-family:Georgia,serif;color:#5e5d59">{medium}</div>
                  </div>
                </div>
                <table style="width:100%;border-collapse:collapse;background:#f5f4ed;border-radius:10px;overflow:hidden">
                  <tr style="background:#e8e6dc">
                    <th style="padding:10px;text-align:left;color:#87867f;font-size:10px;letter-spacing:1px">TYPE</th>
                    <th style="padding:10px;text-align:left;color:#87867f;font-size:10px;letter-spacing:1px">SEVERITY</th>
                    <th style="padding:10px;text-align:left;color:#87867f;font-size:10px;letter-spacing:1px">DETAIL</th>
                  </tr>
                  {findings_html}
                </table>
                <div style="margin-top:24px;text-align:center;color:#87867f;font-size:12px">
                  Phoenix AI Security Platform · {datetime.now().strftime('%d %b %Y %H:%M')}
                </div>
              </div>
            </div>
          </div>
        </body></html>"""

        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_SENDER, msg.as_string())
    except Exception as e:
        print(f"Email error: {e}")

# ─── SUBDOMAIN FINDER ────────────────────────────────────

def find_subdomains(domain: str):
    from urllib.parse import urlparse
    hostname = urlparse(domain).hostname or domain
    base_domain = ".".join(hostname.split(".")[-2:])
    common_subs = ["www","mail","ftp","admin","api","dev","staging","test","portal",
        "app","blog","shop","cdn","static","assets","img","media","upload","vpn",
        "remote","cloud","secure","login","auth","support","help","docs","status",
        "monitor","dashboard","panel","cpanel","webmail","smtp","ns1","ns2","db",
        "backup","old","beta","alpha","v2","m","mobile"]
    found = []
    def check(sub):
        full = f"{sub}.{base_domain}"
        try:
            ip = socket.gethostbyname(full)
            return {"subdomain": full, "ip": ip}
        except: return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(check, common_subs):
            if r: found.append(r)
    return found

# ─── SCANNERS ────────────────────────────────────────────

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
            r = requests.get(test_url, timeout=8, verify=False)
            for error in errors:
                if error.lower() in r.text.lower():
                    findings.append({"type":"SQL Injection","severity":"CRITICAL","detail":f"SQL error with: {payload}","fix":"Use parameterized queries","poc":f"URL: {test_url}"})
                    return
    except: pass

def check_xss(url, findings):
    payloads = ["<script>alert('XSS')</script>","<img src=x onerror=alert(1)>"]
    try:
        for payload in payloads:
            test_url = url+("&" if "?" in url else "?")+"q="+payload
            r = requests.get(test_url, timeout=8, verify=False)
            if payload in r.text:
                findings.append({"type":"XSS Vulnerability","severity":"HIGH","detail":"XSS payload reflected!","fix":"Sanitize all inputs","poc":f"URL: {test_url}"})
                return
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
                findings.append({"type":"SSL Expiring Soon","severity":"HIGH","detail":f"Expires in {days} days!","fix":"Renew SSL certificate"})
    except ssl.SSLError:
        findings.append({"type":"SSL Issue","severity":"HIGH","detail":"SSL/TLS config issue","fix":"Fix SSL configuration"})
    except: pass

def check_ports(url, findings):
    try:
        from urllib.parse import urlparse
        hostname = urlparse(url).hostname
        ports = {21:"FTP",22:"SSH",23:"Telnet",3306:"MySQL",5432:"PostgreSQL",6379:"Redis",27017:"MongoDB",9200:"Elasticsearch"}
        for port, name in ports.items():
            try:
                s = socket.socket(); s.settimeout(1)
                if s.connect_ex((hostname, port)) == 0:
                    findings.append({"type":f"Exposed Port: {name}","severity":"HIGH","detail":f"Port {port} ({name}) is public!","fix":f"Close port {port} with firewall"})
                s.close()
            except: pass
    except: pass

def check_sensitive_files(url, findings):
    base = url.rstrip("/")
    for path in ["/.git/HEAD","/.env","/wp-config.php","/admin","/phpmyadmin","/.htaccess","/backup.zip"]:
        try:
            r = requests.get(base+path, timeout=5, verify=False)
            if r.status_code == 200 and len(r.text) > 10:
                findings.append({"type":"Sensitive File Exposed","severity":"HIGH" if path in ["/.env","/.git/HEAD"] else "LOW","detail":f"Accessible: {path}","fix":f"Restrict access to {path}"})
        except: pass

def check_open_redirect(url, findings):
    try:
        for p in ["?redirect=https://evil.com","?url=https://evil.com"]:
            r = requests.get(url+p, timeout=8, verify=False, allow_redirects=False)
            if r.status_code in [301,302] and "evil.com" in r.headers.get("Location",""):
                findings.append({"type":"Open Redirect","severity":"MEDIUM","detail":"Redirects to external URLs!","fix":"Validate redirect URLs","poc":f"Test: {url+p}"})
                return
    except: pass

def check_source_code_patterns(code, findings):
    patterns = [
        (r"password\s*=\s*['\"][^'\"]+['\"]","CRITICAL","Hardcoded Password","Use environment variables"),
        (r"api_key\s*=\s*['\"][^'\"]+['\"]","CRITICAL","Hardcoded API Key","Store in .env file"),
        (r"secret\s*=\s*['\"][^'\"]+['\"]","HIGH","Hardcoded Secret","Move to .env file"),
        (r"exec\(.*\$_(GET|POST|REQUEST)","CRITICAL","Remote Code Execution","Never pass user input to exec()"),
        (r"eval\(.*\$_(GET|POST)","CRITICAL","Code Injection Risk","Never use eval() with user input"),
        (r"SELECT.*\+.*\$_(GET|POST|REQUEST)","CRITICAL","SQL Injection Risk","Use prepared statements"),
        (r"innerHTML\s*=\s*.*user","HIGH","XSS via innerHTML","Use textContent instead"),
        (r"md5\(","MEDIUM","Weak Hashing MD5","Use bcrypt or SHA-256"),
        (r"AWS_SECRET|aws_secret_access_key","CRITICAL","AWS Key Exposed","Remove immediately"),
        (r"private_key\s*=","CRITICAL","Private Key in Code","Never store keys in code"),
        (r"http://(?!localhost)","LOW","Insecure HTTP URL","Use HTTPS"),
    ]
    for pattern, severity, name, fix in patterns:
        if re.findall(pattern, code, re.IGNORECASE):
            findings.append({"type":name,"severity":severity,"detail":"Pattern found in source code","fix":fix})

def run_url_scan(url):
    findings = []
    try:
        resp = requests.get(url, headers={"User-Agent":"PhoenixAI/1.0"}, timeout=10, verify=False)
        check_security_headers(resp, findings)
        if url.startswith("http://"):
            findings.append({"type":"Insecure Protocol","severity":"HIGH","detail":"HTTP not HTTPS!","fix":"Install SSL certificate"})
        if "Server" in resp.headers:
            findings.append({"type":"Server Info Disclosure","severity":"LOW","detail":f"Server: {resp.headers['Server']}","fix":"Hide server version"})
        soup = BeautifulSoup(resp.text,"html.parser")
        for i,form in enumerate(soup.find_all("form")):
            if not any("csrf" in inp.get("name","").lower() or "token" in inp.get("name","").lower() for inp in form.find_all("input")):
                findings.append({"type":"CSRF Vulnerability","severity":"HIGH","detail":f"Form #{i+1} no CSRF token!","fix":"Add CSRF token"})
        check_sql_injection(url, findings)
        check_xss(url, findings)
        check_open_redirect(url, findings)
        check_sensitive_files(url, findings)
        check_ssl(url, findings)
        check_ports(url, findings)
    except Exception as e:
        findings.append({"type":"Scan Error","severity":"INFO","detail":str(e),"fix":"Check URL"})
    high = sum(1 for f in findings if f["severity"] in ["HIGH","CRITICAL"])
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    return {"status":"completed","url":url,"risk_score":min(100,(high*25)+(medium*15)+(low*5)),"total_findings":len(findings),"high":high,"medium":medium,"low":low,"findings":findings}

def run_code_scan(code):
    findings = []
    check_source_code_patterns(code, findings)
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
                if any(name.endswith(ext) for ext in ['.py','.js','.php','.java','.ts','.jsx','.tsx','.rb','.go','.env','.config']):
                    try:
                        content = z.read(name).decode('utf-8', errors='ignore')
                        file_findings = []
                        check_source_code_patterns(content, file_findings)
                        for f in file_findings:
                            f["file"] = name
                            findings.append(f)
                        scanned_files.append(name)
                    except: pass
    except Exception as e:
        findings.append({"type":"Error","severity":"INFO","detail":str(e),"fix":"Check ZIP"})
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
                findings.append({"type":"High Abuse Score","severity":"CRITICAL","detail":f"Abuse score: {abuse_score}/100","fix":"Block immediately"})
            elif abuse_score > 10:
                findings.append({"type":"Suspicious IP","severity":"HIGH","detail":f"Abuse score: {abuse_score}/100","fix":"Monitor closely"})
        except: pass

        try:
            r = requests.get(target, timeout=8, verify=False)
            server = r.headers.get("Server","")
            intel["server"] = server
        except: pass

        subdomains = find_subdomains(target)
        intel["subdomains"] = subdomains
        if subdomains:
            findings.append({"type":"Subdomains Found","severity":"INFO","detail":f"{len(subdomains)} subdomains found","fix":"Secure all subdomains"})

        try:
            if ip and ip != hostname:
                reversed_ip = ".".join(reversed(ip.split(".")))
                blacklisted = []
                for bl in ["zen.spamhaus.org","bl.spamcop.net"]:
                    try: socket.gethostbyname(f"{reversed_ip}.{bl}"); blacklisted.append(bl)
                    except: pass
                intel["blacklisted"] = len(blacklisted) > 0
                if blacklisted:
                    findings.append({"type":"IP Blacklisted","severity":"CRITICAL","detail":f"Found in: {', '.join(blacklisted)}","fix":"Contact ISP"})
        except: pass

    except Exception as e:
        findings.append({"type":"Error","severity":"INFO","detail":str(e),"fix":"Check target"})

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
        soup = BeautifulSoup(resp.text,"html.parser")
        for i,form in enumerate(soup.find_all("form")):
            if not any("csrf" in inp.get("name","").lower() or "token" in inp.get("name","").lower() for inp in form.find_all("input")):
                findings.append({"type":"CSRF Vulnerability","severity":"HIGH","detail":f"Form #{i+1} no CSRF!","fix":"Add CSRF token"})
        for cookie in session.cookies:
            issues = []
            if not cookie.has_nonstandard_attr("HttpOnly"): issues.append("missing HttpOnly")
            if not cookie.secure: issues.append("missing Secure")
            if issues: findings.append({"type":"Insecure Cookie","severity":"MEDIUM","detail":f"Cookie '{cookie.name}': {', '.join(issues)}","fix":"Set HttpOnly and Secure"})
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
            messages=[{"role":"user","content":f"Security scan: URL:{scan_result.get('url')} Risk:{scan_result.get('risk_score')}/100 H:{scan_result.get('high')} M:{scan_result.get('medium')} Top findings:{json.dumps(scan_result.get('findings',[])[:3])}. Give 3 lines: 1.Status 2.Critical issue 3.Recommendation"}],
            max_tokens=200)
        return r.choices[0].message.content
    except Exception as e:
        return f"AI unavailable: {str(e)}"

def generate_pdf_report(scan_result, target):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, white
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_CENTER
        import io

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=0.75*inch, leftMargin=0.75*inch, topMargin=0.75*inch, bottomMargin=0.75*inch)
        TERRA = HexColor('#c96442'); DARK = HexColor('#141413'); GRAY = HexColor('#5e5d59'); LIGHT = HexColor('#f5f4ed'); WHITE = HexColor('#faf9f5')
        title_s = ParagraphStyle('t', fontSize=28, fontName='Helvetica-Bold', textColor=TERRA, spaceAfter=6, alignment=TA_CENTER)
        sub_s = ParagraphStyle('s', fontSize=12, fontName='Helvetica', textColor=GRAY, spaceAfter=20, alignment=TA_CENTER)
        h2_s = ParagraphStyle('h', fontSize=14, fontName='Helvetica-Bold', textColor=DARK, spaceAfter=8, spaceBefore=16)
        body_s = ParagraphStyle('b', fontSize=10, fontName='Helvetica', textColor=HexColor('#4d4c48'), spaceAfter=6, leading=14)

        story = []
        story.append(Paragraph("Phoenix AI", title_s))
        story.append(Paragraph("Security Testing Platform — Penetration Test Report", sub_s))
        story.append(HRFlowable(width="100%", thickness=2, color=TERRA))
        story.append(Spacer(1, 16))

        risk = scan_result.get('risk_score', 0)
        meta = [['Target', target, 'Date', datetime.now().strftime('%d %b %Y %H:%M')],
                ['Risk Score', f"{risk}/100", 'Total Issues', str(scan_result.get('total_findings',0))],
                ['High/Critical', str(scan_result.get('high',0)), 'Medium', str(scan_result.get('medium',0))]]
        mt = Table(meta, colWidths=[1.2*inch, 2.8*inch, 1.2*inch, 2.8*inch])
        mt.setStyle(TableStyle([('FONTNAME',(0,0),(-1,-1),'Helvetica'),('FONTSIZE',(0,0),(-1,-1),9),
            ('FONTNAME',(0,0),(0,-1),'Helvetica-Bold'),('FONTNAME',(2,0),(2,-1),'Helvetica-Bold'),
            ('TEXTCOLOR',(0,0),(0,-1),GRAY),('TEXTCOLOR',(2,0),(2,-1),GRAY),
            ('GRID',(0,0),(-1,-1),0.5,HexColor('#e8e6dc')),('PADDING',(0,0),(-1,-1),8),
            ('ROWBACKGROUNDS',(0,0),(-1,-1),[WHITE,LIGHT])]))
        story.append(mt); story.append(Spacer(1, 16))

        if scan_result.get('ai_explanation'):
            story.append(Paragraph("AI ANALYSIS", h2_s))
            story.append(HRFlowable(width="100%", thickness=1, color=TERRA))
            story.append(Spacer(1, 8))
            story.append(Paragraph(scan_result['ai_explanation'], body_s))

        findings = scan_result.get('findings', [])
        if findings:
            story.append(Paragraph(f"VULNERABILITIES ({len(findings)})", h2_s))
            story.append(HRFlowable(width="100%", thickness=1, color=TERRA))
            story.append(Spacer(1, 8))
            sev_colors = {'CRITICAL':HexColor('#b53333'),'HIGH':HexColor('#c96442'),'MEDIUM':HexColor('#87867f'),'LOW':HexColor('#b0aea5'),'INFO':HexColor('#5e5d59')}
            for i, f in enumerate(findings):
                c = sev_colors.get(f.get('severity','INFO'), GRAY)
                rows = [[f"#{i+1} {f.get('type','')}", f.get('severity','')],
                        ['Detail:', f.get('detail','')], ['Fix:', f.get('fix','')]]
                if f.get('poc'): rows.append(['PoC:', f.get('poc','')])
                if f.get('file'): rows.append(['File:', f.get('file','')])
                vt = Table(rows, colWidths=[5.5*inch, 2.3*inch])
                vt.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),LIGHT),
                    ('FONTNAME',(0,0),(0,0),'Helvetica-Bold'),('FONTSIZE',(0,0),(-1,-1),9),
                    ('TEXTCOLOR',(1,0),(1,0),c),('FONTNAME',(1,0),(1,0),'Helvetica-Bold'),
                    ('ALIGN',(1,0),(1,0),'RIGHT'),('TEXTCOLOR',(0,1),(0,-1),GRAY),
                    ('FONTNAME',(0,1),(0,-1),'Helvetica-Bold'),
                    ('GRID',(0,0),(-1,-1),0.5,HexColor('#e8e6dc')),('PADDING',(0,0),(-1,-1),6)]))
                story.append(vt); story.append(Spacer(1, 8))

        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor('#e8e6dc')))
        story.append(Paragraph(f"Phoenix AI Security Platform · {datetime.now().strftime('%d %b %Y %H:%M')}", sub_s))
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()
    except: return None

# ─── ROUTES ──────────────────────────────────────────────

@app.get("/")
def home(): return {"message": "Phoenix AI API running! 🚀"}

@app.get("/health")
def health(): return {"status": "OK"}

@app.post("/register")
def register(user: UserRegister):
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    hashed = hashlib.sha256(user.password.encode()).hexdigest()
    try:
        c.execute("INSERT INTO users (email, password, plan, scan_count, created_at) VALUES (?, ?, 'FREE', 0, ?)",
                  (user.email, hashed, datetime.now().isoformat()))
        conn.commit()
        return {"message": "Registered!", "email": user.email}
    except: raise HTTPException(status_code=400, detail="Email already exists!")
    finally: conn.close()

@app.post("/login")
def login(user: UserLogin):
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    hashed = hashlib.sha256(user.password.encode()).hexdigest()
    c.execute("SELECT * FROM users WHERE email=? AND password=?", (user.email, hashed))
    db_user = c.fetchone()
    if not db_user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials!")
    c.execute("UPDATE users SET last_login=? WHERE email=?", (datetime.now().isoformat(), user.email))
    conn.commit()
    conn.close()
    return {"message": "Login successful!", "email": db_user[1], "user_id": db_user[0], "plan": db_user[3] or "FREE"}

@app.post("/scan")
def create_scan(scan: ScanRequest):
    if scan.scan_type == "code": result = run_code_scan(scan.code)
    elif scan.scan_type == "threat": result = run_threat_intel(scan.target)
    elif scan.scan_type == "live": result = run_live_app_test(scan.target, scan.login_url, scan.login_email, scan.login_password)
    else: result = run_url_scan(scan.target)

    result["ai_explanation"] = get_ai_explanation(result)

    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans (user_id, target, scan_type, status, result, created_at) VALUES (?, ?, ?, ?, ?, ?)",
              (scan.user_id, scan.target, scan.scan_type, "completed", json.dumps(result), datetime.now().isoformat()))
    conn.commit()
    scan_id = c.lastrowid
    if scan.user_id:
        c.execute("UPDATE users SET scan_count = scan_count + 1 WHERE id=?", (scan.user_id,))
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
def download_pdf(scan_id: int):
    from fastapi.responses import Response
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT target, result FROM scans WHERE id=?", (scan_id,))
    row = c.fetchone()
    conn.close()
    if not row: raise HTTPException(status_code=404, detail="Not found")
    pdf = generate_pdf_report(json.loads(row[1]), row[0])
    if not pdf: raise HTTPException(status_code=500, detail="PDF failed")
    return Response(content=pdf, media_type="application/pdf",
                   headers={"Content-Disposition": f"attachment; filename=phoenix-ai-{scan_id}.pdf"})

@app.get("/scans")
def get_scans():
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT id, target, scan_type, status, result, created_at FROM scans ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    scans = []
    for row in rows:
        result = None
        try: result = json.loads(row[4]) if row[4] else None
        except: result = None
        scans.append({"id":row[0],"target":row[1],"scan_type":row[2],"status":row[3],"result":result,"created_at":row[5]})
    return {"scans": scans}

# ─── ADMIN ROUTES ─────────────────────────────────────────

@app.get("/admin/stats")
def admin_stats(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM users")
    total_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans")
    total_scans = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE plan='PRO'")
    pro_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE plan='ENTERPRISE'")
    enterprise_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE plan='FREE'")
    free_users = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM scans WHERE created_at >= date('now', '-7 days')")
    scans_this_week = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM users WHERE created_at >= date('now', '-7 days')")
    new_users_week = c.fetchone()[0]

    conn.close()
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "pro_users": pro_users,
        "enterprise_users": enterprise_users,
        "free_users": free_users,
        "scans_this_week": scans_this_week,
        "new_users_week": new_users_week,
        "estimated_revenue": (pro_users * 499) + (enterprise_users * 4999)
    }

@app.get("/admin/users")
def admin_users(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("SELECT id, email, plan, scan_count, plan_expires, last_login, created_at FROM users ORDER BY id DESC")
    rows = c.fetchall()
    conn.close()
    return {"users": [{"id":r[0],"email":r[1],"plan":r[2]or"FREE","scan_count":r[3]or 0,"plan_expires":r[4],"last_login":r[5],"created_at":r[6]} for r in rows]}

@app.post("/admin/update-plan")
def update_plan(data: UpdatePlan):
    if data.admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    plan_days = {"FREE": 0, "PRO": 30, "ENTERPRISE": 30}
    expires = None
    if data.plan != "FREE":
        expires = (datetime.now() + timedelta(days=plan_days.get(data.plan, 30))).isoformat()
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("UPDATE users SET plan=?, plan_started=?, plan_expires=? WHERE id=?",
              (data.plan, datetime.now().isoformat(), expires, data.user_id))
    conn.commit()
    conn.close()
    return {"message": f"Plan updated to {data.plan}", "expires": expires}

@app.get("/admin/scans")
def admin_scans(secret: str):
    if secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")
    conn = sqlite3.connect("voidscan.db")
    c = conn.cursor()
    c.execute("""SELECT s.id, s.target, s.scan_type, s.created_at, u.email
                 FROM scans s LEFT JOIN users u ON s.user_id = u.id
                 ORDER BY s.id DESC LIMIT 100""")
    rows = c.fetchall()
    conn.close()
    return {"scans": [{"id":r[0],"target":r[1],"type":r[2],"date":r[3],"user":r[4]or"Anonymous"} for r in rows]}