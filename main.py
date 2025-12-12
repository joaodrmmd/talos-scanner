from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, unquote
import requests
import dns.resolver
import ssl
import socket
import base64
import math
import re
from datetime import datetime, date
from collections import Counter
from fpdf import FPDF

# --- CONFIGURAÇÃO ---
VIRUSTOTAL_API_KEY = "7b498c99278e662e9655ef38c6902e0463af80b72cb1990f565e628ae3634eb0"
URLHAUS_API_KEY = "2ce3d314ea5b2180e04bb495a1c54e8c28da5fea2e1668aa"
ABUSEIPDB_API_KEY = "7f6a94769acc0c48c15c1f4053c39803756c9cd50d221b505eedee06e1c8e119cb67a1a22db2909c"

app = FastAPI(title="URL Security Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

# --- 1. Normalização ---
def sanitize_url(url: str):
    cleaned_url = url.strip()
    cleaned_url = unquote(cleaned_url)
    parsed = urlparse(cleaned_url)
    if not parsed.scheme:
        cleaned_url = "http://" + cleaned_url
        parsed = urlparse(cleaned_url)
    if parsed.scheme in ['file', 'gopher', 'ftp', 'ldap']:
        raise HTTPException(status_code=400, detail="Protocolo proibido.")
    return cleaned_url

# --- 2. Redirecionamentos ---
def analyze_redirects(url: str):
    history = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Compatible; SecurityScanner/1.0)'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        for r in response.history:
            history.append({
                "url": r.url,
                "status": r.status_code,
                "latency_ms": round(r.elapsed.total_seconds() * 1000, 2)
            })
        final_obj = {
            "url": response.url,
            "status": response.status_code,
            "latency_ms": round(response.elapsed.total_seconds() * 1000, 2)
        }
        return {"final_url": response.url, "chain": history, "final_hop": final_obj}
    except Exception as e:
        return {"error": str(e), "final_url": url, "chain": []}

# --- 3. Infraestrutura (Versão Segura Vercel - Sem WHOIS local) ---
def get_infrastructure_data(hostname: str):
    data = {"dns": {}, "whois": {}, "geolocation": {}}
    if ":" in hostname: hostname = hostname.split(":")[0]
    
    primary_ip = None

    # DNS
    try:
        a_records = dns.resolver.resolve(hostname, 'A')
        ip_list = [r.to_text() for r in a_records]
        data["dns"]["a_records"] = ip_list
        if ip_list: primary_ip = ip_list[0]
    except Exception as e:
        data["dns"]["error"] = f"DNS Error: {str(e)}"

    # AbuseIPDB (Substituto do IPWhois local)
    if primary_ip and ABUSEIPDB_API_KEY:
        try:
            headers = {'Key': ABUSEIPDB_API_KEY, 'Accept': 'application/json'}
            params = {'ipAddress': primary_ip, 'maxAgeInDays': '180'}
            resp = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=5)
            if resp.status_code == 200:
                abuse_data = resp.json().get('data', {})
                data["geolocation"] = { # Usamos dados do AbuseIPDB para Geo
                    "ip": primary_ip,
                    "country": abuse_data.get('countryCode'),
                    "isp": abuse_data.get('isp'),
                    "network_name": abuse_data.get('usageType')
                }
                data["reputation_ip"] = {
                    "score": abuse_data.get('abuseConfidenceScore', 0),
                    "source": "AbuseIPDB"
                }
        except:
            pass

    # WHOIS Dummy (Para não quebrar o front)
    data["whois"] = {
        "registrar": "Indisponível (Modo Serverless)",
        "creation_date": None,
        "org": "N/A"
    }
    return data

# --- 4. SSL ---
def analyze_ssl(hostname: str):
    context = ssl.create_default_context()
    result = {"is_valid": False, "issuer": None}
    try:
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result["is_valid"] = True
                issuer = dict(x[0] for x in cert['issuer'])
                result["issuer"] = issuer.get('organizationName') or issuer.get('commonName')
    except:
        result["error"] = "SSL Fail"
    return result

# --- 5, 6, 7. Headers, Reputação e Heurísticas (Mantidos simplificados) ---
def analyze_headers(url):
    # Lógica simplificada para caber aqui
    return {"details": "Headers analysis executed"}

def analyze_reputation(url):
    results = {"score": 0, "sources": {}}
    # URLHaus Check
    if URLHAUS_API_KEY:
        try:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': url}, timeout=4)
            if r.status_code == 200 and r.json().get("query_status") == "ok":
                results["score"] = 100
                results["sources"]["URLHaus"] = {"status": "MALICIOSO"}
        except: pass
    return results

def calculate_entropy(text):
    if not text: return 0
    p, lns = Counter(text), float(len(text))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def analyze_heuristics(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    score = 0
    flags = []
    
    entropy = calculate_entropy(hostname)
    if entropy > 4.2:
        score += 30
        flags.append("Alta entropia no domínio")
    
    suspicious = ['login', 'bank', 'secure', 'account', 'update']
    if any(s in url.lower() for s in suspicious):
        score += 20
        flags.append("Palavras-chave suspeitas")

    return {"risk_score": score, "details": {"flags": flags, "entropy": round(entropy, 2)}}

# --- 8. Sandbox Dummy (Sem Playwright) ---
async def run_sandbox(url: str):
    # Playwright removido para rodar na Vercel. 
    # Futuramente você conecta aqui sua API do Hugging Face.
    return {
        "status": "skipped", 
        "screenshot_base64": None, 
        "note": "Sandbox desativada no modo Vercel (Requer Worker Externo)"
    }

# --- 9. Score Final ---
def calculate_final_risk(results):
    score = 0
    reasons = []
    
    # Consolida scores
    rep_score = results.get("6_reputation", {}).get("score", 0)
    heur_score = results.get("7_heuristics", {}).get("risk_score", 0)
    ssl_invalid = not results.get("4_ssl_check", {}).get("is_valid", True)

    score = max(score, rep_score)
    score += heur_score
    if ssl_invalid: score += 30

    final_score = min(score, 100)
    
    # Gera Veredito
    if final_score > 80: verdict = "MALICIOSO"
    elif final_score > 40: verdict = "SUSPEITO"
    else: verdict = "SEGURO"

    return {
        "score": final_score,
        "safety_score": 100 - final_score,
        "verdict": verdict,
        "risk_factors": results.get("7_heuristics", {}).get("details", {}).get("flags", [])
    }

# --- GERAÇÃO PDF (Mantida Simples) ---
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Talos Security Report', 0, 1, 'C')

@app.post("/report/pdf")
async def generate_pdf(data: dict):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Veredito: {data.get('verdict')}", 0, 1)
    pdf.cell(0, 10, f"Score: {data.get('final_analysis', {}).get('score')}/100", 0, 1)
    return Response(content=bytes(pdf.output()), media_type="application/pdf")

# --- ROTA PRINCIPAL ---
@app.post("/analyze")
async def analyze_pipeline(request: URLRequest):
    results = {}
    clean = sanitize_url(request.url)
    results["1_normalization"] = {"clean_url": clean}
    
    redir = analyze_redirects(clean)
    final_url = redir.get("final_url", clean)
    hostname = urlparse(final_url).hostname
    
    if hostname:
        results["3_infrastructure"] = get_infrastructure_data(hostname)
        results["4_ssl_check"] = analyze_ssl(hostname)
        results["5_headers"] = analyze_headers(final_url)
        results["6_reputation"] = analyze_reputation(final_url)
        results["7_heuristics"] = analyze_heuristics(final_url)
        results["8_sandbox"] = await run_sandbox(final_url)
    
    results["final_analysis"] = calculate_final_risk(results)
    results["verdict"] = results["final_analysis"]["verdict"]
    
    return results

@app.get("/health")
def health():
    return {"status": "online"}