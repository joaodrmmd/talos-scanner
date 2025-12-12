import dns.resolver
import whois
import ssl
import socket
import requests
import math
import re
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime, date
from api.config import VIRUSTOTAL_KEY, URLHAUS_KEY, ABUSEIPDB_KEY

# --- FUNÇÕES UTILITÁRIAS ---
def calculate_entropy(text):
    if not text: return 0
    p, lns = Counter(text), float(len(text))
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

def get_infrastructure(hostname):
    data = {"dns": {}, "whois": {}, "geo": {}}
    try:
        a_records = dns.resolver.resolve(hostname, 'A')
        data["dns"]["a"] = [r.to_text() for r in a_records]
        ip = data["dns"]["a"][0]
        
        # AbuseIPDB Check (Simplificado)
        if ABUSEIPDB_KEY:
            headers = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'}
            r = requests.get('https://api.abuseipdb.com/api/v2/check', 
                             headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=3)
            if r.status_code == 200:
                data["geo"] = r.json().get('data', {})
    except:
        pass
    
    try:
        w = whois.whois(hostname)
        data["whois"]["org"] = w.org
        data["whois"]["creation_date"] = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date)
    except:
        pass
    return data

def check_ssl(hostname):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                # Lógica simplificada de validade
                return {"valid": True, "issuer": dict(x[0] for x in cert['issuer']).get('commonName', '')}
    except:
        return {"valid": False, "error": "SSL Failed"}

def check_reputation(url):
    score = 0
    sources = {}
    
    # URLHaus
    if URLHAUS_KEY:
        try:
            r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", 
                              data={'url': url}, headers={'Auth-Key': URLHAUS_KEY}, timeout=3)
            if r.status_code == 200 and r.json().get("query_status") == "ok":
                score = 100
                sources["URLHaus"] = "MALICIOSO"
        except: pass

    return {"score": score, "sources": sources}

def run_heuristics(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    score = 0
    flags = []

    entropy = calculate_entropy(hostname)
    if entropy > 4.2:
        score += 30
        flags.append("Alta entropia no domínio (Aleatório)")
    
    suspicious = ['login', 'bank', 'secure', 'account', 'update', 'verify']
    if any(s in url.lower() for s in suspicious):
        score += 20
        flags.append("Palavras-chave de Phishing detectadas")

    return {"score": score, "flags": flags, "entropy": round(entropy, 2)}