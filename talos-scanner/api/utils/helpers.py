import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

def normalize_url(url: str) -> str:
    """
    Garante que a URL tenha esquema (http/https) e remove espaços extras.
    Se o usuário digitar 'google.com', transforma em 'https://google.com'.
    """
    if not url:
        return ""
    
    url = url.strip()
    
    # Se não começar com http nem https, assume https
    if not url.startswith(("http://", "https://")):
        return f"https://{url}"
    
    return url

def validate_url(url: str) -> bool:
    """
    Verifica se a URL é estruturalmente válida para escaneamento.
    """
    try:
        result = urlparse(url)
        # Deve ter esquema (http/s) e um domínio (netloc)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def extract_domain(url: str) -> str:
    """
    Extrai apenas o domínio (ex: 'site.com') para nomear relatórios.
    """
    try:
        return urlparse(url).netloc
    except:
        return "unknown_domain"

def generate_report_id() -> str:
    """
    Gera um ID único para cada relatório de scan.
    """
    return str(uuid.uuid4())[:8]

def get_timestamp() -> str:
    """
    Retorna a data e hora atual formatada para logs.
    """
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def format_vuln_severity(severity: str) -> str:
    """
    Padroniza a severidade para o relatório (HIGH, MEDIUM, LOW, INFO).
    """
    allowed = ["HIGH", "MEDIUM", "LOW", "INFO"]
    sev = severity.upper()
    return sev if sev in allowed else "INFO"