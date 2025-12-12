from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import traceback
import sys
import os

# Passo 1: Adiciona o diretório raiz do projeto ao path (necessário para "api.services")
# Ele retrocede dois níveis: de main.py -> api/ -> raiz
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Imports dos serviços
# A importação correta, considerando a estrutura de pastas, é 'from api.services import ...'
from api.services import scanner, sandbox, report

app = FastAPI(title="Talos Security Scanner API")
# ... (O restante do seu arquivo main.py segue inalterado)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
async def root():
    return {"status": "API Online", "message": "Talos Security Scanner API", "version": "1.0"}

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "talos-api"}

@app.post("/analyze")
async def analyze_url(req: URLRequest):
    try:
        url = req.url.strip()
        if not url.startswith("http"):
            url = "https://" + url
        
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            raise HTTPException(status_code=400, detail="URL inválida - hostname não encontrado")
        
        # Lógica Local com tratamento de erro individual
        try:
            infra = scanner.get_infrastructure(hostname)
        except Exception as e:
            print(f"Erro em get_infrastructure: {e}")
            infra = {"dns": {}, "whois": {}, "geo": {}}
        
        try:
            ssl_data = scanner.check_ssl(hostname)
        except Exception as e:
            print(f"Erro em check_ssl: {e}")
            ssl_data = {"valid": False, "error": str(e)}
        
        try:
            heuristics = scanner.run_heuristics(url)
        except Exception as e:
            print(f"Erro em run_heuristics: {e}")
            heuristics = {"score": 0, "flags": [], "entropy": 0}
        
        try:
            reputation = scanner.check_reputation(url)
        except Exception as e:
            print(f"Erro em check_reputation: {e}")
            reputation = {"score": 0, "sources": {}}
        
        # Lógica Remota (Worker)
        try:
            sandbox_data = await sandbox.get_remote_screenshot(url)
        except Exception as e:
            print(f"Erro em get_remote_screenshot: {e}")
            sandbox_data = {"status": "error", "error": str(e)}
        
        # Consolidação de Risco
        risk_score = 0
        risk_score = max(risk_score, reputation.get("score", 0))
        risk_score += heuristics.get("score", 0)
        if not ssl_data.get("valid"):
            risk_score += 20
        
        final_score = min(risk_score, 100)
        
        result = {
            "url": url,
            "final": {
                "score": final_score,
                "verdict": "MALICIOUS" if final_score > 70 else "SUSPICIOUS" if final_score > 40 else "SAFE",
                "reasons": heuristics.get("flags", []) + ([f"Reputação Ruim: {reputation.get('sources', {})}"] if reputation.get('score', 0) > 0 else [])
            },
            "infra": infra,
            "ssl": ssl_data,
            "sandbox": sandbox_data
        }
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERRO GERAL: {e}")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")

@app.post("/report/pdf")
async def get_pdf(data: dict):
    try:
        pdf_bytes = report.generate_pdf(data)
        return Response(
            content=bytes(pdf_bytes), 
            media_type="application/pdf", 
            headers={"Content-Disposition": "attachment; filename=report.pdf"}
        )
    except Exception as e:
        print(f"Erro ao gerar PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Erro ao gerar PDF: {str(e)}")

# Handler para Vercel
handler = app