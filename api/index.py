from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse  # ← FALTAVA ESTE IMPORT
from api.services import scanner, sandbox, report

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/analyze")
async def analyze_url(req: URLRequest):
    url = req.url.strip()
    if not url.startswith("http"): url = "http://" + url
    
    # Lógica Local
    infra = scanner.get_infrastructure(urlparse(url).hostname)
    ssl_data = scanner.check_ssl(urlparse(url).hostname)
    heuristics = scanner.run_heuristics(url)
    reputation = scanner.check_reputation(url)
    
    # Lógica Remota (Worker)
    sandbox_data = await sandbox.get_remote_screenshot(url)
    
    # Consolidação de Risco
    risk_score = 0
    risk_score = max(risk_score, reputation["score"])
    risk_score += heuristics["score"]
    if not ssl_data.get("valid"): risk_score += 20
    
    final_score = min(risk_score, 100)
    
    result = {
        "url": url,
        "final": {
            "score": final_score,
            "verdict": "MALICIOUS" if final_score > 70 else "SUSPICIOUS" if final_score > 40 else "SAFE",
            "reasons": heuristics["flags"] + ([f"Reputação Ruim: {reputation['sources']}"] if reputation['score'] > 0 else [])
        },
        "infra": infra,
        "ssl": ssl_data,
        "sandbox": sandbox_data
    }
    return result

@app.post("/report/pdf")
async def get_pdf(data: dict):
    pdf_bytes = report.generate_pdf(data)
    return Response(content=bytes(pdf_bytes), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=report.pdf"})