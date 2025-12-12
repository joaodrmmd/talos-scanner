import httpx
from api.config import SANDBOX_URL

async def get_remote_screenshot(url: str):
    if not SANDBOX_URL:
        return {"status": "disabled", "note": "Configure SANDBOX_URL"}
    
    async with httpx.AsyncClient() as client:
        try:
            # Timeout de 20s para dar tempo ao Playwright
            resp = await client.post(SANDBOX_URL, json={"url": url}, timeout=20.0)
            return resp.json()
        except Exception as e:
            return {"status": "error", "error": str(e)}