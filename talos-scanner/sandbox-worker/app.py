from fastapi import FastAPI, Body
from playwright.async_api import async_playwright
import base64

app = FastAPI()

@app.post("/screenshot")
async def take_screenshot(data: dict = Body(...)):
    url = data.get("url")
    results = {"status": "failed", "screenshot": None, "title": "N/A", "final_url": url}
    
    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(headless=True)
            # Contexto com User Agent comum para evitar bloqueios
            context = await browser.new_context(user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            page = await context.new_page()
            
            # Timeout de 15s e espera domcontentloaded (mais rápido que networkidle)
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            
            results["title"] = await page.title()
            results["final_url"] = page.url
            
            # Tira print
            screenshot = await page.screenshot(type='jpeg', quality=70) # JPEG é mais leve que PNG
            results["screenshot"] = "data:image/jpeg;base64," + base64.b64encode(screenshot).decode()
            results["status"] = "success"
            
            await browser.close()
        except Exception as e:
            results["error"] = str(e)
            
    return results