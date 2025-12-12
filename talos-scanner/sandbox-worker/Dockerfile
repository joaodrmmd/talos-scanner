FROM python:3.9-slim

# Instala dependências do sistema e Chrome
RUN apt-get update && apt-get install -y wget && \
    pip install playwright fastapi uvicorn && \
    playwright install --with-deps chromium

COPY . .

# Roda na porta 7860 (Padrão do Hugging Face)
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "7860"]