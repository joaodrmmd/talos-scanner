import os

# Idealmente, use variáveis de ambiente na Vercel. Aqui deixei hardcoded para facilitar seu teste local.
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY", "7b498c99278e662e9655ef38c6902e0463af80b72cb1990f565e628ae3634eb0")
URLHAUS_KEY = os.getenv("URLHAUS_KEY", "2ce3d314ea5b2180e04bb495a1c54e8c28da5fea2e1668aa")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "7f6a94769acc0c48c15c1f4053c39803756c9cd50d221b505eedee06e1c8e119cb67a1a22db2909c")

# URL do seu Space no Hugging Face (CORRIGIDO - estava truncado)
SANDBOX_URL = os.getenv("SANDBOX_URL", "https://tlssecurity-scanpy1.hf.space/screenshot")