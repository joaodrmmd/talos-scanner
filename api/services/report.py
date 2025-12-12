from fpdf import FPDF

class ProfessionalPDF(FPDF):
    def header(self):
        # Fundo do Header (Azul Escuro Profundo)
        self.set_fill_color(10, 20, 35)
        self.rect(0, 0, 210, 40, 'F')
        
        self.set_font('Arial', 'B', 24)
        self.set_text_color(0, 242, 255) # Ciano Neon
        self.set_xy(10, 12)
        self.cell(0, 10, 'TALOS INTELLIGENCE', 0, 1, 'L')
        
        self.set_font('Arial', '', 10)
        self.set_text_color(200, 200, 200)
        self.cell(0, 5, 'Relatório Avançado de Ameaças Cibernéticas', 0, 1, 'L')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Talos Security Scan - Pagina {self.page_no()}', 0, 0, 'C')

def generate_pdf(data):
    pdf = ProfessionalPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Cores
    COLOR_SAFE = (0, 180, 80)
    COLOR_DANGER = (220, 50, 50)
    
    final = data.get("final", {})
    
    # --- BOX DE VEREDITO ---
    pdf.ln(35)
    pdf.set_font("Arial", "B", 14)
    pdf.set_fill_color(245, 245, 250)
    pdf.cell(0, 10, "  RESUMO EXECUTIVO", 0, 1, 'L', 1)
    
    pdf.ln(5)
    pdf.set_font("Arial", "", 12)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(40, 10, "URL Alvo:", 0, 0)
    pdf.set_font("Courier", "", 11)
    pdf.cell(0, 10, data.get("url", ""), 0, 1)
    
    # Score Visual
    score = final.get("score", 0)
    pdf.set_font("Arial", "B", 12)
    pdf.cell(40, 10, "Risk Score:", 0, 0)
    
    if score > 70:
        pdf.set_text_color(*COLOR_DANGER)
        verdict = "CRITICO / MALICIOSO"
    else:
        pdf.set_text_color(*COLOR_SAFE)
        verdict = "SEGURO / BAIXO RISCO"
        
    pdf.cell(0, 10, f"{score}/100 ({verdict})", 0, 1)
    
    # --- FATORES DE RISCO ---
    pdf.ln(10)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(245, 245, 250)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "  DETALHES TÉCNICOS & RISCOS", 0, 1, 'L', 1)
    pdf.ln(5)
    
    pdf.set_font("Arial", "", 10)
    reasons = final.get("reasons", [])
    if not reasons:
        pdf.cell(0, 8, "- Nenhum vetor de ataque óbvio detectado.", 0, 1)
    else:
        for r in reasons:
            pdf.set_text_color(180, 0, 0) # Vermelho escuro
            pdf.cell(5, 8, "!", 0, 0)
            pdf.set_text_color(50, 50, 50)
            pdf.cell(0, 8, str(r), 0, 1)

    # --- SCREENSHOT ---
    b64_img = data.get("sandbox", {}).get("screenshot")
    if b64_img and "base64," in b64_img:
        pdf.add_page()
        pdf.set_font("Arial", "B", 14)
        pdf.cell(0, 10, "EVIDÊNCIA VISUAL (SANDBOX)", 0, 1, 'L')
        import base64, tempfile
        try:
            img_data = base64.b64decode(b64_img.split(',')[1])
            with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
                tmp.write(img_data)
                pdf.image(tmp.name, x=10, y=30, w=190)
        except:
            pdf.cell(0, 10, "[Erro ao renderizar imagem]", 0, 1)

    return pdf.output(dest='S').encode('latin-1')