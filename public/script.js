let currentData = null;

async function analyzeUrl() {
    const url = document.getElementById('urlInput').value.trim();
    if(!url) {
        alert('Por favor, digite uma URL');
        return;
    }

    const overlay = document.getElementById('scanOverlay');
    const loading = document.getElementById('loadingState');
    const modal = document.getElementById('resultModal');
    
    overlay.classList.add('active');
    loading.style.display = 'block';
    modal.style.display = 'none';

    try {
        console.log('Enviando requisição para:', '/api/analyze');
        console.log('URL a ser analisada:', url);
        
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        
        console.log('Status da resposta:', res.status);
        
        if (!res.ok) {
            const errorText = await res.text();
            console.error('Erro da API:', errorText);
            throw new Error(`Erro ${res.status}: ${errorText}`);
        }
        
        currentData = await res.json();
        console.log('Dados recebidos:', currentData);

        loading.style.display = 'none';
        modal.style.display = 'block';

        const score = currentData.final.score;
        const scoreEl = document.getElementById('modalScoreCircle');
        const verdictEl = document.getElementById('modalVerdict');
        
        scoreEl.innerText = score;
        scoreEl.className = "score-circle " + (score > 50 ? "danger" : "safe");
        verdictEl.innerText = score > 50 ? "AMEAÇA DETECTADA" : "SITE SEGURO";
        verdictEl.style.color = score > 50 ? "var(--danger)" : "var(--safe)";

    } catch (e) {
        console.error('Erro completo:', e);
        alert("Erro na análise: " + e.message + "\n\nAbra o console (F12) para mais detalhes.");
        overlay.classList.remove('active');
    }
}

function closeModalAndShowDetails() {
    document.getElementById('scanOverlay').classList.remove('active');
    populateDashboard(currentData);
    document.getElementById('results-area').classList.add('active');
}

function populateDashboard(data) {
    // Score
    document.getElementById('scoreDisplay').innerText = data.final.score + '/100';
    document.getElementById('scoreDisplay').className = 'score-big ' + (data.final.score > 50 ? 'danger' : 'safe');
    
    // Veredito
    document.getElementById('verdictDisplay').innerText = data.final.verdict;
    document.getElementById('verdictDisplay').style.color = data.final.score > 50 ? 'var(--danger)' : 'var(--safe)';
    
    // Heurísticas
    const heurEl = document.getElementById('heuristicsData');
    if (data.final.reasons && data.final.reasons.length > 0) {
        heurEl.innerHTML = data.final.reasons.map(r => `<p>⚠️ ${r}</p>`).join('');
    } else {
        heurEl.innerHTML = '<p style="color: var(--safe);">✅ Nenhum indicador de risco detectado</p>';
    }
    
    // SSL
    const sslEl = document.getElementById('sslData');
    if (data.ssl && data.ssl.valid) {
        sslEl.innerHTML = `<p style="color: var(--safe);">✅ Certificado Válido</p><p>Emissor: ${data.ssl.issuer || 'N/A'}</p>`;
    } else {
        sslEl.innerHTML = `<p style="color: var(--danger);">❌ SSL Inválido ou Ausente</p>`;
    }
    
    // Infraestrutura
    const infraEl = document.getElementById('infraData');
    let infraHTML = '';
    if (data.infra.dns && data.infra.dns.a) {
        infraHTML += `<p><strong>IP:</strong> ${data.infra.dns.a[0]}</p>`;
    }
    if (data.infra.geo && data.infra.geo.countryCode) {
        infraHTML += `<p><strong>País:</strong> ${data.infra.geo.countryCode}</p>`;
    }
    if (data.infra.whois && data.infra.whois.org) {
        infraHTML += `<p><strong>Org:</strong> ${data.infra.whois.org}</p>`;
    }
    infraEl.innerHTML = infraHTML || '<p>Dados não disponíveis</p>';
    
    // Sandbox
    const sandboxEl = document.getElementById('sandboxData');
    if (data.sandbox && data.sandbox.screenshot) {
        sandboxEl.innerHTML = `<img src="${data.sandbox.screenshot}" style="max-width: 100%; border-radius: 8px;" alt="Screenshot">`;
    } else {
        sandboxEl.innerHTML = '<p>Screenshot não disponível</p>';
    }
}

async function downloadPDF() {
    if (!currentData) return alert('Nenhum dado para exportar');
    
    try {
        const res = await fetch('/api/report/pdf', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(currentData)
        });
        
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'talos-report.pdf';
        a.click();
    } catch (e) {
        alert('Erro ao gerar PDF: ' + e.message);
    }
}

// FUNÇÃO DE TESTE - ADICIONE NO FINAL DO ARQUIVO
async function testAPI() {
    try {
        console.log('Testando API...');
        
        // Testa endpoint de health
        const healthRes = await fetch('/api/health');
        const healthData = await healthRes.json();
        console.log('Health check:', healthData);
        
        // Testa endpoint raiz
        const rootRes = await fetch('/api/');
        const rootData = await rootRes.json();
        console.log('Root endpoint:', rootData);
        
        alert('API está online! Verifique o console (F12) para detalhes.');
    } catch (e) {
        console.error('Erro ao testar API:', e);
        alert('ERRO: API não está respondendo. Detalhes no console (F12).');
    }
}