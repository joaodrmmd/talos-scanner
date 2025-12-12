let currentData = null;

async function analyzeUrl() {
    const url = document.getElementById('urlInput').value;
    if(!url) return;

    // 1. Ativa Overlay e Loading
    const overlay = document.getElementById('scanOverlay');
    const loading = document.getElementById('loadingState');
    const modal = document.getElementById('resultModal');
    
    overlay.classList.add('active');
    loading.style.display = 'block';
    modal.style.display = 'none';

    try {
        const res = await fetch('/api/analyze', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({url})
        });
        currentData = await res.json();

        // 2. Transição para Modal
        loading.style.display = 'none';
        modal.style.display = 'block';

        // Popula Modal
        const score = currentData.final.score;
        const scoreEl = document.getElementById('modalScoreCircle');
        const verdictEl = document.getElementById('modalVerdict');
        
        scoreEl.innerText = score;
        scoreEl.className = "score-circle " + (score > 50 ? "danger" : "safe");
        verdictEl.innerText = score > 50 ? "AMEAÇA DETECTADA" : "SITE SEGURO";
        verdictEl.style.color = score > 50 ? "var(--danger)" : "var(--safe)";

    } catch (e) {
        alert("Erro na análise");
        overlay.classList.remove('active');
    }
}

function closeModalAndShowDetails() {
    document.getElementById('scanOverlay').classList.remove('active');
    // Aqui você chama sua função antiga que popula o dashboard completo
    populateDashboard(currentData); 
    document.getElementById('results-area').classList.add('active');
}

// ... Resto das funções de Download PDF e Populate ...