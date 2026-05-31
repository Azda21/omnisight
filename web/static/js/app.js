// OmniSight Frontend

function openScanModal() {
    document.getElementById('scanModal').style.display = 'flex';
}

function closeScanModal() {
    document.getElementById('scanModal').style.display = 'none';
}

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeScanModal();
});

document.getElementById('scanModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'scanModal') closeScanModal();
});

const PRESETS = {
    quick: '21-23,25,53,80,110,443,993,3306,3389,8080',
    full: '1-65535',
};

function setPreset(name) {
    const ports = PRESETS[name];
    if (ports) {
        document.getElementById('scanPorts').value = ports;
    }
}

// Load device-category presets so "scan for cameras" fills camera ports.
async function loadScanPresets() {
    const container = document.getElementById('presetButtons');
    if (!container) return;
    try {
        const resp = await fetch('/api/categories');
        const cats = await resp.json();
        cats.forEach(cat => {
            if (!cat.scan_ports) return;
            PRESETS[cat.key] = cat.scan_ports;
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'btn btn-outline btn-xs';
            btn.textContent = `${cat.icon} ${cat.label.split(' /')[0].split(' ')[0]}`;
            btn.title = cat.description;
            btn.onclick = () => {
                document.getElementById('scanPorts').value = cat.scan_ports;
                if (!document.getElementById('scanName').value) {
                    document.getElementById('scanName').value = `${cat.label} sweep`;
                }
            };
            container.appendChild(btn);
        });
    } catch (e) { /* presets are optional */ }
}

document.addEventListener('DOMContentLoaded', loadScanPresets);

async function startScan(e) {
    e.preventDefault();
    const form = document.getElementById('scanForm');
    const progress = document.getElementById('scanProgress');
    const statusEl = document.getElementById('scanStatus');
    const fillEl = document.getElementById('progressFill');

    const targets = document.getElementById('scanTarget').value;
    const ports = document.getElementById('scanPorts').value;
    const protocol = document.getElementById('scanProtocol').value;
    const scan_mode = document.getElementById('scanMode')?.value || 'auto';
    const name = document.getElementById('scanName').value;

    form.style.display = 'none';
    progress.style.display = 'block';
    statusEl.textContent = 'Starting scan...';
    fillEl.style.width = '10%';

    try {
        const params = new URLSearchParams({ targets, ports, protocol, scan_mode, name });
        const resp = await fetch(`/api/scan?${params}`, { method: 'POST' });
        const data = await resp.json();

        if (data.session_id) {
            statusEl.textContent = `Scan started: ${data.total_hosts} hosts`;
            fillEl.style.width = '30%';
            pollScanStatus(data.session_id);
        }
    } catch (err) {
        statusEl.textContent = `Error: ${err.message}`;
        fillEl.style.width = '0%';
    }
}

async function pollScanStatus(sessionId) {
    const statusEl = document.getElementById('scanStatus');
    const fillEl = document.getElementById('progressFill');

    const poll = async () => {
        try {
            const resp = await fetch(`/api/scan/${sessionId}`);
            const data = await resp.json();

            if (data.status === 'completed') {
                fillEl.style.width = '100%';
                statusEl.textContent = `Scan complete! Found ${data.open_ports_found} open ports`;
                setTimeout(() => {
                    closeScanModal();
                    window.location.reload();
                }, 1500);
                return;
            } else if (data.status === 'failed') {
                statusEl.textContent = `Scan failed: ${data.error}`;
                fillEl.style.width = '0%';
                return;
            } else {
                fillEl.style.width = '60%';
                statusEl.textContent = `Scanning... ${data.open_ports_found || 0} ports found so far`;
            }
        } catch (err) {
            statusEl.textContent = 'Checking status...';
        }
        setTimeout(poll, 2000);
    };

    setTimeout(poll, 2000);
}

function searchHint(query) {
    // The backend parses the full Shodan-style DSL out of the q parameter,
    // so pass the whole expression through verbatim.
    window.location.href = `/search?q=${encodeURIComponent(query)}`;
}

function searchCategory(key) {
    window.location.href = `/search?q=cat:${encodeURIComponent(key)}`;
}

// Open the scan modal ready for an internet target / range.
function openRangeScan() {
    openScanModal();
    const t = document.getElementById('scanTarget');
    if (t) { t.value = ''; t.placeholder = 'Hedef public IP / aralık (ör. 45.33.0.0/24 veya 1.2.3.4-1.2.3.254)'; t.focus(); }
}

// Actively verify access level for a single service — "ben bağlandım, sen de".
async function verifyAccess(ip, port, service, btn) {
    const original = btn.innerHTML;
    btn.innerHTML = '⏳ Bağlanılıyor...';
    btn.disabled = true;
    try {
        const params = new URLSearchParams({ ip, port, service });
        const resp = await fetch(`/api/verify?${params}`, { method: 'POST' });
        const rep = await resp.json();
        // Replace button with a verdict box.
        const box = document.createElement('div');
        box.className = 'verify-result verify-' + rep.level;
        let html = `<div class="verify-verdict">${rep.level_label}</div>`;
        html += `<div class="verify-summary">${rep.summary}</div>`;
        if (rep.credentials) html += `<div class="verify-cred">🔑 ${rep.credentials}</div>`;
        if (rep.evidence && rep.evidence.length) {
            html += '<ul class="verify-evidence">';
            rep.evidence.forEach(e => html += `<li>${e}</li>`);
            html += '</ul>';
        }
        if (rep.proof) html += `<pre class="verify-proof">${rep.proof.substring(0,400).replace(/</g,'&lt;')}</pre>`;
        box.innerHTML = html;
        btn.replaceWith(box);
    } catch (e) {
        btn.innerHTML = original;
        btn.disabled = false;
        showToast('Doğrulama başarısız');
    }
}

// Continuous internet sweep of a target range the user supplies, with auto-verify.
async function startContinuous() {
    const target = prompt(
        'Sürekli taranacak public IP aralığı (yalnızca yetkili olduğun hedefler!):\n' +
        'Örnek: 45.33.0.0/24  veya  93.184.216.0-93.184.216.255',
        ''
    );
    if (!target || !target.trim()) return;
    try {
        const params = new URLSearchParams({
            targets: target.trim(), interval_seconds: 600, auto_verify: 'true',
        });
        await fetch(`/api/continuous/start?${params}`, { method: 'POST' });
        showToast(`Sürekli tarama başladı: ${target} (kapsamlı portlar, otomatik doğrulama)`);
        setTimeout(() => window.location.href = '/monitor', 1200);
    } catch (e) {
        showToast('Sürekli tarama başlatılamadı');
    }
}

async function clearDemo() {
    await fetch('/api/demo/clear', { method: 'POST' });
    showToast('Örnek veriler temizlendi');
    setTimeout(() => window.location.reload(), 800);
}

// ── Global-search API key settings ──
function openSettings() {
    document.getElementById('settingsModal').style.display = 'flex';
    refreshSettingsStatus();
}
function closeSettings() {
    document.getElementById('settingsModal').style.display = 'none';
}
async function refreshSettingsStatus() {
    try {
        const s = await (await fetch('/api/settings')).json();
        const el = document.getElementById('settingsStatus');
        if (el) el.innerHTML = `Shodan: ${s.shodan ? '✅ bağlı' : '❌ yok'} · Censys: ${s.censys ? '✅ bağlı' : '❌ yok'}`;
    } catch(e) {}
}
async function saveSettings() {
    const params = new URLSearchParams();
    const sk = document.getElementById('shodanKey').value.trim();
    const ci = document.getElementById('censysId').value.trim();
    const cs = document.getElementById('censysSecret').value.trim();
    if (sk) params.set('shodan_api_key', sk);
    if (ci) params.set('censys_api_id', ci);
    if (cs) params.set('censys_api_secret', cs);
    await fetch(`/api/settings?${params}`, { method: 'POST' });
    showToast('API anahtarları kaydedildi');
    refreshSettingsStatus();
}

document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeSettings(); });
document.getElementById('settingsModal')?.addEventListener('click', (e) => {
    if (e.target.id === 'settingsModal') closeSettings();
});

function setMode(mode) {
    const easy = document.getElementById('easyHints');
    const adv = document.getElementById('advancedHints');
    const easyTab = document.getElementById('easyTab');
    const advTab = document.getElementById('advancedTab');
    const search = document.getElementById('mainSearch');
    if (!easy || !adv) return;

    if (mode === 'advanced') {
        easy.style.display = 'none';
        adv.style.display = 'block';
        easyTab.classList.remove('active');
        advTab.classList.add('active');
        if (search) search.placeholder = 'port:443 country:TR product:nginx vuln:true "exact phrase"';
        localStorage.setItem('omnisight_mode', 'advanced');
    } else {
        easy.style.display = 'grid';
        adv.style.display = 'none';
        advTab.classList.remove('active');
        easyTab.classList.add('active');
        if (search) search.placeholder = 'Type a device: camera, router, database, printer...';
        localStorage.setItem('omnisight_mode', 'easy');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const saved = localStorage.getItem('omnisight_mode');
    if (saved === 'advanced') setMode('advanced');
});

// Format numbers
function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard');
    });
}

function showToast(message) {
    const toast = document.createElement('div');
    toast.style.cssText = `
        position: fixed; bottom: 24px; right: 24px; padding: 12px 20px;
        background: #1a1f2e; border: 1px solid #3b82f6; border-radius: 8px;
        color: #e2e8f0; font-size: 0.9em; z-index: 999; box-shadow: 0 4px 24px rgba(0,0,0,0.4);
        animation: fadeIn 0.3s ease;
    `;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// Keyboard shortcut: Ctrl+K to focus search
document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('.search-input-wrapper input, .search-form-inline input');
        if (searchInput) searchInput.focus();
    }
});
