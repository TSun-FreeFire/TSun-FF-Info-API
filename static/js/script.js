/**
 * TSun Info - Application Logic
 * Professional, modular, and efficient.
 */

document.addEventListener('DOMContentLoaded', () => {
    initTabs();
    initForms();
    animateIntro();
});

// --- Initialization ---

function initTabs() {
    const tabs = document.querySelectorAll('.nav-btn');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const targetId = tab.dataset.target;

            // Update Tab Buttons
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            // Update Tab Content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
                if (content.id === targetId) {
                    content.classList.add('active');
                }
            });
        });
    });
}

function initForms() {
    // Account Info Form
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', handleAccountSearch);
    }

    // Region Check Form
    const regionForm = document.getElementById('regionForm');
    if (regionForm) {
        regionForm.addEventListener('submit', handleRegionCheck);
    }

    // Full Response Form
    const fullResponseForm = document.getElementById('fullResponseForm');
    if (fullResponseForm) {
        fullResponseForm.addEventListener('submit', handleFullResponse);
    }

    // Copy JSON Button
    const copyBtn = document.getElementById('copyJsonBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyJsonToClipboard);
    }
}

function animateIntro() {
    const brand = document.querySelector('.brand-text');
    if (brand) {
        brand.style.opacity = '0';
        setTimeout(() => {
            brand.style.transition = 'opacity 1s ease';
            brand.style.opacity = '1';
        }, 100);
    }
}

// --- Handlers ---

async function handleAccountSearch(e) {
    e.preventDefault();
    const uidInput = document.getElementById('uid');
    const uid = uidInput.value.trim();

    if (!uid) return;

    const loadingEl = document.getElementById('loading');
    const resultsEl = document.getElementById('results');
    const infoContent = document.getElementById('infoContent');
    const outfitContent = document.getElementById('outfitContent');

    // Reset UI
    loadingEl.style.display = 'flex';
    resultsEl.style.display = 'none';
    infoContent.innerHTML = '';
    outfitContent.innerHTML = '';

    try {
        const response = await fetch(`/get?uid=${uid}`);
        const data = await response.json();

        loadingEl.style.display = 'none';
        resultsEl.style.display = 'grid';

        if (data.AccountInfo) {
            renderAccountInfo(data, uid);
        } else {
            showError(infoContent, data.message || 'Account not found.');
        }
    } catch (error) {
        loadingEl.style.display = 'none';
        resultsEl.style.display = 'block'; // Show block to display error
        showError(infoContent, `Network Error: ${error.message}`);
    }
}

async function handleRegionCheck(e) {
    e.preventDefault();
    const uidInput = document.getElementById('regionUid');
    const uid = uidInput.value.trim();

    if (!uid) return;

    const loadingEl = document.getElementById('regionLoading');
    const resultsEl = document.getElementById('regionResults');
    const regionContent = document.getElementById('regionContent');

    loadingEl.style.display = 'flex';
    resultsEl.style.display = 'none';
    regionContent.innerHTML = '';

    try {
        const response = await fetch(`/region?uid=${uid}`);
        const data = await response.json();

        loadingEl.style.display = 'none';
        resultsEl.style.display = 'block';

        if (data.region) {
            renderRegionInfo(data);
        } else {
            showError(regionContent, data.error || 'Region info not found.');
        }
    } catch (error) {
        loadingEl.style.display = 'none';
        resultsEl.style.display = 'block';
        showError(regionContent, `Network Error: ${error.message}`);
    }
}

async function handleFullResponse(e) {
    e.preventDefault();
    const uidInput = document.getElementById('fullResponseUid');
    const uid = uidInput.value.trim();

    if (!uid) return;

    const loadingEl = document.getElementById('fullResponseLoading');
    const resultsEl = document.getElementById('fullResponseResults');
    const jsonViewer = document.getElementById('jsonViewer');

    loadingEl.style.display = 'flex';
    resultsEl.style.display = 'none';
    jsonViewer.innerHTML = '';

    try {
        const response = await fetch(`/get?uid=${uid}`);
        const data = await response.json();

        loadingEl.style.display = 'none';
        resultsEl.style.display = 'block';

        // Store data for copy function
        window.currentJsonData = data;

        // Render formatted JSON
        renderFormattedJson(data, jsonViewer);
    } catch (error) {
        loadingEl.style.display = 'none';
        resultsEl.style.display = 'block';
        showError(jsonViewer, `Network Error: ${error.message}`);
    }
}

// --- Renderers ---

function renderAccountInfo(data, uid) {
    const infoContent = document.getElementById('infoContent');
    const outfitContent = document.getElementById('outfitContent');

    const basic = data.AccountInfo;
    const profile = data.AccountProfileInfo || {};
    const social = data.SocialInfo || {};
    const guild = data.GuildInfo || {};
    const pet = data.PetInfo || {};
    const credit = data.CreditScoreInfo || {};
    const captain = data.GuildOwnerInfo || {};

    // Helper to create rows
    const createRow = (label, value, highlight = false) => `
        <div class="info-row">
            <span class="info-label">${label}</span>
            <span class="info-value ${highlight ? 'highlight' : ''}">${escapeHtml(String(value || 'N/A'))}</span>
        </div>
    `;

    // 1. Basic Info Card
    const basicCard = document.createElement('div');
    basicCard.className = 'data-card';
    basicCard.innerHTML = `
        <div class="card-header">
            <div class="card-title"><span class="card-icon">👤</span> Profile</div>
        </div>
        ${createRow('Name', basic.AccountName, true)}
        ${createRow('UID', uid)}
        ${createRow('Level', basic.AccountLevel)}
        ${createRow('Region', basic.AccountRegion)}
        ${createRow('Likes', basic.AccountLikes)}
        ${createRow('Created', formatTimestamp(basic.AccountCreateTime))}
        ${createRow('Last Login', formatTimestamp(basic.AccountLastLogin))}
    `;

    // 2. Rank Info Card
    const rankCard = document.createElement('div');
    rankCard.className = 'data-card';
    rankCard.innerHTML = `
        <div class="card-header">
            <div class="card-title"><span class="card-icon">🏆</span> Rank Stats</div>
        </div>
        ${createRow('BR Rank', calculateBRRank(profile.BrRankPoint))}
        ${createRow('BR Points', profile.BrRankPoint)}
        ${createRow('CS Rank', calculateCSRank(profile.CsRankPoint))}
        ${createRow('CS Points', profile.CsRankPoint)}
        ${createRow('Honor Score', credit.creditScore)}
    `;

    // 3. Guild Info Card
    const guildCard = document.createElement('div');
    guildCard.className = 'data-card';
    guildCard.innerHTML = `
        <div class="card-header">
            <div class="card-title"><span class="card-icon">🏰</span> Guild</div>
        </div>
        ${createRow('Name', guild.GuildName)}
        ${createRow('Level', guild.GuildLevel)}
        ${createRow('Members', `${guild.GuildMember || 0}/${guild.GuildCapacity || 0}`)}
        ${captain.AccountName ? `
            <div class="info-row" style="margin-top: 10px; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px;">
                <span class="info-label">Leader</span>
                <span class="info-value">${escapeHtml(captain.AccountName)}</span>
            </div>
            ${createRow('Leader UID', captain.AccountID)}
        ` : ''}
    `;

    // Append Cards
    infoContent.appendChild(basicCard);
    infoContent.appendChild(rankCard);
    infoContent.appendChild(guildCard);

    // Outfit Image
    outfitContent.innerHTML = `
        <div class="outfit-container">
            <img src="https://danger-info-alpha.vercel.app/outfit-image?uid=${uid}&key=DANGER-OUTFIT&bg=3" 
            alt="Character Outfit" 
                 class="outfit-image"
                 onerror="this.parentElement.innerHTML='<div style=\'padding:20px;text-align:center;color:var(--error)\'>Outfit Hidden</div>'">
        </div>
    `;
}

function renderRegionInfo(data) {
    const regionContent = document.getElementById('regionContent');

    const flagHtml = getRegionFlag(data.region);
    const isImageFlag = flagHtml.includes('<img');
    
    regionContent.innerHTML = `
        <div class="data-card" style="max-width: 500px; margin: 0 auto;">
            <div class="card-header">
                <div class="card-title"><span class="card-icon">🌍</span> Region Check</div>
            </div>
            <div style="text-align: center; margin-bottom: 20px;">
                <div style="${isImageFlag ? 'margin-bottom: 10px;' : 'font-size: 3rem; margin-bottom: 10px;'}">${flagHtml}</div>
                <div style="font-size: 1.5rem; font-weight: bold; color: var(--primary);">${data.region}</div>
            </div>
            <div class="info-row">
                <span class="info-label">Nickname</span>
                <span class="info-value highlight">${escapeHtml(data.nickname)}</span>
            </div>
            <div class="info-row">
                <span class="info-label">UID</span>
                <span class="info-value">${data.uid}</span>
            </div>
        </div>
    `;
}

function showError(container, message) {
    container.innerHTML = `
        <div class="data-card" style="border-color: var(--error);">
            <div style="color: var(--error); text-align: center; padding: 20px;">
                <strong>Error</strong><br>
                ${escapeHtml(message)}
            </div>
        </div>
    `;
}

// --- Utilities ---

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTimestamp(timestamp) {
    // If timestamp is already formatted (contains space or hyphen), return as-is
    if (timestamp && typeof timestamp === 'string' && (timestamp.includes(' ') || timestamp.includes('-'))) {
        return timestamp;
    }
    
    if (!timestamp) return 'Unknown';
    
    // Legacy fallback for numeric timestamps
    let date;
    if (String(timestamp).length <= 10) {
        date = new Date(parseInt(timestamp) * 1000);
    } else {
        date = new Date(parseInt(timestamp));
    }
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatNumber(num) {
    return new Intl.NumberFormat().format(num);
}

function getRegionFlag(region) {
    // Special emoji cases for ME, EU, SAC
    const emojiFlags = {
        'ME': '🌍',
        'EU': '🌏',
        'SAC': '🌎'
    };
    
    if (emojiFlags[region]) {
        return emojiFlags[region];
    }
    
    // PNG image flags (available in /flages folder)
    const pngFlags = {
        'BD': 'bd.png',
        'BR': 'br.png',
        'ID': 'id.png',
        'IND': 'ind.png',
        'NA': 'na.png',
        'PK': 'pk.png',
        'RU': 'ru.png',
        'TH': 'th.png',
        'TW': 'tw.png',
        'US': 'us.png',
        'VN': 'vn.png'
    };
    
    if (pngFlags[region]) {
        return `<img src="/flages/${pngFlags[region]}" alt="${region}" style="width: 40px; height: 27px; vertical-align: middle; border-radius: 2px;">`;
    }
    
    // Fallback for regions without PNG or emoji
    return '🏳️';
}

function renderFormattedJson(data, container) {
    const formatted = JSON.stringify(data, null, 2);
    const highlighted = syntaxHighlightJson(formatted);
    container.innerHTML = `<pre class="json-code">${highlighted}</pre>`;
}

function syntaxHighlightJson(json) {
    json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function (match) {
        let cls = 'json-number';
        if (/^"/.test(match)) {
            if (/:$/.test(match)) {
                cls = 'json-key';
            } else {
                cls = 'json-string';
            }
        } else if (/true|false/.test(match)) {
            cls = 'json-boolean';
        } else if (/null/.test(match)) {
            cls = 'json-null';
        }
        return '<span class="' + cls + '">' + match + '</span>';
    });
}

function copyJsonToClipboard() {
    if (!window.currentJsonData) {
        alert('No data to copy!');
        return;
    }

    const jsonString = JSON.stringify(window.currentJsonData, null, 2);

    navigator.clipboard.writeText(jsonString).then(() => {
        const btn = document.getElementById('copyJsonBtn');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
        btn.style.background = 'var(--success)';

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.background = '';
        }, 2000);
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}

// Rank Calculations (Simplified logic based on typical FF points)
function calculateBRRank(points) {
    points = parseInt(points) || 0;
    if (points < 1000) return "Bronze";
    if (points < 1500) return "Silver";
    if (points < 2000) return "Gold";
    if (points < 2500) return "Platinum";
    if (points < 3000) return "Diamond";
    if (points < 3500) return "Heroic";
    return "Grandmaster";
}

function calculateCSRank(points) {
    points = parseInt(points) || 0;
    if (points < 5) return "Bronze";
    if (points < 10) return "Silver";
    if (points < 20) return "Gold";
    if (points < 30) return "Platinum";
    if (points < 40) return "Diamond";
    if (points < 50) return "Heroic";
    return "Grandmaster";
}
