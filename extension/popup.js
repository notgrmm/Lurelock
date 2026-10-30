/**
 * Lurelock - Popup UI Controller
 * Self-explanatory, simple, and sleek real-time phishing inspector.
 */

const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
}[c]));

let activeScanData = null;
let currentTabUrl = '';

// ==========================================================================
// URL Parsing Utilities
// ==========================================================================
function parseUrlMeta(rawUrl) {
  try {
    const formatted = rawUrl.includes('://') ? rawUrl : 'http://' + rawUrl;
    const u = new URL(formatted);
    const host = u.hostname.toLowerCase();
    const parts = host.split('.');
    const apex = parts.length >= 2 ? parts.slice(-2).join('.') : host;
    return {
      host: host || rawUrl,
      apex: apex || host || rawUrl,
      protocol: u.protocol.replace(':', '').toUpperCase(),
      isHttps: u.protocol === 'https:',
      path: u.pathname + (u.search || '')
    };
  } catch {
    const clean = String(rawUrl).replace(/^https?:\/\//i, '').split('/')[0];
    return { host: clean, apex: clean, protocol: 'URL', isHttps: false, path: '' };
  }
}

// ==========================================================================
// Tab Switching
// ==========================================================================
function setTab(tabId) {
  $$('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === tabId);
  });
  $$('.tab-panel').forEach(panel => {
    panel.style.display = panel.id === `tab-${tabId}` ? 'block' : 'none';
  });
}

$$('.tab-btn').forEach(btn => {
  btn.onclick = () => setTab(btn.dataset.tab);
});

// ==========================================================================
// Rendering Functions
// ==========================================================================

function renderVerdict(data) {
  const container = $('#verdict-container');
  if (!container) return;

  const { verdict, meta, features = [], risk = 0, flagCount = 0 } = data;
  const level = verdict.level || 'safe';

  const iconMap = {
    safe: '#icon-shield-check',
    warn: '#icon-shield-alert',
    bad: '#icon-shield-x'
  };

  const statusSubMap = {
    safe: 'Verified against known legitimate patterns. No impersonation markers found.',
    warn: 'Multiple irregular traits detected. Double-check before submitting logins.',
    bad: 'Dangerous URL structure typical of credential theft and phishing traps.'
  };

  const resolvedMeta = meta || parseUrlMeta(data.url || '');
  const apexDomain = resolvedMeta.apex || resolvedMeta.host || 'Current Link';

  container.innerHTML = `
    <div class="verdict-card ${level}">
      <div class="verdict-header">
        <div class="status-badge">
          <div class="status-icon-wrap">
            <svg class="svg-icon"><use href="${iconMap[level] || '#icon-shield'}"/></svg>
          </div>
          <div class="verdict-meta">
            <span class="verdict-title">${esc(verdict.title)}</span>
            <span class="verdict-source">AI Evaluation · ${verdict.source || 'ML Model'}</span>
          </div>
        </div>
        <div class="risk-pill">${risk}% Threat</div>
      </div>

      <!-- Animated Risk Meter Gauge -->
      <div class="risk-meter-wrapper">
        <div class="risk-meter-track">
          <div class="risk-meter-fill" id="meter-fill" style="width: 0%"></div>
        </div>
        <div class="risk-meter-labels">
          <span>0% Safe</span>
          <span>30% Caution</span>
          <span>60% Phishing</span>
          <span>100%</span>
        </div>
      </div>

      <p class="verdict-summary">${esc(verdict.summary || statusSubMap[level])}</p>

      <div class="action-card">
        <svg class="svg-icon"><use href="#icon-check"/></svg>
        <span>${esc(verdict.action || 'Always verify the domain in the browser address bar.')}</span>
      </div>
    </div>

    <!-- Quick Domain Inspection Breakdown -->
    <div class="domain-details-card">
      <div class="detail-row">
        <span class="detail-label">Apex Domain</span>
        <span class="detail-val" title="${esc(apexDomain)}">${esc(apexDomain)}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Security Protocol</span>
        <span class="detail-val">${esc(resolvedMeta.protocol || 'HTTPS')}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Structural Flags</span>
        <span class="detail-val" style="color: ${flagCount > 0 ? 'var(--warn-amber)' : 'var(--safe-green)'}">
          ${flagCount === 0 ? '✓ None (All traits normal)' : `${flagCount} threat signal(s)`}
        </span>
      </div>
    </div>
  `;

  // Animate the risk gauge smoothly
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const fill = $('#meter-fill');
      if (fill) fill.style.width = `${Math.max(4, Math.min(100, risk))}%`;
    });
  });

  // Update Signals Tab Badge
  const badge = $('#signals-badge');
  if (badge) {
    if (flagCount > 0) {
      badge.textContent = flagCount;
      badge.style.display = 'inline-block';
    } else {
      badge.style.display = 'none';
    }
  }

  // Render Signals List
  renderSignals(features);
}

function renderSignals(features = []) {
  const list = $('#signals-list');
  if (!list) return;

  if (!features || features.length === 0) {
    list.innerHTML = `
      <div class="signal-card">
        <span class="signal-note">No individual feature flags detected for this URL.</span>
      </div>
    `;
    return;
  }

  // Sort flagged features first so the user sees the warning signals immediately
  const sorted = [...features].sort((a, b) => (b.flag ? 1 : 0) - (a.flag ? 1 : 0));

  list.innerHTML = sorted.map(f => {
    const isFlag = Boolean(f.flag);
    return `
      <div class="signal-card ${isFlag ? 'flagged' : ''}">
        <div class="signal-top">
          <span class="signal-name">
            ${isFlag ? '<span class="flag-chip">⚠️ FLAG</span>' : '<span style="color:var(--safe-green)">✓</span>'}
            ${esc(f.label)}
          </span>
          <span class="signal-val">${esc(f.value)}</span>
        </div>
        <p class="signal-note">${esc(f.note)}</p>
      </div>
    `;
  }).join('');
}

function updateTargetBar(url, meta) {
  const chip = $('#proto-chip');
  const domain = $('#target-domain');

  const resolvedMeta = meta || parseUrlMeta(url);
  const isHttps = resolvedMeta.isHttps;
  chip.textContent = resolvedMeta.protocol || 'HTTP';
  chip.className = `protocol-chip ${isHttps ? 'https' : 'http'}`;
  domain.textContent = resolvedMeta.apex || resolvedMeta.host || url;
  domain.title = url;
}

function showLoading(show) {
  const loading = $('#state-loading');
  const panels = $$('.tab-panel');
  const offline = $('#state-offline');

  if (loading) loading.style.display = show ? 'flex' : 'none';
  if (offline) offline.style.display = 'none';

  panels.forEach(p => {
    if (show) p.style.display = 'none';
  });

  if (!show && offline?.style.display !== 'flex') {
    setTab('overview');
  }
}

function showOffline(title, errorText, isNoModel = false) {
  showLoading(false);
  $$('.tab-panel').forEach(p => (p.style.display = 'none'));
  const offline = $('#state-offline');
  if (offline) {
    offline.style.display = 'flex';
    $('.offline-title').textContent = title || 'Local AI Engine Offline';
    if (errorText) $('#offline-error-text').textContent = errorText;

    const retryBtn = $('#btn-retry-connect');
    if (isNoModel) {
      retryBtn.innerHTML = `
        <svg class="svg-icon sm"><use href="#icon-refresh"/></svg>
        <span>Connect Default Model</span>
      `;
      retryBtn.onclick = async () => {
        retryBtn.textContent = 'Connecting…';
        try {
          const res = await chrome.runtime.sendMessage({ type: 'load_default_model' });
          if (res && res.ok) {
            await pingServer();
            if (activeScanData?.url || currentTabUrl) {
              executeScan(activeScanData?.url || currentTabUrl);
            }
          } else {
            retryBtn.textContent = 'Retry Connect';
          }
        } catch {
          retryBtn.textContent = 'Retry Connect';
        }
      };
    } else {
      retryBtn.innerHTML = `
        <svg class="svg-icon sm"><use href="#icon-refresh"/></svg>
        <span>Retry Connection</span>
      `;
      retryBtn.onclick = () => {
        pingServer();
        if (activeScanData?.url || currentTabUrl) {
          executeScan(activeScanData?.url || currentTabUrl);
        }
      };
    }
  }
}

// ==========================================================================
// Execution Controller
// ==========================================================================

async function executeScan(url) {
  if (!url) return;
  const cleanUrl = url.trim();

  // Handle internal browser URLs gracefully without a fake 100% Threat Phishing card
  if (/^(chrome|edge|brave|opera|about|view-source|file):/i.test(cleanUrl)) {
    showLoading(false);
    const meta = { host: cleanUrl.split('/')[0], apex: cleanUrl.split('/')[0], protocol: 'INTERNAL', isHttps: true };
    updateTargetBar(cleanUrl, meta);
    renderVerdict({
      verdict: {
        level: 'safe',
        title: 'Browser System Page',
        summary: 'Browser internal settings and extension pages cannot be scanned for phishing threats.',
        action: 'Navigate to any web page or paste a link in the "Scan Link" tab to inspect it.',
        risk: 0,
        source: 'Browser Sandbox'
      },
      meta,
      features: [],
      risk: 0,
      flagCount: 0
    });
    return;
  }

  showLoading(true);

  try {
    const result = await chrome.runtime.sendMessage({ type: 'scan', url: cleanUrl });

    if (!result.ok) {
      if (result.noModel) {
        showOffline(
          'ML Model Not Loaded',
          'The local server is running on 127.0.0.1:8787, but no model is currently active.',
          true
        );
      } else if (result.offline) {
        showOffline(
          'Local AI Engine Offline',
          result.error || 'Cannot reach local server at http://127.0.0.1:8787. Make sure python run_server.py is running.',
          false
        );
      } else {
        showOffline('Scan Request Failed', result.error || 'Server rejected the inspection request.', false);
      }
      return;
    }

    activeScanData = result;
    showLoading(false);
    updateTargetBar(result.url, result.meta);
    renderVerdict(result);
  } catch (err) {
    showOffline('Connection Error', 'Could not communicate with Lurelock background worker.', false);
  }
}

// Check server connectivity for bottom footer
async function pingServer() {
  const dot = $('#footer-dot');
  const label = $('#footer-status');

  // Helper to test health directly or via background
  async function checkHealthDirect() {
    for (const base of ['http://127.0.0.1:8787', 'http://localhost:8787']) {
      try {
        const t0 = performance.now();
        const r = await fetch(`${base}/health`, { signal: AbortSignal.timeout(2000) });
        if (r.ok) {
          const j = await r.json().catch(() => ({}));
          const latency = Math.round(performance.now() - t0);
          return { online: Boolean(j.model_loaded), modelLoaded: Boolean(j.model_loaded), latency, error: null };
        }
      } catch {
        // try next
      }
    }
    return null;
  }

  try {
    let res = null;
    try {
      res = await chrome.runtime.sendMessage({ type: 'check_health' });
    } catch {
      // background worker may be asleep, fallback to direct fetch
    }

    if (!res) {
      res = await checkHealthDirect();
    }

    if (res && res.online) {
      dot.className = 'status-indicator online';
      const lat = res.latency ? ` · ${res.latency}ms` : '';
      label.textContent = `Model Online${lat}`;
      label.style.cursor = 'default';
      label.onclick = null;
    } else if (res && !res.modelLoaded && !res.error) {
      dot.className = 'status-indicator offline';
      label.textContent = 'No model loaded (Click to connect)';
      label.style.cursor = 'pointer';
      label.onclick = async () => {
        label.textContent = 'Loading model…';
        try {
          await chrome.runtime.sendMessage({ type: 'load_default_model' });
          await pingServer();
          if (activeScanData?.url || currentTabUrl) {
            executeScan(activeScanData?.url || currentTabUrl);
          }
        } catch {
          pingServer();
        }
      };
    } else {
      dot.className = 'status-indicator offline';
      label.textContent = 'Server offline';
      label.style.cursor = 'default';
      label.onclick = null;
    }
  } catch {
    dot.className = 'status-indicator offline';
    label.textContent = 'Server offline';
    label.style.cursor = 'default';
    label.onclick = null;
  }
}

// ==========================================================================
// Event Listeners & Initialization
// ==========================================================================

// Rescan current URL
$('#btn-rescan').onclick = () => {
  const btn = $('#btn-rescan');
  btn.classList.add('spinning');
  setTimeout(() => btn.classList.remove('spinning'), 800);
  if (activeScanData?.url) {
    executeScan(activeScanData.url);
  } else if (currentTabUrl) {
    executeScan(currentTabUrl);
  }
};

// Copy current URL
$('#btn-copy-url').onclick = async () => {
  const urlToCopy = activeScanData?.url || currentTabUrl;
  if (!urlToCopy) return;
  try {
    await navigator.clipboard.writeText(urlToCopy);
    const domainSpan = $('#target-domain');
    const original = domainSpan.textContent;
    domainSpan.textContent = '✓ Copied to clipboard!';
    setTimeout(() => { domainSpan.textContent = original; }, 1500);
  } catch {
    // fallback
  }
};

// Open Settings
const openSettings = (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
};
$('#btn-settings').onclick = openSettings;
$('#btn-open-options').onclick = openSettings;
$('#footer-options-link').onclick = openSettings;

// Custom Scan Tab form
$('#custom-scan-form').onsubmit = (e) => {
  e.preventDefault();
  const input = $('#custom-url-input');
  const url = input.value.trim();
  if (!url) return;
  executeScan(url);
};

// Paste from clipboard
$('#btn-paste').onclick = async () => {
  try {
    const text = await navigator.clipboard.readText();
    if (text) {
      $('#custom-url-input').value = text;
      executeScan(text);
    }
  } catch {
    $('#custom-url-input').focus();
  }
};

// Sample chips
$$('.chip-btn').forEach(btn => {
  btn.onclick = () => {
    const sample = btn.dataset.sample;
    if (sample) {
      $('#custom-url-input').value = sample;
      executeScan(sample);
    }
  };
});

// Switch back to active tab from right-click scan
$('#btn-return-tab').onclick = async () => {
  await chrome.runtime.sendMessage({ type: 'clear_pending' });
  $('#pending-notice').style.display = 'none';
  if (currentTabUrl) executeScan(currentTabUrl);
};

// ==========================================================================
// Bootstrap
// ==========================================================================
(async () => {
  await pingServer();

  // 1. Check if user scanned a link via right-click context menu
  try {
    const pending = await chrome.runtime.sendMessage({ type: 'get_pending' });
    if (pending && pending.result && pending.url) {
      $('#pending-notice').style.display = 'flex';
      activeScanData = pending.result;
      updateTargetBar(pending.url, pending.result.meta);
      renderVerdict(pending.result);
      return;
    }
  } catch (err) {
    // ignore
  }

  // 2. Otherwise scan the active tab
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url && /^https?:/i.test(tab.url)) {
      currentTabUrl = tab.url;
      updateTargetBar(tab.url, parseUrlMeta(tab.url));
      executeScan(tab.url);
    } else {
      updateTargetBar('No active web page', null);
      renderVerdict({
        verdict: {
          level: 'safe',
          title: 'Ready to Inspect',
          summary: 'Navigate to any website or paste a URL in the "Scan Link" tab to check its safety.',
          action: 'Lurelock runs completely locally — your URLs are never tracked or logged.',
          risk: 0,
          source: 'Lurelock Local'
        },
        meta: { host: 'lurelock', apex: 'lurelock', protocol: 'LOCAL' },
        features: [],
        risk: 0,
        flagCount: 0
      });
    }
  } catch (err) {
    showOffline('Initialization Error', 'Could not inspect the active browser tab.');
  }
})();
