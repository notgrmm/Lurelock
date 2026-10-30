/**
 * Lurelock - Background Service Worker
 * Handles tab scanning, context menus, badge indicators, and API communication.
 */
const DEFAULTS = { api: 'http://127.0.0.1:8787' };
const CANDIDATE_APIS = ['http://127.0.0.1:8787', 'http://localhost:8787'];

async function getApiCandidates() {
  const store = await chrome.storage.sync.get(DEFAULTS);
  const preferred = (store.api || DEFAULTS.api).replace(/\/+$/, '');
  const list = [preferred];
  for (const c of CANDIDATE_APIS) {
    if (!list.includes(c)) list.push(c);
  }
  return list;
}

async function requestApi(endpoint, options = {}, timeoutMs = 8000) {
  const candidates = await getApiCandidates();
  let lastErr = null;

  for (const base of candidates) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      const res = await fetch(`${base}${endpoint}`, {
        ...options,
        signal: controller.signal
      });
      clearTimeout(timer);
      chrome.storage.sync.set({ api: base }).catch(() => {});
      return { res, base, ok: true };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Cannot connect to local engine on 127.0.0.1:8787 or localhost:8787');
}

const VERDICTS = {
  safe: {
    title: 'Likely Legitimate',
    summary: 'The model identified no typical phishing signatures in this link structure.',
    action: 'Safe to browse. Always verify before entering sensitive credentials.',
    badge: '✓',
    color: '#10b981'
  },
  warn: {
    title: 'Suspicious URL Structure',
    summary: 'Contains irregular structural patterns frequently observed in phishing attacks.',
    action: 'Exercise caution. Confirm the true domain identity before logging in.',
    badge: '!',
    color: '#f59e0b'
  },
  bad: {
    title: 'High Risk Phishing Detected',
    summary: 'High probability of malicious impersonation, spoofing, or deceptive redirection.',
    action: 'Do not enter passwords, personal data, or credit card information here.',
    badge: '✕',
    color: '#f43f5e'
  }
};

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

async function scanUrl(url) {
  if (!url || typeof url !== 'string') {
    return { ok: false, error: 'Please enter a valid link.' };
  }
  const cleanUrl = url.trim();
  const meta = parseUrlMeta(cleanUrl);

  if (/^(chrome|edge|brave|opera|about|view-source|file):/i.test(cleanUrl)) {
    return {
      ok: false,
      isInternalPage: true,
      error: 'Browser internal pages cannot be scanned for phishing.',
      meta,
      url: cleanUrl
    };
  }

  try {
    const { res, base } = await requestApi('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: cleanUrl })
    }, 8000);

    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const isNoModel = res.status === 503 || String(data.error || '').toLowerCase().includes('no model');
      return {
        ok: false,
        error: data.error || (isNoModel ? 'No ML model loaded on local server.' : 'Server returned an error.'),
        noModel: isNoModel,
        offline: false,
        meta,
        url: cleanUrl,
        api: base
      };
    }

    const prob = Math.min(1, Math.max(0, Number(data.probability) || 0));
    const risk = Math.round(prob * 100);
    const level = risk >= 60 ? 'bad' : risk >= 30 ? 'warn' : 'safe';
    const vMeta = VERDICTS[level];
    const features = Array.isArray(data.features) ? data.features : [];
    const flagCount = features.filter(f => Boolean(f.flag)).length;

    return {
      ok: true,
      url: cleanUrl,
      meta,
      risk,
      probability: prob,
      level,
      flagCount,
      verdict: {
        level,
        title: vMeta.title,
        summary: vMeta.summary,
        action: vMeta.action,
        risk,
        source: 'XGBoost ML Pipeline'
      },
      features,
      api: base
    };
  } catch (err) {
    const isAbort = err.name === 'AbortError';
    return {
      ok: false,
      offline: true,
      meta,
      url: cleanUrl,
      error: isAbort
        ? 'Request timed out waiting for server response.'
        : 'Cannot connect to Lurelock engine on 127.0.0.1:8787 or localhost:8787. Make sure run_server.py is running.'
    };
  }
}

function updateBadge(tabId, level) {
  if (!tabId || !level || !VERDICTS[level]) return;
  const { badge, color } = VERDICTS[level];
  try {
    chrome.action.setBadgeText({ tabId, text: badge });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (err) {
    // Ignore if tab was already closed
  }
}

// Right-click context menu for scanning any link on a page
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'lurelock-scan-link',
    title: '🛡️ Scan link with Lurelock',
    contexts: ['link']
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== 'lurelock-scan-link' || !info.linkUrl) return;

  const result = await scanUrl(info.linkUrl);
  if (result.ok) {
    await chrome.storage.session.set({
      pendingScan: {
        url: info.linkUrl,
        result,
        timestamp: Date.now()
      }
    });
    if (tab && tab.id) {
      updateBadge(tab.id, result.level);
    }
    chrome.action.setBadgeText({ text: VERDICTS[result.level].badge });
    chrome.action.setBadgeBackgroundColor({ color: VERDICTS[result.level].color });
  }
});

// Auto-scan current page on navigation complete
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab?.url || !/^https?:/i.test(tab.url)) {
    return;
  }
  const result = await scanUrl(tab.url);
  if (result.ok) {
    updateBadge(tabId, result.level);
  }
});

// Message hub for popup and options pages
chrome.runtime.onMessage.addListener((request, _sender, sendResponse) => {
  if (request.type === 'scan') {
    scanUrl(request.url).then(sendResponse);
    return true;
  }

  if (request.type === 'get_pending') {
    chrome.storage.session.get('pendingScan').then(data => {
      sendResponse(data.pendingScan || null);
    });
    return true;
  }

  if (request.type === 'clear_pending') {
    chrome.storage.session.remove('pendingScan').then(() => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (request.type === 'load_default_model') {
    requestApi('/model', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'models/model.joblib' })
    }, 5000)
      .then(async ({ res, base }) => {
        const j = await res.json().catch(() => ({}));
        sendResponse({ ok: res.ok, modelLoaded: Boolean(j.model_loaded), source: j.source, error: j.error, api: base });
      })
      .catch((err) => {
        sendResponse({ ok: false, error: err.message });
      });
    return true;
  }

  if (request.type === 'check_health') {
    const t0 = performance.now();
    requestApi('/health', {}, 3000)
      .then(async ({ res, base }) => {
        const j = await res.json().catch(() => ({}));
        const latency = Math.round(performance.now() - t0);
        sendResponse({
          online: res.ok && j.model_loaded,
          modelLoaded: Boolean(j.model_loaded),
          source: j.source || null,
          error: j.error || null,
          api: base,
          latency
        });
      })
      .catch((err) => {
        sendResponse({
          online: false,
          modelLoaded: false,
          source: null,
          error: err.message,
          api: null,
          latency: null
        });
      });
    return true;
  }
});
