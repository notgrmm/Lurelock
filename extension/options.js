/**
 * Lurelock - Options & Settings Controller
 */

const $ = (s) => document.querySelector(s);
const DEF_API = 'http://127.0.0.1:8787';
const DEF_SRC = 'models/model.joblib';

async function updateLiveStatus(api) {
  const statusEl = $('#val-engine-status');
  const fileEl = $('#val-model-file');
  const latEl = $('#val-latency');

  statusEl.textContent = 'Testing connection…';
  statusEl.style.color = 'var(--text-muted)';
  fileEl.textContent = '—';
  latEl.textContent = '—';

  const candidates = [api, 'http://127.0.0.1:8787', 'http://localhost:8787'];
  for (const target of candidates) {
    const t0 = performance.now();
    try {
      const res = await fetch(`${target}/health`, { signal: AbortSignal.timeout(2500) });
      const data = await res.json().catch(() => ({}));
      const latency = Math.round(performance.now() - t0);

      if (res.ok && data.model_loaded) {
        statusEl.textContent = '● Online (Ready)';
        statusEl.style.color = 'var(--safe-green)';
        fileEl.textContent = data.source ? data.source.split(/[\\/]/).pop() : 'Default Model';
        latEl.textContent = `${latency} ms`;
        return { ok: true, activeApi: target };
      } else if (res.ok) {
        statusEl.textContent = '▲ Server Up · No Model Loaded';
        statusEl.style.color = 'var(--warn-amber)';
        fileEl.textContent = data.error || 'Check model path';
        latEl.textContent = `${latency} ms`;
        return { ok: false, activeApi: target };
      }
    } catch {
      // try next candidate
    }
  }

  statusEl.textContent = '○ Engine Offline';
  statusEl.style.color = 'var(--bad-rose)';
  fileEl.textContent = 'Cannot reach server';
  latEl.textContent = 'Timeout';
  return { ok: false, activeApi: api };
}

// Bootstrap
(async () => {
  const store = await chrome.storage.sync.get({ api: DEF_API, src: DEF_SRC });
  $('#api').value = store.api || DEF_API;
  $('#src').value = store.src || DEF_SRC;

  const result = await updateLiveStatus((store.api || DEF_API).replace(/\/+$/, ''));
  if (result.activeApi && result.activeApi !== $('#api').value) {
    $('#api').value = result.activeApi;
    chrome.storage.sync.set({ api: result.activeApi });
  }
})();

// Presets
$('#preset-joblib').onclick = () => {
  $('#src').value = 'models/model.joblib';
};

$('#preset-json').onclick = () => {
  $('#src').value = 'models/xgboost_model.json';
};

// Ping Test
$('#btn-test-conn').onclick = async () => {
  const api = ($('#api').value.trim() || DEF_API).replace(/\/+$/, '');
  const result = await updateLiveStatus(api);
  const msg = $('#save-status-msg');
  if (result.ok) {
    msg.className = 'status-message success';
    msg.textContent = '✓ Successfully connected to local server!';
  } else {
    msg.className = 'status-message error';
    msg.textContent = '✕ Could not reach model. Ensure python run_server.py is running.';
  }
  setTimeout(() => { msg.textContent = ''; }, 4000);
};

// Save & Connect Model
$('#btn-save').onclick = async () => {
  const api = ($('#api').value.trim() || DEF_API).replace(/\/+$/, '');
  const src = $('#src').value.trim() || DEF_SRC;
  const msg = $('#save-status-msg');

  msg.className = 'status-message';
  msg.textContent = 'Saving configuration & loading model…';

  await chrome.storage.sync.set({ api, src });

  try {
    const payload = { source: src };
    const res = await fetch(`${api}/model`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });
    const data = await res.json().catch(() => ({}));

    if (res.ok && data.model_loaded) {
      msg.className = 'status-message success';
      msg.textContent = `✓ Model loaded: ${data.source ? data.source.split(/[\\/]/).pop() : 'Active'}`;
    } else {
      msg.className = 'status-message error';
      msg.textContent = `Failed to load: ${data.error || 'Server error'}`;
    }
  } catch (err) {
    msg.className = 'status-message error';
    msg.textContent = 'Settings saved locally, but could not reach server. Start run_server.py to connect.';
  }

  updateLiveStatus(api);
  setTimeout(() => { msg.textContent = ''; }, 5000);
};
