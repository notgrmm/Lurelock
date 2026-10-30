(() => {
  const API = (localStorage.getItem('lurelock-api') || 'http://127.0.0.1:8787').replace(/\/$/, '');
  const $ = (s) => document.querySelector(s);
  const icon = (id) => `<svg><use href="#i-${id}"/></svg>`;
  const esc = (s) => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  /* theme */
  const root = document.documentElement;
  root.dataset.theme = localStorage.getItem('lurelock-theme') || 'dark';
  $('#theme').onclick = () => {
    root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('lurelock-theme', root.dataset.theme);
  };

  /* routing */
  const routes = ['home', 'download', 'about', 'contact'];
  function route() {
    const r = routes.includes(location.hash.slice(1)) ? location.hash.slice(1) : 'home';
    routes.forEach(n => $('#view-' + n).hidden = n !== r);
    document.querySelectorAll('[data-route]').forEach(a => a.classList.toggle('on', a.dataset.route === r));
    window.scrollTo(0, 0);
  }
  addEventListener('hashchange', route); route();

  /* API status */
  let online = false;
  async function ping() {
    try {
      const t = performance.now();
      const r = await fetch(API + '/health', { signal: AbortSignal.timeout(2500) });
      const j = await r.json();
      online = r.ok && j.model_loaded;
      $('#dot').className = online ? 'on' : 'off';
      $('#status-text').textContent = online ? `API connected · latency ${Math.round(performance.now() - t)}ms` : 'No model connected';
    } catch {
      online = false;
      $('#dot').className = 'off';
      $('#status-text').textContent = 'No model connected';
    }
  }
  ping(); setInterval(ping, 20000);

  /* scan — result comes entirely from the .joblib model loaded on the server */
  const VERDICTS = {
    safe: ['No warning signs', 'The model rates this URL as likely legitimate. No detector can guarantee a site is safe.'],
    warn: ['Some warning signs', 'The model sees some phishing-like patterns in this URL. These are signals, not proof.'],
    bad: ['Likely phishing', 'The model rates this URL as likely phishing. Avoid entering credentials and confirm the intended domain.']
  };

  function show(level, title, summary, risk, features) {
    const meter = risk == null ? '' : `<div class="meter"><i style="width:0" data-w="${Math.max(3, risk)}%"></i></div>`;
    const tag = risk == null ? '' : `<span class="tag">ML model · ${risk}% risk</span>`;
    const cell = (f) => `<div class="cell"><small>${esc(f.label)}${f.flag ? ' · ⚠' : ''}</small><b>${esc(f.value)}</b><p>${esc(f.note)}</p></div>`;
    const detail = !features || !features.length ? '' : `
        <div class="lab">Lexical &amp; structural features</div>
        <div class="grid">${features.map(cell).join('')}</div>
        <p class="note">These are the static URL traits the model learns from: length, subdomains, path depth, special characters, digits, host type, keywords and entropy. They explain the result but do not change it. Only the URL string was analysed: page content is not inspected, and shortened links hide their real destination until opened. Phishing tactics also change over time, so treat the result as a signal, not proof.</p>`;
    $('#result').innerHTML = `
      <div class="res ${level}">
        <div class="res-head">${icon(level === 'safe' ? 'shield-ok' : 'shield')}<h2>${esc(title)}</h2>${tag}</div>
        <p class="res-sum"${risk == null ? ' style="margin-bottom:0"' : ''}>${esc(summary)}</p>
        ${meter}${detail}
      </div>`;
    const m = $('.meter i');
    if (m) requestAnimationFrame(() => requestAnimationFrame(() => { m.style.width = m.dataset.w; }));
  }

  async function predict(url) {
    const r = await fetch(API + '/predict', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }), signal: AbortSignal.timeout(8000)
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'Model unavailable');
    return { p: Math.min(1, Math.max(0, Number(j.probability) || 0)), features: j.features || [] };
  }

  $('#scan-form').onsubmit = async (e) => {
    e.preventDefault();
    const url = $('#url').value.trim();
    const btn = $('#scan-btn');
    $('#hero').classList.add('scanned');
    $('#home-sub').hidden = false;
    $('#again').hidden = false;
    if (!url) { show('bad', 'Enter a link', 'Paste a full URL such as https://example.com.', null); return; }
    btn.disabled = true;
    try {
      const r = await predict(url);
      const p = Math.round(r.p * 100);
      const level = p >= 60 ? 'bad' : p >= 30 ? 'warn' : 'safe';
      show(level, VERDICTS[level][0], VERDICTS[level][1], p, r.features);
    } catch (err) {
      show('bad', 'No model connected', 'Start the Lurelock server and link a .joblib model or Hugging Face URL in the extension options. ' + (err.message || ''), null);
    }
    btn.disabled = false;
  };

  /* contact: opens the user's mail client (no backend) */
  $('#contact-form').onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    location.href = `mailto:hello@lurelock.app?subject=${encodeURIComponent(f.get('subject'))}&body=${encodeURIComponent(`${f.get('message')}\n\n— ${f.get('name')} (${f.get('email')})`)}`;
  };
})();

