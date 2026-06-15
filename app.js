const form = document.getElementById('audit-form');
const input = document.getElementById('api-key');
const statusNode = document.getElementById('status');
const button = document.getElementById('analyze-btn');
const resultsNode = document.getElementById('results');
const summaryNode = document.getElementById('summary');
const apiResultsNode = document.getElementById('api-results');
const issuesNode = document.getElementById('issues');
const backendStatusNode = document.getElementById('backend-status');

// ── Backend detection ──────────────────────────────────
// Tries /api (Cloudflare Pages Functions or wrangler dev) then Node.js local backend.
const BACKEND_CANDIDATES = ['/api', 'http://127.0.0.1:3001'];
let backendAvailable = false;
let activeBackendUrl = null;
let discoveredProjectId = null;
let lastApiKey = null;

async function detectBackend() {
  for (const candidate of BACKEND_CANDIDATES) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      const res = await fetch(`${candidate}/health`, { signal: controller.signal });
      clearTimeout(timer);
      if (res.ok) {
        const data = await res.json();
        if (data.ok) {
          backendAvailable = true;
          activeBackendUrl = candidate;
          break;
        }
      }
    } catch {}
  }
  renderBackendStatus();
}

function renderBackendStatus() {
  if (!backendStatusNode) return;
  if (backendAvailable) {
    const isCloudflare = activeBackendUrl === '/api';
    const label = isCloudflare
      ? 'Cloudflare Worker connected — full probe coverage'
      : 'Local Node.js backend connected — full probe coverage';
    backendStatusNode.className = 'backend-status bs-on';
    backendStatusNode.innerHTML = `<span class="bs-dot"></span>${label}`;
  } else {
    backendStatusNode.className = 'backend-status bs-off';
    backendStatusNode.innerHTML =
      '<span class="bs-dot"></span>Client-only mode — Maps REST endpoints probed via JSONP'
      + ' <a class="bs-link" href="#backend-help">How to enable backend</a>';
  }
}

detectBackend();

// ── Request helpers ────────────────────────────────────

async function doRequest(url, options) {
  return backendAvailable ? doBackendRequest(url, options) : doDirectRequest(url, options);
}

async function doDirectRequest(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  let json = null;
  try { json = text ? JSON.parse(text) : null; } catch {}
  return { ok: response.ok, statusCode: response.status, body: json, text };
}

async function doBackendRequest(url, options) {
  const res = await fetch(`${activeBackendUrl}/probe`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url,
      method: options?.method || 'GET',
      body: options?.body ?? null,
    }),
  });
  if (!res.ok) throw new Error(`Backend error: ${res.status}`);
  const data = await res.json();
  let json = null;
  try { json = data.text ? JSON.parse(data.text) : null; } catch {}
  return {
    ok: data.statusCode >= 200 && data.statusCode < 300,
    statusCode: data.statusCode,
    body: json,
    text: data.text || '',
  };
}

// JSONP — client-side fallback for Maps REST APIs that block CORS.
// Maps Directions, Distance Matrix, Places support ?callback= for JSONP.
// Note: JSONP can't read the HTTP status code (always reports 200).
function doJsonpRequest(url, signal) {
  return new Promise((resolve, reject) => {
    const cbName = `__gcpauditor_${Date.now()}_${Math.random().toString(36).slice(2)}`;
    const script = document.createElement('script');
    let settled = false;

    const cleanup = () => {
      delete window[cbName];
      script.remove();
    };

    signal?.addEventListener('abort', () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new DOMException('Aborted', 'AbortError'));
    });

    window[cbName] = (data) => {
      if (settled) return;
      settled = true;
      cleanup();
      const text = JSON.stringify(data);
      resolve({ ok: true, statusCode: 200, body: data, text });
    };

    script.onerror = () => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error('JSONP request failed'));
    };

    script.src = `${url}&callback=${cbName}`;
    document.head.appendChild(script);
  });
}

// Helper: use backend if available, fall back to JSONP for Maps REST GET endpoints.
function doMapsRequest(url, signal) {
  if (backendAvailable) return doRequest(url, { method: 'GET', signal });
  return doJsonpRequest(url, signal);
}

// ── API test definitions ───────────────────────────────

const API_TESTS = [
  // ── Maps ──────────────────────────────────────────────
  {
    id: 'maps-geocoding',
    name: 'Maps Geocoding API',
    category: 'Maps',
    severity: 'high',
    impact: 'Large-scale geocoding abuse can generate substantial cost quickly.',
    pocMethod: 'GET',
    pocUrl: 'https://maps.googleapis.com/maps/api/geocode/json?address=rome&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(
        `https://maps.googleapis.com/maps/api/geocode/json?address=rome&key=${encodeURIComponent(key)}`,
        { method: 'GET', signal }
      ),
    parser: parseMapsStyleResponse,
  },
  {
    id: 'places-find',
    name: 'Places API',
    category: 'Maps',
    severity: 'high',
    impact: 'Place lookup and geodata extraction can consume high quota volumes.',
    pocMethod: 'GET',
    pocUrl: 'https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=milan&inputtype=textquery&fields=place_id&key={KEY}',
    pocBody: null,
    clientNote: 'JSONP',
    request: (key, signal) =>
      doMapsRequest(
        `https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=milan&inputtype=textquery&fields=place_id&key=${encodeURIComponent(key)}`,
        signal
      ),
    parser: parseMapsStyleResponse,
  },
  {
    id: 'maps-directions',
    name: 'Maps Directions API',
    category: 'Maps',
    severity: 'medium',
    impact: 'Route calculation at scale generates sustained billable Maps API traffic.',
    pocMethod: 'GET',
    pocUrl: 'https://maps.googleapis.com/maps/api/directions/json?origin=rome&destination=milan&key={KEY}',
    pocBody: null,
    clientNote: 'JSONP',
    request: (key, signal) =>
      doMapsRequest(
        `https://maps.googleapis.com/maps/api/directions/json?origin=rome&destination=milan&key=${encodeURIComponent(key)}`,
        signal
      ),
    parser: parseMapsStyleResponse,
  },
  {
    id: 'maps-distance-matrix',
    name: 'Maps Distance Matrix API',
    category: 'Maps',
    severity: 'medium',
    impact: 'Matrix calculations over large origin/destination sets generate high spend.',
    pocMethod: 'GET',
    pocUrl: 'https://maps.googleapis.com/maps/api/distancematrix/json?origins=rome&destinations=milan&key={KEY}',
    pocBody: null,
    clientNote: 'JSONP',
    request: (key, signal) =>
      doMapsRequest(
        `https://maps.googleapis.com/maps/api/distancematrix/json?origins=rome&destinations=milan&key=${encodeURIComponent(key)}`,
        signal
      ),
    parser: parseMapsStyleResponse,
  },
  // ── AI / ML ───────────────────────────────────────────
  {
    id: 'gemini',
    name: 'Gemini API',
    category: 'AI',
    severity: 'high',
    impact: 'AI model inference can be very expensive and exposes generative AI capabilities.',
    pocMethod: 'GET',
    pocUrl: 'https://generativelanguage.googleapis.com/v1/models?key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(`https://generativelanguage.googleapis.com/v1/models?key=${encodeURIComponent(key)}`, {
        method: 'GET',
        signal,
      }),
  },
  {
    id: 'vision',
    name: 'Cloud Vision API',
    category: 'AI',
    severity: 'high',
    impact: 'Image analysis endpoints can be abused for billable inference calls.',
    pocMethod: 'POST',
    pocUrl: 'https://vision.googleapis.com/v1/images:annotate?key={KEY}',
    pocBody: '{"requests":[]}',
    request: (key, signal) =>
      doRequest(`https://vision.googleapis.com/v1/images:annotate?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({ requests: [] }),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
  {
    id: 'translate',
    name: 'Cloud Translation API',
    category: 'AI',
    severity: 'high',
    impact: 'Automated translation traffic can create recurring cost spikes.',
    pocMethod: 'GET',
    pocUrl: 'https://translation.googleapis.com/language/translate/v2/languages?target=en&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(
        `https://translation.googleapis.com/language/translate/v2/languages?target=en&key=${encodeURIComponent(key)}`,
        { method: 'GET', signal }
      ),
  },
  {
    id: 'natural-language',
    name: 'Cloud Natural Language API',
    category: 'AI',
    severity: 'medium',
    impact: 'NLP text analysis can be abused for large-scale automated content processing.',
    pocMethod: 'POST',
    pocUrl: 'https://language.googleapis.com/v1/documents:analyzeEntities?key={KEY}',
    pocBody: '{"document":{"type":"PLAIN_TEXT","content":"test"},"encodingType":"UTF8"}',
    request: (key, signal) =>
      doRequest(`https://language.googleapis.com/v1/documents:analyzeEntities?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({ document: { type: 'PLAIN_TEXT', content: 'test' }, encodingType: 'UTF8' }),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
  {
    id: 'text-to-speech',
    name: 'Cloud Text-to-Speech API',
    category: 'AI',
    severity: 'medium',
    impact: 'Voice synthesis can be abused for spam generation and billable audio rendering.',
    pocMethod: 'GET',
    pocUrl: 'https://texttospeech.googleapis.com/v1/voices?key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(`https://texttospeech.googleapis.com/v1/voices?key=${encodeURIComponent(key)}`, {
        method: 'GET',
        signal,
      }),
  },
  {
    id: 'speech-to-text',
    name: 'Cloud Speech-to-Text API',
    category: 'AI',
    severity: 'medium',
    impact: 'Unauthorized transcription can drain audio processing quota at scale.',
    pocMethod: 'POST',
    pocUrl: 'https://speech.googleapis.com/v1/speech:recognize?key={KEY}',
    pocBody: '{"config":{"encoding":"LINEAR16","sampleRateHertz":16000,"languageCode":"en-US"},"audio":{"content":""}}',
    request: (key, signal) =>
      doRequest(`https://speech.googleapis.com/v1/speech:recognize?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({
          config: { encoding: 'LINEAR16', sampleRateHertz: 16000, languageCode: 'en-US' },
          audio: { content: '' },
        }),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
  // ── Location ──────────────────────────────────────────
  {
    id: 'geolocation',
    name: 'Geolocation API',
    category: 'Location',
    severity: 'high',
    impact: 'Geolocation calls may leak location intelligence and incur high spend.',
    pocMethod: 'POST',
    pocUrl: 'https://www.googleapis.com/geolocation/v1/geolocate?key={KEY}',
    pocBody: '{}',
    request: (key, signal) =>
      doRequest(`https://www.googleapis.com/geolocation/v1/geolocate?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({}),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
  // ── Auth ──────────────────────────────────────────────
  {
    id: 'identity-toolkit',
    name: 'Identity Toolkit API',
    category: 'Auth',
    severity: 'high',
    impact: 'Sign-up or auth endpoint abuse can enable account spam and enumeration.',
    pocMethod: 'POST',
    pocUrl: 'https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={KEY}',
    pocBody: '{"returnSecureToken":true}',
    request: (key, signal) =>
      doRequest(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({ returnSecureToken: true }),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
  // ── Media ─────────────────────────────────────────────
  {
    id: 'youtube-data',
    name: 'YouTube Data API v3',
    category: 'Media',
    severity: 'medium',
    impact: 'Video/channel metadata scraping can drain daily quotas.',
    pocMethod: 'GET',
    pocUrl: 'https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=1&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(
        `https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&type=video&maxResults=1&key=${encodeURIComponent(key)}`,
        { method: 'GET', signal }
      ),
  },
  {
    id: 'books',
    name: 'Google Books API',
    category: 'Media',
    severity: 'low',
    impact: 'Books metadata scraping can be used for automated content indexing.',
    pocMethod: 'GET',
    pocUrl: 'https://www.googleapis.com/books/v1/volumes?q=test&maxResults=1&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(`https://www.googleapis.com/books/v1/volumes?q=test&maxResults=1&key=${encodeURIComponent(key)}`, {
        method: 'GET',
        signal,
      }),
  },
  // ── Search ────────────────────────────────────────────
  {
    id: 'custom-search',
    name: 'Custom Search API',
    category: 'Search',
    severity: 'medium',
    impact: 'Programmatic search queries can be abused for scraping workloads.',
    pocMethod: 'GET',
    pocUrl: 'https://customsearch.googleapis.com/customsearch/v1?q=test&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(`https://customsearch.googleapis.com/customsearch/v1?q=test&key=${encodeURIComponent(key)}`, {
        method: 'GET',
        signal,
      }),
  },
  {
    id: 'knowledge-graph',
    name: 'Knowledge Graph Search API',
    category: 'Search',
    severity: 'low',
    impact: 'Entity search can be abused for automated knowledge extraction at scale.',
    pocMethod: 'GET',
    pocUrl: 'https://kgsearch.googleapis.com/v1/entities:search?query=test&limit=1&key={KEY}',
    pocBody: null,
    request: (key, signal) =>
      doRequest(`https://kgsearch.googleapis.com/v1/entities:search?query=test&limit=1&key=${encodeURIComponent(key)}`, {
        method: 'GET',
        signal,
      }),
  },
  // ── Firebase ──────────────────────────────────────────
  {
    id: 'firebase-dynamic-links',
    name: 'Firebase Dynamic Links API',
    category: 'Firebase',
    severity: 'medium',
    impact: 'Dynamic link generation can be repurposed for spam or phishing funnels.',
    pocMethod: 'POST',
    pocUrl: 'https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key={KEY}',
    pocBody: '{"dynamicLinkInfo":{"domainUriPrefix":"https://example.page.link","link":"https://example.com"}}',
    request: (key, signal) =>
      doRequest(`https://firebasedynamiclinks.googleapis.com/v1/shortLinks?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        signal,
        body: JSON.stringify({
          dynamicLinkInfo: { domainUriPrefix: 'https://example.page.link', link: 'https://example.com' },
        }),
        headers: { 'Content-Type': 'application/json' },
      }),
  },
];

function buildProjectTests(projectId) {
  return [
    {
      id: 'storage-buckets',
      name: 'Cloud Storage (Bucket List)',
      category: 'Storage',
      severity: 'high',
      impact: 'Bucket enumeration exposes storage structure and may enable unauthorized data access.',
      pocMethod: 'GET',
      pocUrl: `https://storage.googleapis.com/storage/v1/b?project=${projectId}&key={KEY}`,
      pocBody: null,
      request: (key, signal) =>
        doRequest(
          `https://storage.googleapis.com/storage/v1/b?project=${encodeURIComponent(projectId)}&key=${encodeURIComponent(key)}`,
          { method: 'GET', signal }
        ),
    },
    {
      id: 'pubsub-topics',
      name: 'Pub/Sub Topic List',
      category: 'Infrastructure',
      severity: 'high',
      impact: 'Topic enumeration reveals messaging infrastructure and potential data ingestion pipelines.',
      pocMethod: 'GET',
      pocUrl: `https://pubsub.googleapis.com/v1/projects/${projectId}/topics?key={KEY}`,
      pocBody: null,
      request: (key, signal) =>
        doRequest(
          `https://pubsub.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/topics?key=${encodeURIComponent(key)}`,
          { method: 'GET', signal }
        ),
    },
  ];
}

// ── Utilities ──────────────────────────────────────────

function extractProjectId(text) {
  if (!text) return null;
  const m = text.match(/\bproject[/=\s]+(\d{10,14})\b/i);
  return m ? m[1] : null;
}

function maskKey(key) {
  if (!key) return '***';
  return key.slice(0, 8) + '•••';
}

function highlightBody(text, key) {
  if (!text) return '<em style="opacity:.5">no response body</em>';

  let body = text.length > 3000 ? text.slice(0, 3000) + '\n…[truncated]' : text;
  try { body = JSON.stringify(JSON.parse(body), null, 2); } catch {}

  body = escapeHtml(body);

  if (key) {
    const safeKey = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    body = body.replace(new RegExp(safeKey, 'g'), maskKey(key));
  }

  body = body.replace(
    /\b(API_KEY_SERVICE_BLOCKED|REQUEST_DENIED|PERMISSION_DENIED|SERVICE_DISABLED|INVALID_KEY|ACCESS_DENIED)\b/g,
    '<mark class="hl-danger">$&</mark>'
  );
  body = body.replace(/\b(OK|ZERO_RESULTS|INVALID_REQUEST)\b/g, '<mark class="hl-ok">$&</mark>');
  body = body.replace(/\b(\d{10,14})\b/g, '<mark class="hl-warn">$&</mark>');

  return body;
}

// ── Main audit flow ────────────────────────────────────

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  const apiKey = input.value.trim();
  if (!isLikelyGoogleApiKey(apiKey)) {
    paintStatus('Invalid key format. It should start with AIza and have a plausible length.', 'error');
    hideResults();
    return;
  }

  button.disabled = true;
  discoveredProjectId = null;
  lastApiKey = apiKey;
  hideResults();
  paintStatus('Starting exposure analysis...', 'info');

  try {
    const output = [];

    for (let i = 0; i < API_TESTS.length; i += 1) {
      const test = API_TESTS[i];
      paintStatus(`[${i + 1}/${API_TESTS.length}+] Testing ${test.name}...`, 'info');
      const result = await runTest(test, apiKey);
      output.push(result);
    }

    if (discoveredProjectId) {
      const projectTests = buildProjectTests(discoveredProjectId);
      const grandTotal = API_TESTS.length + projectTests.length;

      for (let i = 0; i < projectTests.length; i += 1) {
        const test = projectTests[i];
        paintStatus(`[${API_TESTS.length + i + 1}/${grandTotal}] ${test.name} (project scan)...`, 'info');
        const result = await runTest(test, apiKey);
        output.push(result);
      }
    }

    const report = buildReport(output);
    renderReport(output, report);
    paintStatus('Analysis completed.', 'ok');
  } catch (error) {
    paintStatus(`Unexpected analysis error: ${error.message}`, 'error');
    hideResults();
  } finally {
    button.disabled = false;
  }
});

function isLikelyGoogleApiKey(value) {
  return /^AIza[0-9A-Za-z-_]{16,}$/.test(value);
}

async function runTest(test, apiKey) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);

  try {
    const raw = await test.request(apiKey, controller.signal);

    if (!discoveredProjectId && raw.text) {
      const found = extractProjectId(raw.text);
      if (found) discoveredProjectId = found;
    }

    const parsed = test.parser ? test.parser(raw) : parseGoogleStyleResponse(raw);
    return { test, ...parsed, raw };
  } catch (error) {
    if (error.name === 'AbortError') {
      return { test, status: 'unknown', severity: 'low', summary: 'Request timeout', details: 'The endpoint did not respond before the timeout.', raw: null };
    }
    return { test, status: 'unknown', severity: 'low', summary: 'Blocked by CORS or network policy', details: error.message, raw: null };
  } finally {
    clearTimeout(timeout);
  }
}

// ── Response parsers ───────────────────────────────────

function parseMapsStyleResponse(raw) {
  if (!raw.body) return parseGoogleStyleResponse(raw);

  const body = raw.body;

  if (body.status === 'OK' || body.status === 'ZERO_RESULTS' || body.status === 'INVALID_REQUEST') {
    return { status: 'accessible', severity: 'high', summary: 'Endpoint reachable with this key', details: `Maps response: ${body.status}` };
  }

  if (body.status === 'OVER_DAILY_LIMIT' || body.status === 'OVER_QUERY_LIMIT') {
    return { status: 'accessible', severity: 'high', summary: 'Endpoint reachable but quota/billing constrained', details: safeText(body.error_message || body.status) };
  }

  if (body.status === 'REQUEST_DENIED') {
    return classifyFromMessage(body.error_message || 'REQUEST_DENIED', raw.statusCode);
  }

  return parseGoogleStyleResponse(raw);
}

function parseGoogleStyleResponse(raw) {
  if (!raw.body) {
    if (raw.ok) return { status: 'accessible', severity: 'medium', summary: 'Endpoint reachable', details: `HTTP ${raw.statusCode}` };
    return { status: 'unknown', severity: 'low', summary: 'Non-JSON response could not be interpreted', details: `HTTP ${raw.statusCode}` };
  }

  const error = raw.body.error;
  if (!error) {
    return { status: 'accessible', severity: 'medium', summary: 'Endpoint reachable with this key', details: `HTTP ${raw.statusCode}` };
  }

  const reasons = collectReasons(error);
  const message = `${error.message || ''} ${reasons.join(' ')}`.trim();
  return classifyFromMessage(message, raw.statusCode, reasons);
}

function collectReasons(error) {
  if (!error.details || !Array.isArray(error.details)) return [];
  return error.details.filter((d) => d && typeof d.reason === 'string').map((d) => d.reason);
}

function classifyFromMessage(message, statusCode, reasons = []) {
  const text = `${message} ${reasons.join(' ')}`.toLowerCase();

  if (text.includes('api key not valid') || text.includes('api_key_invalid') || text.includes('badrequest')) {
    return { status: 'invalid', severity: 'high', summary: 'API key appears invalid', details: safeText(message) };
  }

  if (
    text.includes('api_key_http_referrer_blocked') || text.includes('api_key_ip_address_blocked') ||
    text.includes('api_key_android_app_blocked') || text.includes('api_key_ios_app_blocked') ||
    text.includes('requests from referer') || text.includes('requests from referrer') ||
    text.includes('referer') || text.includes('referrer')
  ) {
    return { status: 'restricted', severity: 'low', summary: 'Blocked by API key restrictions', details: safeText(message) };
  }

  if (text.includes('api_key_service_blocked') || text.includes('are blocked')) {
    return { status: 'not_enabled', severity: 'low', summary: 'API service blocked for this key', details: safeText(message) };
  }

  if (
    text.includes('not been used in project') || text.includes('is disabled') ||
    text.includes('not enabled') || text.includes('not activated') ||
    text.includes('not authorized to use this api')
  ) {
    return { status: 'not_enabled', severity: 'low', summary: 'API is not enabled in the target project', details: safeText(message) };
  }

  if (text.includes('billing')) {
    return { status: 'billing', severity: 'medium', summary: 'Billing or quota dependency detected', details: safeText(message) };
  }

  if (statusCode >= 400 && statusCode < 500) {
    if (text.includes('missing') || text.includes('required') || text.includes('invalid argument') || text.includes('request')) {
      return { status: 'accessible', severity: 'medium', summary: 'Endpoint reached: request-level error indicates key acceptance', details: safeText(message) };
    }
    return { status: 'unknown', severity: 'low', summary: 'Client error was not conclusive', details: safeText(message) };
  }

  if (statusCode >= 500) {
    return { status: 'unknown', severity: 'low', summary: 'Remote server error', details: `HTTP ${statusCode}` };
  }

  return { status: 'accessible', severity: 'medium', summary: 'Endpoint reachable', details: safeText(message || `HTTP ${statusCode}`) };
}

// ── Report building ────────────────────────────────────

function buildReport(results) {
  const count = (status) => results.filter((r) => r.status === status).length;
  const accessible = count('accessible');
  const restricted = count('restricted');
  const notEnabled = count('not_enabled');
  const billing = count('billing');
  const unknown = count('unknown');
  const invalid = count('invalid');

  const issues = [];

  if (invalid > 0) {
    issues.push({ level: 'high', title: 'The key appears invalid or already revoked', detail: 'Probe responses indicate key validity errors. Confirm typo, rotation status, or key lifecycle changes.' });
  }

  if (accessible > 0) {
    const highImpact = results.filter((r) => r.status === 'accessible' && r.test.severity === 'high');
    if (highImpact.length > 0) {
      issues.push({ level: 'high', title: `${highImpact.length} high-impact ${highImpact.length === 1 ? 'API is' : 'APIs are'} reachable`, detail: 'Exposed usage of these APIs can rapidly trigger unauthorized billable traffic if the key leaks publicly.' });
    }
    issues.push({ level: 'medium', title: `Observed active surface: ${accessible}/${results.length} endpoints`, detail: 'The key is usable from this browser context. Weak referrer/IP/app constraints increase unauthorized usage risk.' });
  }

  if (billing > 0) {
    issues.push({ level: 'medium', title: 'Billing or quota-linked endpoints detected', detail: 'Abuse can translate into direct spend and service degradation from quota exhaustion.' });
  }

  if (restricted === 0 && accessible > 0) {
    issues.push({ level: 'high', title: 'No strong restriction enforcement signal observed', detail: 'If this result is confirmed from multiple origins, the key may be overly permissive and should be tightened.' });
  }

  if (discoveredProjectId) {
    issues.push({ level: 'info', title: `Project ID disclosed: ${discoveredProjectId}`, detail: 'The numeric project ID was leaked via error responses. Google considers this semi-public, but it aids further reconnaissance and was used to automatically add project-scoped probes.' });
  }

  if (unknown > 0) {
    issues.push({ level: 'info', title: 'Some probes were inconclusive', detail: `${unknown} probe${unknown === 1 ? '' : 's'} could not be completed due to CORS or network restrictions. Run with backend for full coverage.` });
  }

  if (notEnabled > 0) {
    issues.push({ level: 'info', title: `${notEnabled} ${notEnabled === 1 ? 'API is' : 'APIs are'} not enabled or blocked`, detail: 'This reduces the exposed surface but does not replace strict key restrictions.' });
  }

  return {
    risk: calculateGlobalRisk(results, issues),
    issues,
    totals: { accessible, restricted, notEnabled, billing, unknown, invalid },
  };
}

function calculateGlobalRisk(results, issues) {
  if (issues.some((i) => i.level === 'high')) return 'high';
  if (results.filter((r) => r.status === 'accessible').length >= 2) return 'medium';
  return 'low';
}

// ── Rendering ──────────────────────────────────────────

const SEVERITY_RANK = { high: 0, medium: 1, low: 2 };

function effectiveSeverity(result) {
  if (result.status === 'accessible') return result.test.severity;
  if (result.status === 'invalid') return 'high';
  return result.severity;
}

function renderReport(results, report) {
  const riskLabel = { high: 'High Risk', medium: 'Medium Risk', low: 'Low Risk' }[report.risk];

  const parts = [
    `<div class="risk-headline ${report.risk}">${riskLabel}</div>`,
    `<div class="risk-stats">`,
    `<span>${report.totals.accessible} reachable</span>`,
    `<span>${report.totals.restricted} restricted</span>`,
    `<span>${report.totals.notEnabled} not enabled</span>`,
    `<span>${report.totals.unknown} unknown</span>`,
    `</div>`,
  ];

  if (discoveredProjectId) {
    parts.push(`
      <div class="pid-alert">
        <span class="pid-label">PROJECT ID DISCLOSED</span>
        <code class="pid-value">${escapeHtml(discoveredProjectId)}</code>
        <span class="pid-desc">Leaked via error responses — project-scoped probes were automatically added.</span>
      </div>
    `);
  }

  parts.push(`<p class="note">100% client-side analysis — cannot read internal GCP key policy without IAM/OAuth access.</p>`);
  summaryNode.innerHTML = parts.join('');

  const sorted = [...results].sort(
    (a, b) => (SEVERITY_RANK[effectiveSeverity(a)] ?? 2) - (SEVERITY_RANK[effectiveSeverity(b)] ?? 2)
  );

  apiResultsNode.innerHTML = '';
  for (const result of sorted) {
    const sev = effectiveSeverity(result);
    const sevLabel = { high: 'HIGH', medium: 'MED', low: 'LOW' }[sev] ?? 'LOW';
    const li = document.createElement('li');
    li.className = `api-item ${sev}`;

    const pocUrl = result.test.pocUrl.replace('{KEY}', maskKey(lastApiKey));
    const pocMethod = result.test.pocMethod || 'GET';
    const pocBody = result.test.pocBody || null;
    const isJsonp = !backendAvailable && result.test.clientNote === 'JSONP';
    const isBackend = backendAvailable;

    const transportBadge = isBackend
      ? '<span class="transport-badge tb-backend">via backend</span>'
      : isJsonp
        ? '<span class="transport-badge tb-jsonp">via JSONP</span>'
        : '';

    let rawSection = '';
    if (result.raw) {
      rawSection = `
        <div class="raw-row">
          <span class="raw-label">RESPONSE</span>
          <span class="raw-val">${escapeHtml(String(result.raw.statusCode))}${isJsonp ? ' <em class="raw-note">(JSONP — status always 200)</em>' : ''}</span>
        </div>
        <div class="raw-row raw-row-pre">
          <span class="raw-label">DATA</span>
          <pre class="raw-pre">${highlightBody(result.raw.text, lastApiKey)}</pre>
        </div>
      `;
    } else {
      rawSection = `
        <div class="raw-row">
          <span class="raw-label">RESPONSE</span>
          <span class="raw-val raw-blocked">Could not connect — CORS or network error</span>
        </div>
      `;
    }

    const bodySection = pocBody
      ? `<div class="raw-row"><span class="raw-label">BODY</span><code class="raw-val">${escapeHtml(pocBody)}</code></div>`
      : '';

    li.innerHTML = `
      <div class="api-head">
        <span class="api-sev ${sev}">${sevLabel}</span>
        <span class="api-name">${escapeHtml(result.test.name)}</span>
        <span class="api-cat">${escapeHtml(result.test.category)}</span>
        <span class="api-status ${sev}">${labelForStatus(result.status)}</span>
      </div>
      <div class="api-impact">${escapeHtml(result.test.impact)}</div>
      <div class="api-finding">${escapeHtml(result.summary)}${result.details ? ` — ${escapeHtml(result.details)}` : ''}</div>
      <details class="api-raw">
        <summary><span class="raw-arrow">▶</span> Details &amp; PoC ${transportBadge}</summary>
        <div class="raw-panel">
          <div class="raw-row">
            <span class="raw-label">REQUEST</span>
            <code class="raw-val">${escapeHtml(pocMethod)} ${escapeHtml(pocUrl)}</code>
          </div>
          ${bodySection}
          ${rawSection}
        </div>
      </details>
    `;
    apiResultsNode.appendChild(li);
  }

  issuesNode.innerHTML = '';
  const issuesToShow = report.issues.length > 0 ? report.issues : [{ level: 'info', title: 'No major issue detected', detail: 'No high-risk finding emerged from this run.' }];
  for (const issue of issuesToShow) {
    const li = document.createElement('li');
    li.className = issue.level;
    li.innerHTML = `
      <div class="issue-row ${issue.level}">
        <span class="issue-level">${issue.level.toUpperCase()}</span>
        <span class="issue-title">${escapeHtml(issue.title)}</span>
      </div>
      <div class="issue-detail">${escapeHtml(issue.detail)}</div>
    `;
    issuesNode.appendChild(li);
  }

  // Backend help section (only in client-only mode)
  renderBackendHelp();

  resultsNode.classList.remove('hidden');
}

function renderBackendHelp() {
  const existing = document.getElementById('backend-help');
  if (existing) existing.remove();
  if (backendAvailable) return;

  const div = document.createElement('div');
  div.id = 'backend-help';
  div.className = 'backend-help';
  div.innerHTML = `
    <h2>Run with backend for full coverage</h2>
    <p>Some probes are blocked by browser CORS policy. A backend proxy removes this constraint — your API key never leaves your environment.</p>
    <h3 class="help-heading">Option A — Cloudflare Pages (recommended)</h3>
    <div class="help-steps">
      <div class="help-step"><span class="step-num">1</span><code>npm install</code></div>
      <div class="help-step"><span class="step-num">2</span><code>npm run deploy</code></div>
      <div class="help-step"><span class="step-num">3</span>Open the deployed Cloudflare Pages URL — Worker activates automatically</div>
    </div>
    <h3 class="help-heading">Option B — Local dev with Wrangler</h3>
    <div class="help-steps">
      <div class="help-step"><span class="step-num">1</span><code>npm install</code></div>
      <div class="help-step"><span class="step-num">2</span><code>npm run dev</code></div>
      <div class="help-step"><span class="step-num">3</span>Open <code>localhost:8787</code> in this browser — backend activates automatically</div>
    </div>
    <h3 class="help-heading">Option C — Local Node.js</h3>
    <div class="help-steps">
      <div class="help-step"><span class="step-num">1</span><code>npm install</code></div>
      <div class="help-step"><span class="step-num">2</span><code>npm start</code></div>
      <div class="help-step"><span class="step-num">3</span>Reload this page — backend activates automatically</div>
    </div>
    <p class="note">The proxy only accepts requests to <code>*.googleapis.com</code>. Your API key is never sent to any third-party service.</p>
  `;
  resultsNode.appendChild(div);
}

function hideResults() {
  resultsNode.classList.add('hidden');
  summaryNode.innerHTML = '';
  apiResultsNode.innerHTML = '';
  issuesNode.innerHTML = '';
  const help = document.getElementById('backend-help');
  if (help) help.remove();
}

function labelForStatus(status) {
  return { accessible: 'Reachable', restricted: 'Restricted', not_enabled: 'Not enabled', billing: 'Billing/Quota', invalid: 'Invalid key', unknown: 'Unknown' }[status] || status;
}

function paintStatus(text, level) {
  statusNode.textContent = text;
  statusNode.style.color = level === 'error' ? 'var(--danger)' : level === 'ok' ? 'var(--ok)' : 'var(--muted)';
}

function safeText(value) {
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function escapeHtml(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}
