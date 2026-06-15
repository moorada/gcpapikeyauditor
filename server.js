import express from 'express';
import { request as makeRequest } from 'https';

const app = express();
const PORT = process.env.PORT || 3001;

app.use(express.json({ limit: '100kb' }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const ALLOWED_HOSTS = /^([a-z0-9-]+\.)*googleapis\.com$/i;

app.get('/health', (req, res) => res.json({ ok: true }));

app.post('/probe', (req, res) => {
  const { url, method = 'GET', body = null, headers: extraHeaders = null } = req.body ?? {};

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Missing url' });
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid url' });
  }

  if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.test(parsed.hostname)) {
    return res.status(403).json({ error: 'Host not allowed — only *.googleapis.com' });
  }

  const bodyStr = body ? (typeof body === 'string' ? body : JSON.stringify(body)) : null;

  const options = {
    hostname: parsed.hostname,
    path: parsed.pathname + parsed.search,
    method: method.toUpperCase(),
    headers: {
      ...(bodyStr ? { 'Content-Type': 'application/json' } : {}),
      ...(extraHeaders || {}),
    },
  };

  const upstream = makeRequest(options, (upstream) => {
    const chunks = [];
    upstream.on('data', (c) => chunks.push(c));
    upstream.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf-8');
      res.json({ statusCode: upstream.statusCode, text });
    });
  });

  upstream.on('error', (err) => {
    if (!res.headersSent) res.status(502).json({ error: err.message });
  });

  if (bodyStr) upstream.write(bodyStr);
  upstream.end();
});

app.listen(PORT, '127.0.0.1', () => {
  console.log('\n  GCP API Key Auditor — proxy backend');
  console.log(`  Listening on http://127.0.0.1:${PORT}`);
  console.log('\n  Open index.html in your browser — backend mode activates automatically.\n');
});
