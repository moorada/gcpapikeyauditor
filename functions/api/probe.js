const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

const ALLOWED_HOST = /^([a-z0-9-]+\.)*googleapis\.com$/i;

export function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestPost({ request }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ error: 'Invalid JSON body' }, { status: 400, headers: CORS });
  }

  const { url, method = 'GET', body: reqBody = null } = body;

  if (!url || typeof url !== 'string') {
    return Response.json({ error: 'Missing url' }, { status: 400, headers: CORS });
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return Response.json({ error: 'Invalid url' }, { status: 400, headers: CORS });
  }

  if (parsed.protocol !== 'https:' || !ALLOWED_HOST.test(parsed.hostname)) {
    return Response.json({ error: 'Host not allowed — only *.googleapis.com' }, { status: 403, headers: CORS });
  }

  const bodyStr = reqBody
    ? (typeof reqBody === 'string' ? reqBody : JSON.stringify(reqBody))
    : undefined;

  try {
    const upstream = await fetch(parsed.toString(), {
      method: method.toUpperCase(),
      headers: bodyStr ? { 'Content-Type': 'application/json' } : {},
      body: bodyStr,
    });

    const text = await upstream.text();
    return Response.json({ statusCode: upstream.status, text }, { headers: CORS });
  } catch (err) {
    return Response.json({ error: err.message }, { status: 502, headers: CORS });
  }
}
