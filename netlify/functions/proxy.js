// Thin passthrough — all real work happens on the Railway stateful server
// Set RAILWAY_URL in Netlify environment variables to your Railway server URL
const https = require('https');
const http = require('http');

exports.handler = async (event) => {
  const RAILWAY_URL = process.env.RAILWAY_URL;

  if (!RAILWAY_URL) {
    return {
      statusCode: 500,
      body: 'RAILWAY_URL environment variable not set. Add it in Netlify site settings > Environment variables.',
    };
  }

  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
      },
      body: '',
    };
  }

  // Forward entire request to Railway server
  const params = new URLSearchParams(event.queryStringParameters || {});
  const railwayTarget = RAILWAY_URL.replace(/\/$/, '') + '/proxy?' + params.toString();

  return new Promise((resolve) => {
    try {
      const parsed = new URL(railwayTarget);
      const mod = parsed.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: event.httpMethod || 'GET',
        headers: {
          'Content-Type': event.headers?.['content-type'] || 'application/octet-stream',
        },
      };

      const req = mod.request(options, (res) => {
        const chunks = [];
        res.on('data', c => chunks.push(c));
        res.on('end', () => {
          const raw = Buffer.concat(chunks);
          const ct = (res.headers['content-type'] || '').toLowerCase();
          const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml') || ct.includes('svg');

          const headers = {};
          for (const [k, v] of Object.entries(res.headers)) {
            if (k.toLowerCase() === 'transfer-encoding') continue;
            headers[k] = Array.isArray(v) ? v.join(', ') : v;
          }

          resolve({
            statusCode: res.statusCode || 200,
            headers,
            body: isText ? raw.toString('utf8') : raw.toString('base64'),
            isBase64Encoded: !isText,
          });
        });
      });

      req.on('error', e => resolve({ statusCode: 500, body: 'Passthrough error: ' + e.message }));
      if (event.body) req.write(event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body);
      req.end();
    } catch(e) {
      resolve({ statusCode: 500, body: 'Error: ' + e.message });
    }
  });
};
