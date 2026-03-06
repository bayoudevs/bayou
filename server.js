const https = require('https');
const http = require('http');
const zlib = require('zlib');
const { createServer } = require('http');

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// ── In-memory cookie jar keyed by session ID ──────────────────────────────
// { sessionId: { hostname: { cookieName: cookieValue } } }
const sessions = {};

function getSession(sid) {
  if (!sessions[sid]) sessions[sid] = {};
  return sessions[sid];
}

function getCookiesForHost(sid, host) {
  const sess = getSession(sid);
  // Also include parent domain cookies e.g. .instagram.com for www.instagram.com
  const parts = host.split('.');
  const parent = parts.length > 2 ? parts.slice(-2).join('.') : host;
  const jar = { ...(sess[parent] || {}), ...(sess[host] || {}) };
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

function storeCookies(sid, host, setCookieHeaders) {
  const sess = getSession(sid);
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  cookies.forEach(c => {
    if (!c) return;
    const parts = c.split(';').map(s => s.trim());
    const [nameVal] = parts;
    const eq = nameVal.indexOf('=');
    if (eq < 0) return;
    const name = nameVal.slice(0, eq).trim();
    const value = nameVal.slice(eq + 1).trim();

    // Find domain directive
    let cookieHost = host;
    const domainPart = parts.find(p => p.toLowerCase().startsWith('domain='));
    if (domainPart) {
      cookieHost = domainPart.split('=')[1].replace(/^\./, '').trim();
    }

    if (!sess[cookieHost]) sess[cookieHost] = {};
    sess[cookieHost][name] = value;
  });
}

// Clean up old sessions every 30 minutes (memory hygiene)
setInterval(() => {
  const keys = Object.keys(sessions);
  if (keys.length > 1000) {
    keys.slice(0, 500).forEach(k => delete sessions[k]);
  }
}, 30 * 60 * 1000);

// ── Strip headers that break embedding ───────────────────────────────────
const STRIP_HEADERS = [
  'x-frame-options',
  'content-security-policy',
  'content-security-policy-report-only',
  'cross-origin-embedder-policy',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'x-content-type-options',
  'strict-transport-security',
  'transfer-encoding',
  'set-cookie',
];

// ── URL rewriter ──────────────────────────────────────────────────────────
function resolveUrl(u, origin, target, PROXY) {
  try {
    if (!u) return u;
    if (u.startsWith('data:') || u.startsWith('blob:') || u.startsWith('javascript:') || u.startsWith('#')) return u;
    if (u.startsWith(PROXY)) return u;
    if (u.startsWith('//')) return PROXY + encodeURIComponent('https:' + u);
    if (u.startsWith('http://') || u.startsWith('https://')) return PROXY + encodeURIComponent(u);
    if (u.startsWith('/')) return PROXY + encodeURIComponent(origin + u);
    const base = target.substring(0, target.lastIndexOf('/') + 1);
    return PROXY + encodeURIComponent(base + u);
  } catch(e) { return u; }
}

// ── Main request handler ──────────────────────────────────────────────────
function handleRequest(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Credentials': 'true',
    });
    res.end();
    return;
  }

  const reqUrl = new URL(req.url, `http://${req.headers.host}`);
  const target = reqUrl.searchParams.get('url');
  const sid = reqUrl.searchParams.get('sid') || 'default';

  if (!target) {
    res.writeHead(400);
    res.end('Missing url param');
    return;
  }

  let parsed;
  try { parsed = new URL(target); }
  catch(e) { res.writeHead(400); res.end('Invalid URL'); return; }

  const origin = parsed.origin;
  const PROXY = '/proxy?url=';
  const mod = parsed.protocol === 'https:' ? https : http;

  // Build Cookie header from session jar
  const storedCookies = getCookiesForHost(sid, parsed.hostname);

  const reqHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1',
    'Upgrade-Insecure-Requests': '1',
    'Origin': origin,
    'Referer': origin + '/',
  };

  if (storedCookies) reqHeaders['Cookie'] = storedCookies;
  if (req.headers['content-type']) reqHeaders['Content-Type'] = req.headers['content-type'];

  const options = {
    hostname: parsed.hostname,
    port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: req.method,
    headers: reqHeaders,
  };

  // Collect request body for POST etc.
  const bodyChunks = [];
  req.on('data', chunk => bodyChunks.push(chunk));
  req.on('end', () => {
    const body = Buffer.concat(bodyChunks);

    const proxyReq = mod.request(options, (proxyRes) => {
      // Store any set-cookie headers in the session jar
      if (proxyRes.headers['set-cookie']) {
        storeCookies(sid, parsed.hostname, proxyRes.headers['set-cookie']);
      }

      // Build safe response headers
      const safeHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Allow-Credentials': 'true',
      };

      for (const [key, val] of Object.entries(proxyRes.headers)) {
        const k = key.toLowerCase();
        if (STRIP_HEADERS.includes(k)) continue;
        if (Array.isArray(val)) safeHeaders[k] = val.join(', ');
        else safeHeaders[k] = val;
      }

      // Rewrite redirects
      if (safeHeaders['location']) {
        try {
          const redir = new URL(safeHeaders['location'], target).toString();
          safeHeaders['location'] = PROXY + encodeURIComponent(redir) + '&sid=' + sid;
        } catch(e) {}
      }

      const chunks = [];
      proxyRes.on('data', chunk => chunks.push(chunk));
      proxyRes.on('end', () => {
        const raw = Buffer.concat(chunks);
        const ct = (proxyRes.headers['content-type'] || '').toLowerCase();
        const enc = (proxyRes.headers['content-encoding'] || '').toLowerCase();
        const isText = ct.includes('text') || ct.includes('javascript') || ct.includes('json') || ct.includes('xml') || ct.includes('svg');

        if (!isText) {
          delete safeHeaders['content-encoding'];
          res.writeHead(proxyRes.statusCode || 200, safeHeaders);
          res.end(raw);
          return;
        }

        function processText(buf) {
          let text = buf.toString('utf8');
          delete safeHeaders['content-encoding'];

          if (ct.includes('text/html')) {
            const RU = (u) => resolveUrl(u, origin, target, PROXY + encodeURIComponent('') + ''.replace('', '') );
            // Use a closure with correct PROXY path including sid
            const PBASE = `/proxy?sid=${sid}&url=`;
            const ru = (u) => resolveUrl(u, origin, target, PBASE);

            text = text
              .replace(/\bsrc\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `src="${ru(u)}"`)
              .replace(/\bsrc\s*=\s*'([^'#][^']*)'/gi, (_, u) => `src='${ru(u)}'`)
              .replace(/\bhref\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `href="${ru(u)}"`)
              .replace(/\bhref\s*=\s*'([^'#][^']*)'/gi, (_, u) => `href='${ru(u)}'`)
              .replace(/\baction\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `action="${ru(u)}"`)
              .replace(/\baction\s*=\s*'([^'#][^']*)'/gi, (_, u) => `action='${ru(u)}'`)
              .replace(/\bdata-src\s*=\s*"([^"#][^"]*)"/gi, (_, u) => `data-src="${ru(u)}"`)
              .replace(/\bdata-src\s*=\s*'([^'#][^']*)'/gi, (_, u) => `data-src='${ru(u)}'`)
              .replace(/\bsrcset\s*=\s*"([^"]*)"/gi, (_, s) => `srcset="${s.split(',').map(p => { const [u,...r]=p.trim().split(/\s+/); return [ru(u),...r].join(' '); }).join(', ')}"`)
              .replace(/<base[^>]+href[^>]*>/gi, '')
              .replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${ru(u)}')`);

            const interceptor = `<script>
(function(){
  const P='/proxy?sid=${sid}&url=';
  const O='${origin}';
  const T='${target}';
  const BASE=T.substring(0,T.lastIndexOf('/')+1);
  function px(u){
    if(!u||typeof u!=='string')return u;
    if(u.startsWith(P)||u.startsWith('data:')||u.startsWith('blob:')||u.startsWith('javascript:')||u.startsWith('#'))return u;
    try{
      if(u.startsWith('//'))return P+encodeURIComponent('https:'+u);
      if(/^https?:/.test(u))return P+encodeURIComponent(u);
      if(u.startsWith('/'))return P+encodeURIComponent(O+u);
      return P+encodeURIComponent(BASE+u);
    }catch(e){return u;}
  }
  const oFetch=window.fetch;
  window.fetch=function(input,init){
    if(typeof input==='string')input=px(input);
    else if(input&&input.url)input=new Request(px(input.url),input);
    return oFetch.call(this,input,init);
  };
  const oOpen=XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open=function(m,u,...r){return oOpen.call(this,m,px(u),...r);};
  const oCreate=document.createElement.bind(document);
  document.createElement=function(tag,...a){
    const el=oCreate(tag,...a);
    const t=tag.toLowerCase();
    if(['script','link','img','iframe','source','audio','video'].includes(t)){
      const attr=t==='link'?'href':'src';
      const proto=Object.getPrototypeOf(el);
      const desc=Object.getOwnPropertyDescriptor(proto,attr);
      if(desc&&desc.set){Object.defineProperty(el,attr,{get(){return desc.get.call(this);},set(v){desc.set.call(this,px(v));},configurable:true});}
    }
    return el;
  };
  window.open=function(u,...r){return window._origOpen?window._origOpen(px(u),...r):null;};
  window._origOpen=window.open;
  document.addEventListener('click',function(e){
    const a=e.target.closest('a');
    if(!a)return;
    const href=a.getAttribute('href');
    if(!href||href.startsWith('#')||href.startsWith('javascript:')||href.startsWith('mailto:'))return;
    try{
      const resolved=new URL(href,T).toString();
      if(href.startsWith(P)||href.startsWith('/proxy'))return;
      if(!resolved.startsWith(window.location.origin)){e.preventDefault();e.stopPropagation();window.top.postMessage({type:'BAYOU_NAVIGATE',url:resolved},'*');}
    }catch(e2){}
  },true);
  document.addEventListener('contextmenu',function(e){
    const a=e.target.closest('a');
    const url=a?new URL(a.getAttribute('href')||'',T).toString():null;
    if(url&&!url.startsWith('#')&&!url.startsWith('javascript:')){e.preventDefault();e.stopPropagation();window.top.postMessage({type:'BAYOU_CONTEXTMENU',url,x:e.clientX,y:e.clientY},'*');}
  },true);
})();
<\/script>`;

            text = text.replace(/<head>/i, '<head>' + interceptor);
            text = text.replace(/<style([^>]*)>([\s\S]*?)<\/style>/gi, (match, attrs, css) => {
              const PBASE2 = `/proxy?sid=${sid}&url=`;
              const fixedCss = css.replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u, origin, target, PBASE2)}')`);
              return `<style${attrs}>${fixedCss}</style>`;
            });

          } else if (ct.includes('css')) {
            const PBASE = `/proxy?sid=${sid}&url=`;
            text = text
              .replace(/url\(['"]?((?!data:)[^'"\)]+)['"]?\)/gi, (_, u) => `url('${resolveUrl(u, origin, target, PBASE)}')`)
              .replace(/@import\s+['"]([^'"]+)['"]/gi, (_, u) => `@import '${resolveUrl(u, origin, target, PBASE)}'`);
          }

          res.writeHead(proxyRes.statusCode || 200, safeHeaders);
          res.end(text, 'utf8');
        }

        if (enc === 'gzip') {
          zlib.gunzip(raw, (e, d) => processText(e ? raw : d));
        } else if (enc === 'br') {
          zlib.brotliDecompress(raw, (e, d) => processText(e ? raw : d));
        } else if (enc === 'deflate') {
          zlib.inflate(raw, (e, d) => processText(e ? raw : d));
        } else {
          processText(raw);
        }
      });
    });

    proxyReq.on('error', e => {
      res.writeHead(500);
      res.end('Proxy error: ' + e.message);
    });

    if (body.length > 0) proxyReq.write(body);
    proxyReq.end();
  });
}

const PORT = process.env.PORT || 3000;
createServer(handleRequest).listen(PORT, () => {
  console.log(`Bayou proxy server running on port ${PORT}`);
});
