const TEMPLATE_KEYS = {
  clash: "config:template:clash",
  shadowrocket: "config:template:shadowrocket",
};

const SETTINGS_KEY = "config:settings";
const DEFAULT_TYPE = "clash";

export default {
  async fetch(request, env) {
    return handleRequestWithErrors(request, env);
  },
};

async function routeRequest(request, env) {
  const url = new URL(request.url);
  const path = normalizePath(url.pathname);

  if (request.method === "GET" && path === "/health") {
    return jsonResponse({ ok: true });
  }

  if (request.method === "GET" && path === "/template") {
    return getTemplate(url, env, false);
  }

  if (request.method === "GET" && path === "/config") {
    return getConfig(url, env);
  }

  if (request.method === "GET" && path === "/main") {
    await checkToken(url, env);
    const config = await settings(env);
    return proxyUpstream(config.MAIN_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/bootstrap") {
    await checkToken(url, env);
    const config = await settings(env);
    return proxyUpstream(config.BOOTSTRAP_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/rules/home-secret") {
    await checkToken(url, env);
    const config = await settings(env);
    return proxyUpstream(config.HOME_SECRET_RULE_URL, request);
  }

  if (request.method === "GET" && path === "/rules/sensitive") {
    await checkToken(url, env);
    const config = await settings(env);
    return proxyUpstream(config.SENSITIVE_RULE_URL, request);
  }

  if (request.method === "POST" && path === "/admin/update-template") {
    return updateTemplate(request, env);
  }

  if (request.method === "GET" && path === "/admin/get-template") {
    requireAdmin(url.searchParams.get("admin"), env);
    return getTemplate(url, env, true);
  }

  if (request.method === "GET" && path === "/admin/list-templates") {
    requireAdmin(url.searchParams.get("admin"), env);
    return jsonResponse({ templates: Object.keys(TEMPLATE_KEYS) });
  }

  if (request.method === "POST" && path === "/admin/config") {
    return updateConfig(request, env);
  }

  if (request.method === "GET" && path === "/admin/config") {
    requireAdmin(url.searchParams.get("admin"), env);
    return jsonResponse(await settings(env));
  }

  if (request.method === "GET" && path === "/admin/tokens") {
    return htmlResponse(tokenAdminPage());
  }

  if (request.method === "POST" && path === "/admin/token/add") {
    return addToken(request, env);
  }

  if (request.method === "POST" && path === "/admin/token/remove") {
    return removeToken(request, env);
  }

  return textResponse("Not Found", 404);
}

async function getTemplate(url, env, adminOnly) {
  const type = templateType(url);
  const template = await env.SUB_KV.get(TEMPLATE_KEYS[type]);
  if (!template) {
    return textResponse(`Config template is not configured: ${type}`, 500);
  }

  return configResponse(template, type, adminOnly);
}

async function getConfig(url, env) {
  const token = await checkToken(url, env);
  const type = templateType(url);
  const template = await env.SUB_KV.get(TEMPLATE_KEYS[type]);
  if (!template) {
    return textResponse(`Config template is not configured: ${type}`, 500);
  }

  const config = await settings(env);
  const baseURL = String(config.PUBLIC_BASE_URL || url.origin).replace(/\/$/, "");
  let body = template
    .replaceAll("BASE_URL", baseURL)
    .replaceAll("DEVICE_TOKEN", token);

  if (type === "shadowrocket") {
    body = await injectShadowrocketMainSub(body, config);
  }

  return configResponse(body, type, true);
}

async function injectShadowrocketMainSub(template, config) {
  if (!template.includes("MAIN_SUB_PROXIES")) {
    return template;
  }

  const proxies = await fetchProxyURIList(config.MAIN_SUB_URL);
  if (!proxies) {
    return template.replaceAll("MAIN_SUB_PROXIES", "# MAIN_SUB_URL returned no supported proxy lines");
  }

  const configBody = template.replaceAll("MAIN_SUB_PROXIES", proxies);
  return `${proxies}\n\n${configBody}`;
}

async function fetchProxyURIList(target) {
  const upstream = await fetch(requiredEnv(target, "MAIN_SUB_URL"), {
    method: "GET",
    headers: { accept: "text/plain,*/*" },
    redirect: "follow",
    cf: { cacheTtl: 0, cacheEverything: false },
  });

  if (!upstream.ok) {
    throw new HttpError(`MAIN_SUB_URL fetch failed: ${upstream.status}`, 502);
  }

  const text = await upstream.text();
  return extractProxyURILines(text).join("\n");
}

function extractProxyURILines(text) {
  const decoded = maybeBase64Decode(text);
  const uriLines = decoded
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(isProxyURI);

  if (uriLines.length > 0) {
    return uriLines;
  }

  return extractClashProxyLines(decoded);
}

function maybeBase64Decode(text) {
  const compact = text.trim().replace(/\s+/g, "");
  if (!compact || isProxyURI(text.trim())) {
    return text;
  }

  try {
    const normalized = compact.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    const decoded = atob(padded);
    if (/^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|wireguard):\/\//im.test(decoded)) {
      return decoded;
    }
  } catch (_) {
  }

  return text;
}

function isProxyURI(line) {
  return /^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|wireguard):\/\//i.test(line);
}

function extractClashProxyLines(text) {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("- {") || line.startsWith("-{"))
    .map((line) => line.slice(line.indexOf("{")))
    .map(parseJSONProxy)
    .filter(Boolean)
    .map(clashProxyToShadowrocket)
    .filter(Boolean);
}

function parseJSONProxy(text) {
  try {
    return JSON.parse(text);
  } catch (_) {
    return null;
  }
}

function clashProxyToShadowrocket(proxy) {
  const type = String(proxy.type || "").toLowerCase();
  if (!proxy.name || !proxy.server || !proxy.port) {
    return "";
  }

  if (type === "ss") {
    return shadowrocketLine(proxy.name, "ss", proxy.server, proxy.port, {
      "encrypt-method": proxy.cipher,
      password: proxy.password,
      "udp-relay": proxy.udp,
    });
  }

  if (type === "vmess") {
    return shadowrocketLine(proxy.name, "vmess", proxy.server, proxy.port, {
      method: proxy.cipher || "auto",
      password: proxy.uuid,
      obfs: proxy.network === "ws" ? "websocket" : undefined,
      "obfs-host": proxy["ws-opts"]?.headers?.Host,
      "obfs-uri": proxy["ws-opts"]?.path,
      tls: Boolean(proxy.tls),
      "skip-cert-verify": proxy["skip-cert-verify"],
    });
  }

  if (type === "vless") {
    return shadowrocketLine(proxy.name, "vless", proxy.server, proxy.port, {
      password: proxy.uuid,
      method: "none",
      obfs: proxy.network === "ws" ? "websocket" : undefined,
      "obfs-host": proxy["ws-opts"]?.headers?.Host,
      "obfs-uri": proxy["ws-opts"]?.path,
      tls: Boolean(proxy.tls),
      "skip-cert-verify": proxy["skip-cert-verify"],
    });
  }

  if (type === "trojan") {
    return shadowrocketLine(proxy.name, "trojan", proxy.server, proxy.port, {
      password: proxy.password,
      sni: proxy.sni || proxy.servername,
      "skip-cert-verify": proxy["skip-cert-verify"],
    });
  }

  if (type === "hysteria2") {
    return shadowrocketLine(proxy.name, "hysteria2", proxy.server, proxy.port, {
      password: proxy.password || proxy.auth,
      sni: proxy.sni,
      "skip-cert-verify": proxy["skip-cert-verify"],
    });
  }

  if (type === "http") {
    return shadowrocketLine(proxy.name, "http", proxy.server, proxy.port, {
      username: proxy.username,
      password: proxy.password,
    });
  }

  return "";
}

function shadowrocketLine(name, type, server, port, options) {
  const parts = [`${name} = ${type}`, String(server), String(port)];
  for (const [key, value] of Object.entries(options)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }
    parts.push(`${key}=${formatShadowrocketValue(value)}`);
  }
  return parts.join(", ");
}

function formatShadowrocketValue(value) {
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  return String(value).replaceAll(",", "%2C");
}

async function updateTemplate(request, env) {
  let admin;
  let type;
  let template;

  const contentType = request.headers.get("content-type") || "";
  if (contentType.includes("multipart/form-data")) {
    const form = await request.formData();
    admin = stringValue(form.get("admin"));
    type = normalizeType(stringValue(form.get("type")) || DEFAULT_TYPE);
    template = await formFileOrText(form.get("template"));
  } else if (contentType.includes("application/json")) {
    const body = await request.json();
    admin = stringValue(body.admin);
    type = normalizeType(body.type || DEFAULT_TYPE);
    template = stringValue(body.template);
  } else {
    admin = new URL(request.url).searchParams.get("admin");
    type = templateType(new URL(request.url));
    template = await request.text();
  }

  requireAdmin(admin, env);
  if (!template || !template.trim()) {
    return textResponse("template is required", 400);
  }

  await env.SUB_KV.put(TEMPLATE_KEYS[type], template);
  return jsonResponse({ ok: true, type, bytes: new TextEncoder().encode(template).length });
}

async function updateConfig(request, env) {
  const body = await request.json();
  requireAdmin(body.admin, env);

  const config = {
    MAIN_SUB_URL: stringValue(body.MAIN_SUB_URL),
    BOOTSTRAP_SUB_URL: stringValue(body.BOOTSTRAP_SUB_URL),
    HOME_SECRET_RULE_URL: stringValue(body.HOME_SECRET_RULE_URL),
    SENSITIVE_RULE_URL: stringValue(body.SENSITIVE_RULE_URL),
    ALLOWED_TOKENS: stringValue(body.ALLOWED_TOKENS),
    PUBLIC_BASE_URL: stringValue(body.PUBLIC_BASE_URL),
  };

  await env.SUB_KV.put(SETTINGS_KEY, JSON.stringify(config, null, 2));
  return jsonResponse({ ok: true });
}

async function addToken(request, env) {
  const body = await request.json();
  requireAdmin(body.admin, env);

  const token = normalizeToken(body.token);
  if (!token) {
    return textResponse("token is required", 400);
  }

  const config = await settings(env);
  const tokens = parseCSV(config.ALLOWED_TOKENS);
  if (!tokens.includes(token)) {
    tokens.push(token);
  }

  config.ALLOWED_TOKENS = tokens.join(",");
  await saveSettings(env, config);
  return jsonResponse({ ok: true, tokens });
}

async function removeToken(request, env) {
  const body = await request.json();
  requireAdmin(body.admin, env);

  const token = normalizeToken(body.token);
  if (!token) {
    return textResponse("token is required", 400);
  }

  const config = await settings(env);
  const tokens = parseCSV(config.ALLOWED_TOKENS).filter((item) => item !== token);
  config.ALLOWED_TOKENS = tokens.join(",");
  await saveSettings(env, config);
  return jsonResponse({ ok: true, tokens });
}

async function proxyUpstream(target, request) {
  const upstream = await fetch(requiredEnv(target, "target url"), {
    method: "GET",
    headers: forwardHeaders(request.headers),
    redirect: "follow",
    cf: { cacheTtl: 0, cacheEverything: false },
  });

  const body = await upstream.arrayBuffer();
  const headers = cleanProxyHeaders(upstream.headers);

  return new Response(body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

function cleanProxyHeaders(upstreamHeaders) {
  const headers = new Headers(upstreamHeaders);
  headers.delete("content-length");
  headers.delete("content-encoding");
  headers.delete("transfer-encoding");
  headers.delete("set-cookie");
  headers.set("cache-control", "no-store");
  return headers;
}

async function settings(env) {
  let stored = {};
  const raw = await env.SUB_KV.get(SETTINGS_KEY);
  if (raw) {
    stored = JSON.parse(raw);
  }

  return {
    MAIN_SUB_URL: env.MAIN_SUB_URL || stored.MAIN_SUB_URL || "",
    BOOTSTRAP_SUB_URL: env.BOOTSTRAP_SUB_URL || stored.BOOTSTRAP_SUB_URL || "",
    HOME_SECRET_RULE_URL: env.HOME_SECRET_RULE_URL || stored.HOME_SECRET_RULE_URL || "",
    SENSITIVE_RULE_URL: env.SENSITIVE_RULE_URL || stored.SENSITIVE_RULE_URL || "",
    ALLOWED_TOKENS: env.ALLOWED_TOKENS || stored.ALLOWED_TOKENS || "",
    PUBLIC_BASE_URL: env.PUBLIC_BASE_URL || stored.PUBLIC_BASE_URL || "",
  };
}

async function saveSettings(env, config) {
  await env.SUB_KV.put(SETTINGS_KEY, JSON.stringify({
    MAIN_SUB_URL: config.MAIN_SUB_URL || "",
    BOOTSTRAP_SUB_URL: config.BOOTSTRAP_SUB_URL || "",
    HOME_SECRET_RULE_URL: config.HOME_SECRET_RULE_URL || "",
    SENSITIVE_RULE_URL: config.SENSITIVE_RULE_URL || "",
    ALLOWED_TOKENS: config.ALLOWED_TOKENS || "",
    PUBLIC_BASE_URL: config.PUBLIC_BASE_URL || "",
  }, null, 2));
}

function normalizeToken(token) {
  return String(token || "").trim();
}

async function checkToken(url, env) {
  const token = url.searchParams.get("token") || "";
  if (!token) {
    throw new HttpError("missing token", 401);
  }

  const config = await settings(env);
  const allowedTokens = parseCSV(config.ALLOWED_TOKENS);
  if (allowedTokens.length > 0 && !allowedTokens.includes(token)) {
    throw new HttpError("invalid token", 403);
  }

  return token;
}

function requireToken(url, env) {
  const token = url.searchParams.get("token") || "";
  if (!token) {
    throw new HttpError("missing token", 401);
  }

  const allowedTokens = parseCSV(env.ALLOWED_TOKENS);
  if (allowedTokens.length > 0 && !allowedTokens.includes(token)) {
    throw new HttpError("invalid token", 403);
  }

  return token;
}

function requireAdmin(admin, env) {
  const secret = requiredEnv(env.ADMIN_SECRET, "ADMIN_SECRET");
  if (!admin || admin !== secret) {
    throw new HttpError("unauthorized", 401);
  }
}

function templateType(url) {
  return normalizeType(url.searchParams.get("type") || DEFAULT_TYPE);
}

function normalizeType(type) {
  type = String(type || "").trim().toLowerCase();
  if (type === "sr" || type === "shadowrocket" || type === "ss") {
    return "shadowrocket";
  }
  if (type === "clash" || type === "mihomo") {
    return "clash";
  }
  throw new HttpError(`unsupported template type: ${type}`, 400);
}

async function formFileOrText(value) {
  if (!value) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  if (typeof value.text === "function") {
    return value.text();
  }
  return String(value);
}

function stringValue(value) {
  if (value == null) {
    return "";
  }
  return String(value);
}

function forwardHeaders(headers) {
  const next = new Headers();
  for (const name of ["accept", "user-agent"]) {
    const value = headers.get(name);
    if (value) {
      next.set(name, value);
    }
  }
  return next;
}

function configResponse(body, type, privateResponse) {
  const headers = new Headers();
  headers.set("content-type", type === "clash" ? "text/yaml; charset=utf-8" : "text/plain; charset=utf-8");
  headers.set("cache-control", privateResponse ? "no-store" : "public, max-age=300");
  headers.set("x-content-type-options", "nosniff");
  return new Response(body, { status: 200, headers });
}

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function tokenAdminPage() {
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>mysub Token Admin</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
    body { margin: 0; background: #f6f7f9; color: #1f2937; }
    main { max-width: 760px; margin: 0 auto; padding: 32px 18px; }
    h1 { font-size: 24px; margin: 0 0 18px; }
    section { background: #fff; border: 1px solid #d9dee7; border-radius: 8px; padding: 18px; margin-bottom: 16px; }
    label { display: block; font-size: 13px; font-weight: 650; margin-bottom: 8px; }
    input { box-sizing: border-box; width: 100%; min-height: 40px; border: 1px solid #c7ceda; border-radius: 6px; padding: 8px 10px; font: inherit; background: #fff; color: inherit; }
    button { min-height: 38px; border: 1px solid #1f2937; border-radius: 6px; padding: 0 12px; font: inherit; background: #1f2937; color: #fff; cursor: pointer; }
    button.secondary { background: #fff; color: #1f2937; }
    button.danger { border-color: #b42318; background: #b42318; }
    .row { display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: end; }
    .toolbar { display: flex; gap: 10px; flex-wrap: wrap; }
    .tokens { list-style: none; padding: 0; margin: 14px 0 0; display: grid; gap: 8px; }
    .token { display: grid; grid-template-columns: 1fr auto auto; gap: 8px; align-items: center; padding: 8px; border: 1px solid #d9dee7; border-radius: 6px; background: #fbfcfe; }
    code { overflow-wrap: anywhere; }
    .status { min-height: 22px; font-size: 13px; color: #475467; margin-top: 10px; }
    @media (prefers-color-scheme: dark) {
      body { background: #101418; color: #e5e7eb; }
      section, input, button.secondary, .token { background: #151b22; border-color: #344054; color: #e5e7eb; }
      button { border-color: #e5e7eb; background: #e5e7eb; color: #111827; }
      .status { color: #aab4c0; }
    }
  </style>
</head>
<body>
  <main>
    <h1>mysub Token Admin</h1>
    <section>
      <label for="admin">ADMIN_SECRET</label>
      <div class="row">
        <input id="admin" type="password" autocomplete="current-password" placeholder="输入管理员密钥">
        <button id="load">加载</button>
      </div>
      <div class="status" id="status"></div>
    </section>
    <section>
      <label for="token">新增 token</label>
      <div class="row">
        <input id="token" autocomplete="off" placeholder="例如 router_lin_home">
        <button id="add">增加</button>
      </div>
      <ul class="tokens" id="tokens"></ul>
    </section>
  </main>
  <script>
    const admin = document.querySelector('#admin');
    const tokenInput = document.querySelector('#token');
    const tokensEl = document.querySelector('#tokens');
    const statusEl = document.querySelector('#status');
    let tokens = [];

    function setStatus(message) { statusEl.textContent = message; }
    function adminValue() { return admin.value.trim(); }

    async function api(path, body) {
      const response = await fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ admin: adminValue(), ...body }),
      });
      const text = await response.text();
      if (!response.ok) throw new Error(text || response.statusText);
      return JSON.parse(text);
    }

    function render() {
      tokensEl.innerHTML = '';
      for (const token of tokens) {
        const item = document.createElement('li');
        item.className = 'token';
        const value = document.createElement('code');
        value.textContent = token;
        const copy = document.createElement('button');
        copy.className = 'secondary';
        copy.textContent = '复制';
        copy.onclick = async () => { await navigator.clipboard.writeText(token); setStatus('已复制 ' + token); };
        const remove = document.createElement('button');
        remove.className = 'danger';
        remove.textContent = '删除';
        remove.onclick = async () => {
          const result = await api('/admin/token/remove', { token });
          tokens = result.tokens;
          render();
          setStatus('已删除 ' + token);
        };
        item.append(value, copy, remove);
        tokensEl.append(item);
      }
      if (tokens.length === 0) setStatus('当前没有 token；空白名单表示不限制非空 token。');
    }

    document.querySelector('#load').onclick = async () => {
      const response = await fetch('/admin/config?admin=' + encodeURIComponent(adminValue()));
      const text = await response.text();
      if (!response.ok) { setStatus(text); return; }
      const config = JSON.parse(text);
      tokens = String(config.ALLOWED_TOKENS || '').split(',').map(item => item.trim()).filter(Boolean);
      render();
      setStatus('已加载 ' + tokens.length + ' 个 token');
    };

    document.querySelector('#add').onclick = async () => {
      const token = tokenInput.value.trim();
      if (!token) { setStatus('请输入 token'); return; }
      const result = await api('/admin/token/add', { token });
      tokens = result.tokens;
      tokenInput.value = '';
      render();
      setStatus('已增加 ' + token);
    };
  </script>
</body>
</html>`;
}

function textResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function requiredEnv(value, name) {
  if (!value) {
    throw new HttpError(`${name} is not configured`, 500);
  }
  return value;
}

function parseCSV(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizePath(path) {
  if (path.length > 1) {
    return path.replace(/\/+$/, "");
  }
  return path;
}

class HttpError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function handleRequestWithErrors(request, env) {
  try {
    return await routeRequest(request, env);
  } catch (error) {
    if (error instanceof HttpError) {
      return textResponse(error.message, error.status);
    }
    console.error(error);
    return textResponse("Internal Server Error", 500);
  }
}
