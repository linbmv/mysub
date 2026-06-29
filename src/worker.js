const TEMPLATE_KEYS = {
  clash: "config:template:clash",
  shadowrocket: "config:template:shadowrocket",
};

const CONFIG_KEY = "config:settings";
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

  if (request.method === "GET" && path === "/sr-config") {
    return getShadowrocketConfig(url, env);
  }

  if (request.method === "GET" && path === "/main") {
    requireToken(url, env);
    const config = await loadConfig(env);
    return proxyText(config.MAIN_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/bootstrap") {
    requireToken(url, env);
    const config = await loadConfig(env);
    return proxyText(config.BOOTSTRAP_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/rules/home-secret") {
    requireToken(url, env);
    const config = await loadConfig(env);
    return proxyTextWithFallback(config.HOME_SECRET_RULE_URL, request, env, "rule:home-secret");
  }

  if (request.method === "GET" && path === "/rules/sensitive") {
    requireToken(url, env);
    const config = await loadConfig(env);
    return proxyTextWithFallback(config.SENSITIVE_RULE_URL, request, env, "rule:sensitive");
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
    const config = await loadConfig(env);
    return jsonResponse(config);
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
  const token = requireToken(url, env);
  await checkAllowedToken(token, env);

  const type = templateType(url);
  const template = await env.SUB_KV.get(TEMPLATE_KEYS[type]);
  if (!template) {
    return textResponse(`Config template is not configured: ${type}`, 500);
  }

  const config = await loadConfig(env);
  const baseURL = config.PUBLIC_BASE_URL || url.origin;
  let body = template
    .replaceAll("BASE_URL", baseURL)
    .replaceAll("DEVICE_TOKEN", token);

  if (type === "shadowrocket") {
    body = await injectShadowrocketMainSub(body, env);
  }

  return configResponse(body, type, true);
}

async function getShadowrocketConfig(url, env) {
  const token = requireToken(url, env);
  await checkAllowedToken(token, env);

  const template = await env.SUB_KV.get(TEMPLATE_KEYS.shadowrocket);
  if (!template) {
    return textResponse(`Shadowrocket config template is not configured`, 500);
  }

  const config = await loadConfig(env);
  const baseURL = config.PUBLIC_BASE_URL || url.origin;

  // Return pure config without node section
  let body = template
    .replaceAll("BASE_URL", baseURL)
    .replaceAll("DEVICE_TOKEN", token);

  return configResponse(body, "shadowrocket", true);
}

async function injectShadowrocketMainSub(config, env) {
  if (!config.includes("MAIN_SUB_PROXIES")) {
    return config;
  }

  const settings = await loadConfig(env);
  const proxies = await fetchProxyURIList(settings.MAIN_SUB_URL);
  return config.replaceAll("MAIN_SUB_PROXIES", proxies || "# MAIN_SUB_URL returned no supported proxy lines");
}

async function buildShadowrocketSubscription(config, env) {
  // Fetch proxy nodes
  const settings = await loadConfig(env);
  const proxyURIList = await fetchProxyURIList(settings.MAIN_SUB_URL);

  // Remove [Proxy] section placeholder from config
  const configWithoutProxySection = config.replace(/\[Proxy\][^\[]*/, '');

  // Build Shadowrocket subscription format:
  // 1. Proxy URIs (one per line)
  // 2. Separator comment
  // 3. Configuration sections ([General], [Proxy Group], [Rule], etc.)
  const subscription = proxyURIList + "\n\n# Shadowrocket Config\n\n" + configWithoutProxySection.trim();

  return subscription;
}

async function fetchProxyURIList(target) {
  const upstream = await fetch(requiredEnv(target, "MAIN_SUB_URL"), {
    method: "GET",
    headers: { accept: "text/plain,*/*" },
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
  const lines = decoded
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  return lines.filter(isProxyURI);
}

function maybeBase64Decode(text) {
  const compact = text.trim().replace(/\s+/g, "");
  if (!compact || /^(ss|ssr|vmess|vless|trojan|hysteria2|hy2|tuic|wireguard):\/\//i.test(text.trim())) {
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

async function loadConfig(env) {
  const stored = await env.SUB_KV.get(CONFIG_KEY);
  const config = stored ? JSON.parse(stored) : {};

  return {
    MAIN_SUB_URL: config.MAIN_SUB_URL || "",
    BOOTSTRAP_SUB_URL: config.BOOTSTRAP_SUB_URL || "",
    HOME_SECRET_RULE_URL: config.HOME_SECRET_RULE_URL || "",
    SENSITIVE_RULE_URL: config.SENSITIVE_RULE_URL || "",
    ALLOWED_TOKENS: config.ALLOWED_TOKENS || "",
    PUBLIC_BASE_URL: config.PUBLIC_BASE_URL || "",
  };
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

  await env.SUB_KV.put(CONFIG_KEY, JSON.stringify(config, null, 2));
  return jsonResponse({ ok: true, config });
}

async function proxyText(target, request) {
  target = requiredEnv(target, "target url");
  const upstream = await fetch(target, {
    method: "GET",
    headers: forwardHeaders(request.headers),
    cf: { cacheTtl: 0, cacheEverything: false },
  });

  const headers = new Headers(upstream.headers);
  headers.set("cache-control", "no-store");
  headers.delete("set-cookie");
  return new Response(upstream.body, { status: upstream.status, headers });
}

async function proxyTextWithFallback(target, request, env, kvKey) {
  try {
    target = requiredEnv(target, "target url");
    const upstream = await fetch(target, {
      method: "GET",
      headers: forwardHeaders(request.headers),
      cf: { cacheTtl: 0, cacheEverything: false },
      signal: AbortSignal.timeout(5000), // 5s timeout
    });

    if (upstream.ok) {
      const text = await upstream.text();
      // Cache to KV for fallback
      await env.SUB_KV.put(kvKey, text, { expirationTtl: 86400 });

      const headers = new Headers();
      headers.set("cache-control", "no-store");
      headers.set("content-type", "text/plain; charset=utf-8");
      return new Response(text, { status: 200, headers });
    }
  } catch (e) {
    console.error("Upstream fetch failed, trying KV fallback:", e.message);
  }

  // Fallback to KV
  const cached = await env.SUB_KV.get(kvKey);
  if (cached) {
    const headers = new Headers();
    headers.set("cache-control", "no-store");
    headers.set("content-type", "text/plain; charset=utf-8");
    headers.set("x-fallback", "true");
    return new Response(cached, { status: 200, headers });
  }

  return textResponse("Rule source unavailable and no cache", 502);
}

function requireToken(url, env) {
  const token = url.searchParams.get("token") || "";
  if (!token) {
    throw new HttpError("missing token", 401);
  }

  return token;
}

async function checkAllowedToken(token, env) {
  const config = await loadConfig(env);
  const allowedTokens = parseCSV(config.ALLOWED_TOKENS);
  if (allowedTokens.length > 0 && !allowedTokens.includes(token)) {
    throw new HttpError("invalid token", 403);
  }
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
  const userAgent = headers.get("user-agent");
  if (userAgent) {
    next.set("user-agent", userAgent);
  }
  next.set("accept", headers.get("accept") || "*/*");
  return next;
}

function configResponse(body, type, privateResponse) {
  const headers = new Headers();
  headers.set("content-type", type === "clash" ? "text/yaml; charset=utf-8" : "text/plain; charset=utf-8");
  headers.set("cache-control", privateResponse ? "no-store" : "public, max-age=300");
  headers.set("x-content-type-options", "nosniff");
  return new Response(body, { status: 200, headers });
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

globalThis.addEventListener?.("unhandledrejection", (event) => {
  console.error(event.reason);
});

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

async function convertToClashProvider(target, request) {
  try {
    target = requiredEnv(target, "target url");
    const upstream = await fetch(target, {
      method: "GET",
      headers: forwardHeaders(request.headers),
      cf: { cacheTtl: 0, cacheEverything: false },
    });

    if (!upstream.ok) {
      throw new HttpError(`Upstream fetch failed: ${upstream.status}`, 502);
    }

    const text = await upstream.text();

    // Always parse and filter, even if it's already Clash YAML format
    // This ensures we filter out invalid fields like network:"none"
    const proxyURIs = extractProxyURILines(text);

    // If no proxy URIs found, try to extract from existing Clash YAML
    if (proxyURIs.length === 0 && text.includes("proxies:")) {
      // Extract JSON-format proxies from YAML
      const lines = text.split("\n");
      const yamlProxies = [];
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith("- {") || trimmed.startsWith("-{")) {
          try {
            const jsonStr = trimmed.substring(trimmed.indexOf("{"));
            const proxy = JSON.parse(jsonStr);
            yamlProxies.push(cleanupClashProxy(proxy));
          } catch (e) {
            // Skip invalid JSON
          }
        }
      }

      if (yamlProxies.length > 0) {
        const yaml = buildClashYAMLFromObjects(yamlProxies);
        const headers = new Headers();
        headers.set("content-type", "text/yaml; charset=utf-8");
        headers.set("cache-control", "no-store");
        return new Response(yaml, { status: 200, headers });
      }
    }

    const yaml = buildClashYAML(proxyURIs);

    const headers = new Headers();
    headers.set("content-type", "text/yaml; charset=utf-8");
    headers.set("cache-control", "no-store");

    // Don't set content-encoding here - let Cloudflare handle compression automatically
    // Cloudflare Workers automatically compresses responses if Accept-Encoding header is present

    return new Response(yaml, { status: 200, headers });
  } catch (error) {
    console.error("convertToClashProvider error:", error);
    throw error;
  }
}

function buildClashYAML(proxyURIs) {
  const proxies = [];

  for (const uri of proxyURIs) {
    try {
      const proxy = parseProxyURIToClash(uri);
      if (proxy) {
        proxies.push(proxy);
      }
    } catch (e) {
      // Skip unparseable nodes, don't crash
      console.error("Failed to parse proxy URI:", uri.substring(0, 50), e.message);
    }
  }

  return buildClashYAMLFromObjects(proxies);
}

function buildClashYAMLFromObjects(proxies) {
  if (proxies.length === 0) {
    return "proxies: []";
  }

  // Build YAML manually to avoid external dependencies
  let yaml = "proxies:\n";
  for (const proxy of proxies) {
    yaml += "  - name: " + JSON.stringify(proxy.name) + "\n";
    yaml += "    type: " + proxy.type + "\n";
    yaml += "    server: " + proxy.server + "\n";
    yaml += "    port: " + proxy.port + "\n";

    // Add protocol-specific fields
    for (const [key, value] of Object.entries(proxy)) {
      if (["name", "type", "server", "port"].includes(key)) continue;
      if (value === undefined || value === null) continue;

      if (typeof value === "object") {
        yaml += "    " + key + ":\n";
        for (const [k, v] of Object.entries(value)) {
          yaml += "      " + k + ": " + JSON.stringify(v) + "\n";
        }
      } else {
        yaml += "    " + key + ": " + JSON.stringify(value) + "\n";
      }
    }
  }

  return yaml;
}

function cleanupClashProxy(proxy) {
  // Remove invalid fields
  const cleaned = { ...proxy };

  // Filter out network:"none" and network:"tcp" (defaults)
  if (cleaned.network === "none" || cleaned.network === "tcp") {
    delete cleaned.network;
  }

  return cleaned;
}

function parseProxyURIToClash(uri) {
  // Simple parser with error handling for each protocol
  if (uri.startsWith("ss://")) {
    return parseSS(uri);
  } else if (uri.startsWith("vmess://")) {
    return parseVMess(uri);
  } else if (uri.startsWith("vless://")) {
    return parseVLess(uri);
  } else if (uri.startsWith("trojan://")) {
    return parseTrojan(uri);
  } else if (uri.startsWith("hysteria2://") || uri.startsWith("hy2://")) {
    return parseHysteria2(uri);
  }

  return null;
}

function parseSS(uri) {
  const url = new URL(uri);
  const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;

  // Try to decode userinfo
  let method = "aes-256-gcm";
  let password = "";

  try {
    const userinfo = url.username ? atob(url.username) : atob(uri.split("@")[0].replace("ss://", ""));
    const parts = userinfo.split(":");
    if (parts.length >= 2) {
      method = parts[0];
      password = parts.slice(1).join(":");
    }
  } catch (e) {
    // If decode fails, skip this node
    return null;
  }

  return {
    name,
    type: "ss",
    server: url.hostname,
    port: parseInt(url.port) || 8388,
    cipher: method,
    password: password,
  };
}

function parseVMess(uri) {
  try {
    const json = JSON.parse(atob(uri.replace("vmess://", "")));
    const proxy = {
      name: json.ps || json.add || "VMess",
      type: "vmess",
      server: json.add,
      port: parseInt(json.port),
      uuid: json.id,
      alterId: parseInt(json.aid || 0),
      cipher: json.scy || "auto",
    };

    if (json.net && json.net !== "tcp" && json.net !== "none") {
      proxy.network = json.net;
    }
    if (json.tls === "tls") {
      proxy.tls = true;
    }
    if (json.net === "ws") {
      proxy["ws-opts"] = {
        path: json.path || "/",
      };
      if (json.host) {
        proxy["ws-opts"].headers = { Host: json.host };
      }
    }

    return proxy;
  } catch (e) {
    return null;
  }
}

function parseVLess(uri) {
  const url = new URL(uri);
  const params = Object.fromEntries(url.searchParams);
  const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;

  const proxy = {
    name,
    type: "vless",
    server: url.hostname,
    port: parseInt(url.port),
    uuid: url.username,
  };

  if (params.type && params.type !== "tcp" && params.type !== "none") {
    proxy.network = params.type;
  }
  if (params.security === "tls" || params.security === "reality") {
    proxy.tls = true;
  }
  if (params.flow) {
    proxy.flow = params.flow;
  }
  if (params.type === "ws") {
    proxy["ws-opts"] = {
      path: params.path || "/",
    };
    if (params.host) {
      proxy["ws-opts"].headers = { Host: params.host };
    }
  }
  if (params.security === "reality" && params.pbk) {
    proxy["reality-opts"] = {
      "public-key": params.pbk,
    };
    if (params.sid) {
      proxy["reality-opts"]["short-id"] = params.sid;
    }
  }
  if (params.sni) {
    proxy.servername = params.sni;
  }

  return proxy;
}

function parseTrojan(uri) {
  const url = new URL(uri);
  const params = Object.fromEntries(url.searchParams);
  const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;

  const proxy = {
    name,
    type: "trojan",
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username,
  };

  if (params.sni) {
    proxy.sni = params.sni;
  }
  if (params.allowInsecure === "1") {
    proxy["skip-cert-verify"] = true;
  }
  if (params.type === "ws") {
    proxy.network = "ws";
    proxy["ws-opts"] = {
      path: params.path || "/",
    };
  }

  return proxy;
}

function parseHysteria2(uri) {
  const url = new URL(uri.replace("hy2://", "hysteria2://"));
  const params = Object.fromEntries(url.searchParams);
  const name = decodeURIComponent(url.hash.slice(1)) || url.hostname;

  const proxy = {
    name,
    type: "hysteria2",
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username,
  };

  if (params.sni) {
    proxy.sni = params.sni;
  }
  if (params.insecure === "1") {
    proxy["skip-cert-verify"] = true;
  }

  return proxy;
}

export { handleRequestWithErrors as handleRequest };
