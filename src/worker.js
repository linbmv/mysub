const TEMPLATE_KEYS = {
  clash: "config:template:clash",
  shadowrocket: "config:template:shadowrocket",
};

const DEFAULT_TYPE = "clash";

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
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
    requireToken(url, env);
    return proxyText(env.MAIN_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/bootstrap") {
    requireToken(url, env);
    return proxyText(env.BOOTSTRAP_SUB_URL, request);
  }

  if (request.method === "GET" && path === "/rules/home-secret") {
    requireToken(url, env);
    return proxyText(env.HOME_SECRET_RULE_URL, request);
  }

  if (request.method === "GET" && path === "/rules/sensitive") {
    requireToken(url, env);
    return proxyText(env.SENSITIVE_RULE_URL, request);
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
  const type = templateType(url);
  const template = await env.SUB_KV.get(TEMPLATE_KEYS[type]);
  if (!template) {
    return textResponse(`Config template is not configured: ${type}`, 500);
  }

  const baseURL = requiredEnv(env.PUBLIC_BASE_URL, "PUBLIC_BASE_URL").replace(/\/$/, "");
  const body = template
    .replaceAll("BASE_URL", baseURL)
    .replaceAll("DEVICE_TOKEN", token);

  return configResponse(body, type, true);
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

export { handleRequestWithErrors as handleRequest };
