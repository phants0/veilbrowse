import express from "express";
import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = fileURLToPath(new URL("./public/", import.meta.url));

app.disable("x-powered-by");
app.set("trust proxy", false);

app.use(express.static(PUBLIC_DIR, {
  index: false,
  fallthrough: true,
  etag: false,
  maxAge: 0
}));

// Accept browser request bodies for proxied forms/API calls, but keep a hard
// limit so a public proxy cannot be used as an unlimited upload sink.
app.use("/proxy", express.raw({
  type: () => true,
  limit: "10mb"
}));

// Privacy defaults:
// - no request logging
// - no persistent cache
// - no persistent browsing-history database
// - no analytics
// - no persistent upstream cookie jar
//
// A small in-memory cookie jar is used only to make modern sites work during
// active sessions. It expires automatically and is never written to disk.

const BLOCKED_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "cookie",
  "set-cookie"
]);

const PASS_RESPONSE_HEADERS = [
  "content-type",
  "content-language",
  "accept-ranges",
  "content-range"
];

const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
const COOKIE_CLEANUP_MS = 10 * 60 * 1000;
const sessions = new Map();

function getSessionId(req, res) {
  const cookieHeader = typeof req.headers.cookie === "string" ? req.headers.cookie : "";
  const match = cookieHeader.match(/(?:^|;\s*)vb_sid=([^;]+)/);
  const existing = match?.[1];

  if (existing && /^[A-Za-z0-9_-]{32,128}$/.test(existing) && sessions.has(existing)) {
    const session = sessions.get(existing);
    session.lastUsed = Date.now();
    return existing;
  }

  const id = crypto.randomBytes(24).toString("base64url");
  sessions.set(id, { lastUsed: Date.now(), cookies: new Map() });

  // Session cookie only. No Max-Age/Expires means the browser drops it when
  // the browser session ends.
  res.setHeader("Set-Cookie", "vb_sid=" + id + "; Path=/; HttpOnly; SameSite=Lax");
  return id;
}

function cleanupSessions() {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, session] of sessions) {
    if (session.lastUsed < cutoff) sessions.delete(id);
  }
}

setInterval(cleanupSessions, COOKIE_CLEANUP_MS).unref();

function parseCookieHeader(header) {
  const cookies = new Map();
  if (!header) return cookies;

  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index <= 0) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies.set(name, value);
  }

  return cookies;
}

function cookieMatches(cookie, target) {
  if (cookie.expiresAt && cookie.expiresAt <= Date.now()) return false;
  if (cookie.secure && target.protocol !== "https:") return false;

  const host = target.hostname.toLowerCase();
  const domain = cookie.domain.toLowerCase();

  if (
    host !== domain &&
    !(cookie.hostOnly === false && host.endsWith("." + domain))
  ) {
    return false;
  }

  const path = target.pathname || "/";
  return path === cookie.path || path.startsWith(cookie.path.endsWith("/") ? cookie.path : cookie.path + "/");
}

function getCookieHeader(session, target) {
  const parts = [];

  for (const [key, cookie] of session.cookies) {
    if (cookieMatches(cookie, target)) {
      parts.push(key.split("\n")[0] + "=" + cookie.value);
    }
  }

  return parts.join("; ");
}

function storeSetCookies(session, target, upstream) {
  const setCookies = typeof upstream.headers.getSetCookie === "function"
    ? upstream.headers.getSetCookie()
    : [];

  for (const raw of setCookies) {
    const pieces = raw.split(";").map((part) => part.trim());
    const first = pieces.shift();
    if (!first) continue;

    const separator = first.indexOf("=");
    if (separator <= 0) continue;

    const name = first.slice(0, separator).trim();
    const value = first.slice(separator + 1).trim();
    if (!name) continue;

    let domain = target.hostname.toLowerCase();
    let hostOnly = true;
    let path = "/";

    const cookie = {
      value,
      domain,
      hostOnly,
      path,
      secure: false,
      expiresAt: null
    };

    for (const attribute of pieces) {
      const index = attribute.indexOf("=");
      const key = (index >= 0 ? attribute.slice(0, index) : attribute).trim().toLowerCase();
      const attrValue = index >= 0 ? attribute.slice(index + 1).trim() : "";

      if (key === "domain" && attrValue) {
        domain = attrValue.replace(/^\./, "").toLowerCase();
        if (!domain) continue;
        hostOnly = false;

        if (
          target.hostname.toLowerCase() !== domain &&
          !target.hostname.toLowerCase().endsWith("." + domain)
        ) {
          cookie.domain = target.hostname.toLowerCase();
          cookie.hostOnly = true;
        } else {
          cookie.domain = domain;
          cookie.hostOnly = false;
        }
      } else if (key === "path" && attrValue.startsWith("/")) {
        path = attrValue;
      } else if (key === "secure") {
        cookie.secure = true;
      } else if (key === "max-age") {
        const seconds = Number(attrValue);
        if (Number.isFinite(seconds)) {
          cookie.expiresAt = seconds <= 0 ? 0 : Date.now() + seconds * 1000;
        }
      } else if (key === "expires") {
        const timestamp = Date.parse(attrValue);
        if (Number.isFinite(timestamp)) cookie.expiresAt = timestamp;
      }
    }

    cookie.domain = domain;
    cookie.hostOnly = hostOnly;
    cookie.path = path;

    const key = cookie.domain + "\n" + cookie.path + "\n" + name;

    if (cookie.expiresAt === 0 || (cookie.expiresAt && cookie.expiresAt <= Date.now())) {
      session.cookies.delete(key);
    } else {
      session.cookies.set(key, cookie);
    }
  }
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }

  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

function isBlockedAddress(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true;
}

async function assertSafeTarget(rawUrl) {
  let target;

  try {
    target = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported");
  }

  if (!target.hostname || target.username || target.password) {
    throw new Error("Invalid target URL");
  }

  const host = target.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host === "metadata.google.internal"
  ) {
    throw new Error("Private/local targets are blocked");
  }

  if (net.isIP(host)) {
    if (isBlockedAddress(host)) throw new Error("Private/local targets are blocked");
    return target;
  }

  const addresses = await dns.lookup(host, { all: true });
  if (!addresses.length || addresses.some(({ address }) => isBlockedAddress(address))) {
    throw new Error("Private/local targets are blocked");
  }

  return target;
}

function proxyUrl(targetUrl, baseUrl) {
  try {
    const absolute = new URL(targetUrl, baseUrl);
    if (!["http:", "https:"].includes(absolute.protocol)) return "#";
    return "/proxy?url=" + encodeURIComponent(absolute.href);
  } catch {
    return "#";
  }
}

function rewriteSrcset(value, baseUrl) {
  return value
    .split(",")
    .map((candidate) => {
      const trimmed = candidate.trim();
      if (!trimmed) return trimmed;

      const match = trimmed.match(/^(\S+)(\s+.+)?$/);
      if (!match) return trimmed;

      const [, url, descriptor = ""] = match;
      if (
        url.startsWith("data:") ||
        url.startsWith("blob:") ||
        url.startsWith("#")
      ) {
        return trimmed;
      }

      return proxyUrl(url, baseUrl) + descriptor;
    })
    .join(", ");
}

function rewriteCss(css, baseUrl) {
  let rewritten = css.replace(
    /url\(\s*(['"]?)(.*?)\1\s*\)/gi,
    (match, quote, value) => {
      const trimmed = value.trim();
      if (
        !trimmed ||
        trimmed.startsWith("data:") ||
        trimmed.startsWith("blob:") ||
        trimmed.startsWith("#")
      ) {
        return match;
      }

      return 'url("' + proxyUrl(trimmed, baseUrl) + '")';
    }
  );

  rewritten = rewritten.replace(
    /@import\s+(?:url\(\s*)?(['"])(.*?)\1\s*\)?/gi,
    (match, quote, value) => {
      if (!value || value.startsWith("data:") || value.startsWith("blob:")) return match;
      return match.replace(value, proxyUrl(value, baseUrl));
    }
  );

  return rewritten;
}

function runtimeBridgeScript(targetUrl) {
  const encodedTarget = JSON.stringify(targetUrl);

  return `<script data-veilbrowse-runtime>
(() => {
  const targetBase = new URL(${encodedTarget});
  const proxy = (input) => {
    try {
      const raw = typeof input === "string" ? input : input?.url;
      if (!raw) return null;

      const absolute = new URL(raw, targetBase);
      if (!["http:", "https:"].includes(absolute.protocol)) return null;

      if (absolute.href.startsWith(location.origin + "/proxy?url=")) {
        return absolute.href;
      }

      return location.origin + "/proxy?url=" + encodeURIComponent(absolute.href);
    } catch {
      return null;
    }
  };

  const originalFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    const rewritten = proxy(input);
    if (!rewritten) return originalFetch(input, init);

    if (input instanceof Request) {
      return originalFetch(new Request(rewritten, input), init);
    }

    return originalFetch(rewritten, init);
  };

  const originalOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    const rewritten = proxy(url);
    return originalOpen.call(this, method, rewritten || url, ...rest);
  };

  const originalSendBeacon = navigator.sendBeacon?.bind(navigator);
  if (originalSendBeacon) {
    navigator.sendBeacon = (url, data) => {
      const rewritten = proxy(url);
      return originalSendBeacon(rewritten || url, data);
    };
  }

  window.__VEILBROWSE_TARGET__ = targetBase.href;
})();
</script>`;
}

async function rewriteHtml(html, baseUrl) {
  const { load } = await import("cheerio");
  const $ = load(html, { decodeEntities: false });

  const urlAttributes = [
    ["a", "href"],
    ["area", "href"],
    ["link", "href"],
    ["script", "src"],
    ["img", "src"],
    ["source", "src"],
    ["video", "src"],
    ["audio", "src"],
    ["iframe", "src"],
    ["embed", "src"],
    ["object", "data"],
    ["form", "action"],
    ["input", "src"],
    ["track", "src"],
    ["iframe", "srcdoc"],
    ["meta", "content"]
  ];

  for (const [selector, attribute] of urlAttributes) {
    $(`${selector}[${attribute}]`).each((_, element) => {
      const value = $(element).attr(attribute);
      if (!value) return;

      if (
        value.startsWith("#") ||
        value.startsWith("data:") ||
        value.startsWith("blob:") ||
        value.startsWith("javascript:")
      ) {
        return;
      }

      if (attribute === "content" && !$(element).is('meta[http-equiv="refresh" i]')) {
        return;
      }

      $(element).attr(attribute, proxyUrl(value, baseUrl));
    });
  }

  $("[srcset]").each((_, element) => {
    const value = $(element).attr("srcset");
    if (value) $(element).attr("srcset", rewriteSrcset(value, baseUrl));
  });

  $("link[href]").each((_, element) => {
    const href = $(element).attr("href");
    const rel = ($(element).attr("rel") || "").toLowerCase();

    if (rel.includes("stylesheet") || rel.includes("manifest") || rel.includes("icon") || rel.includes("preload")) {
      $(element).attr("href", proxyUrl(href, baseUrl));
    }
  });

  $("img[imagesrcset], link[imagesrcset]").each((_, element) => {
    const value = $(element).attr("imagesrcset");
    if (value) $(element).attr("imagesrcset", rewriteSrcset(value, baseUrl));
  });

  $("[poster]").each((_, element) => {
    const value = $(element).attr("poster");
    if (value) $(element).attr("poster", proxyUrl(value, baseUrl));
  });

  $("[style]").each((_, element) => {
    const value = $(element).attr("style");
    if (value) $(element).attr("style", rewriteCss(value, baseUrl));
  });

  $("style").each((_, element) => {
    const value = $(element).html();
    if (value) $(element).html(rewriteCss(value, baseUrl));
  });

  $("meta[http-equiv]").each((_, element) => {
    const httpEquiv = ($(element).attr("http-equiv") || "").toLowerCase();
    if (httpEquiv === "content-security-policy") {
      $(element).remove();
    }
  });

  $("base").remove();

  $("head").prepend(
    runtimeBridgeScript(baseUrl) +
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">'
  );

  return $.html();
}

function copyResponseHeaders(upstream, response) {
  for (const header of PASS_RESPONSE_HEADERS) {
    const value = upstream.headers.get(header);
    if (value) response.setHeader(header, value);
  }

  // Node fetch transparently decodes gzip/br/deflate responses. Never forward
  // the upstream Content-Encoding header after that decoding.
  response.removeHeader("Content-Encoding");
  response.removeHeader("Content-Length");
  response.removeHeader("Location");

  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cache-Control", "no-store, private, max-age=0");
}

function getForwardedHeaders(req, target, session, method) {
  const headers = {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
    "Accept": req.headers.accept || "*/*",
    "Accept-Language": req.headers["accept-language"] || "en-US,en;q=0.9"
  };

  const forwardable = [
    "authorization",
    "content-type",
    "range",
    "if-none-match",
    "if-modified-since",
    "if-range",
    "accept"
  ];

  for (const name of forwardable) {
    const value = req.headers[name];
    if (typeof value === "string") headers[name] = value;
  }

  const cookie = getCookieHeader(session, target);
  if (cookie) headers.cookie = cookie;

  if (req.headers.origin) headers.origin = target.origin;
  if (req.headers.referer) headers.referer = target.href;

  if (!["GET", "HEAD"].includes(method) && req.headers["content-type"]) {
    headers["content-type"] = req.headers["content-type"];
  }

  return headers;
}

function appendProxyQueryToTarget(req, target) {
  const requestUrl = new URL(req.originalUrl, "http://veilbrowse.local");
  for (const [key, value] of requestUrl.searchParams) {
    if (key !== "url") target.searchParams.append(key, value);
  }
  return target;
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, persistentStorage: false });
});

app.all("/proxy", async (req, res) => {
  const rawUrl = typeof req.query.url === "string" ? req.query.url : "";

  if (!rawUrl) {
    return res.status(400).send("Missing URL");
  }

  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(req.method)) {
    return res.status(405).send("Method not supported");
  }

  let target;
  try {
    target = await assertSafeTarget(rawUrl);
    target = appendProxyQueryToTarget(req, target);
  } catch (error) {
    return res.status(400).send(error.message);
  }

  const sessionId = getSessionId(req, res);
  const session = sessions.get(sessionId);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    let currentTarget = target;
    let method = req.method;
    let body = ["GET", "HEAD"].includes(method) ? undefined : req.body;
    let upstream;

    for (let redirects = 0; redirects <= 10; redirects++) {
      const requestHeaders = getForwardedHeaders(req, currentTarget, session, method);

      upstream = await fetch(currentTarget, {
        method,
        redirect: "manual",
        signal: controller.signal,
        headers: requestHeaders,
        body
      });

      storeSetCookies(session, currentTarget, upstream);

      if (![301, 302, 303, 307, 308].includes(upstream.status)) break;

      const location = upstream.headers.get("location");
      if (!location) break;

      currentTarget = await assertSafeTarget(new URL(location, currentTarget).href);

      if (upstream.status === 303 || ((upstream.status === 301 || upstream.status === 302) && method === "POST")) {
        method = "GET";
        body = undefined;
      }

      if (redirects === 10) {
        return res.status(508).send("Too many redirects.");
      }
    }

    copyResponseHeaders(upstream, res);

    const contentType = (upstream.headers.get("content-type") || "").toLowerCase();

    if (contentType.includes("text/html")) {
      const html = await upstream.text();
      const rewritten = await rewriteHtml(html, currentTarget.href);

      res.removeHeader("Content-Encoding");
      res.removeHeader("Content-Length");
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(upstream.status).send(rewritten);
    }

    if (contentType.includes("text/css")) {
      const css = await upstream.text();

      res.removeHeader("Content-Encoding");
      res.removeHeader("Content-Length");
      res.setHeader("Content-Type", "text/css; charset=utf-8");
      return res.status(upstream.status).send(rewriteCss(css, currentTarget.href));
    }

    if (upstream.body) {
      Readable.fromWeb(upstream.body).pipe(res);
      return;
    }

    return res.status(upstream.status).end();
  } catch (error) {
    if (error.name === "AbortError") {
      return res.status(504).send("The website took too long to respond.");
    }

    return res.status(502).send("Unable to load the website.");
  } finally {
    clearTimeout(timeout);
  }
});

app.use((_req, res) => {
  res.sendFile("index.html", {
    root: PUBLIC_DIR
  });
});

app.listen(PORT, () => {});
