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

  for (const cookie of session.cookies.values()) {
    if (cookieMatches(cookie, target)) {
      parts.push(cookie.name + "=" + cookie.value);
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

  const searchStyle = document.createElement("style");
  searchStyle.textContent = [
    "#veilbrowse-search-toggle{position:fixed;top:14px;right:14px;z-index:2147483647;height:38px;padding:0 13px;border:1px solid #30343d;border-radius:10px;background:rgba(17,19,24,.94);color:#cbd0d8;font:600 13px/1 system-ui,-apple-system,BlinkMacSystemFont,sans-serif;cursor:pointer;box-shadow:0 8px 28px rgba(0,0,0,.24);backdrop-filter:blur(12px)}",
    "#veilbrowse-search-toggle:hover{background:#1a1d23;color:#fff}",
    "#veilbrowse-search-toggle:focus-visible{outline:2px solid #8ab4ff;outline-offset:2px}",
    "#veilbrowse-search-overlay{position:fixed;inset:0;z-index:2147483646;display:flex;align-items:flex-start;justify-content:center;padding:12vh 20px 20px;background:rgba(0,0,0,.42);backdrop-filter:blur(3px)}",
    "#veilbrowse-search-overlay[hidden]{display:none}",
    "#veilbrowse-search-box{display:flex;gap:8px;width:min(760px,100%);padding:8px;border:1px solid #30343d;border-radius:16px;background:#0f1116;box-shadow:0 24px 80px rgba(0,0,0,.5)}",
    "#veilbrowse-search-input{flex:1;min-width:0;height:44px;border:0;outline:0;border-radius:10px;background:#171a20;color:#fff;padding:0 14px;font:16px system-ui,-apple-system,BlinkMacSystemFont,sans-serif}",
    "#veilbrowse-search-input::placeholder{color:#737986}",
    "#veilbrowse-search-go{height:44px;border:0;border-radius:10px;padding:0 18px;background:#f4f4f5;color:#090a0d;font:700 14px system-ui,-apple-system,BlinkMacSystemFont,sans-serif;cursor:pointer}",
    "#veilbrowse-search-go:hover{background:#fff}"
  ].join("");

  const createSearchUi = () => {
    if (document.getElementById("veilbrowse-search-overlay")) return;

    document.head.appendChild(searchStyle);

    const toggle = document.createElement("button");
    toggle.id = "veilbrowse-search-toggle";
    toggle.type = "button";
    toggle.textContent = "Search";
    toggle.title = "Open VeilBrowse search (Ctrl+K / ⌘K)";
    toggle.setAttribute("aria-label", "Open VeilBrowse search");

    const overlay = document.createElement("div");
    overlay.id = "veilbrowse-search-overlay";
    overlay.hidden = true;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-label", "VeilBrowse search");

    const box = document.createElement("form");
    box.id = "veilbrowse-search-box";

    const searchInput = document.createElement("input");
    searchInput.id = "veilbrowse-search-input";
    searchInput.type = "text";
    searchInput.placeholder = "Search or enter a website URL";
    searchInput.autocomplete = "off";
    searchInput.spellcheck = false;
    searchInput.setAttribute("aria-label", "Search or enter a website URL");

    const go = document.createElement("button");
    go.id = "veilbrowse-search-go";
    go.type = "submit";
    go.textContent = "Go";

    box.append(searchInput, go);
    overlay.appendChild(box);
    document.body.append(toggle, overlay);

    const closeSearch = () => {
      overlay.hidden = true;
      toggle.focus();
    };

    const openSearch = () => {
      overlay.hidden = false;
      searchInput.value = "";
      searchInput.focus();
    };

    const submitSearch = (event) => {
      event.preventDefault();
      const value = searchInput.value.trim();
      if (!value) return;

      if (/^[a-z][a-z0-9+.-]*:/i.test(value) && !/^https?:\/\//i.test(value)) return;

      let destination;
      try {
        const candidate = /^(?:https?:\/\/|\/\/)/i.test(value)
          ? (value.startsWith("//") ? "https:" + value : value)
          : "https://" + value;
        const url = new URL(candidate);
        const looksLikeUrl = /^(?:https?:\/\/|\/\/)/i.test(value) ||
          /^localhost(?::\d+)?(?:[/?#]|$)/i.test(value) ||
          /^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:[/?#]|$)/.test(value) ||
          (url.hostname.includes(".") && !url.hostname.endsWith("."));
        destination = looksLikeUrl
          ? "/proxy?url=" + encodeURIComponent(url.href)
          : "/search?q=" + encodeURIComponent(value);
      } catch {
        destination = "/search?q=" + encodeURIComponent(value);
      }

      window.location.assign(destination);
    };

    toggle.addEventListener("click", openSearch);
    overlay.addEventListener("click", (event) => {
      if (event.target === overlay) closeSearch();    });
    box.addEventListener("submit", submitSearch);

    document.addEventListener("keydown", (event) => {
      const modifier = event.ctrlKey || event.metaKey;
      if (modifier && event.key.toLowerCase() === "k") {
        event.preventDefault();
        event.stopPropagation();
        openSearch();
        return;
      }

      if (event.key === "Escape" && !overlay.hidden) {
        event.preventDefault();
        closeSearch();
      }
    }, true);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", createSearchUi, { once: true });
  } else {
    createSearchUi();
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
    ["track", "src"]
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

      $(element).attr(attribute, proxyUrl(value, baseUrl));
    });
  }

  $("[srcset]").each((_, element) => {
    const value = $(element).attr("srcset");
    if (value) $(element).attr("srcset", rewriteSrcset(value, baseUrl));
  });

  $("meta[http-equiv]").each((_, element) => {
    const httpEquiv = ($(element).attr("http-equiv") || "").toLowerCase();

    if (httpEquiv === "content-security-policy") {
      $(element).remove();
      return;
    }

    if (httpEquiv === "refresh") {
      const value = $(element).attr("content") || "";
      const match = value.match(/^(\s*\d+\s*;\s*url\s*=\s*)(.*)$/i);

      if (match) {
        const rawTarget = match[2].trim().replace(/^['"]|['"]$/g, "");
        $(element).attr("content", match[1] + proxyUrl(rawTarget, baseUrl));
      }
    }
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

app.get("/search-debug", async (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q.trim() : "";
  if (!query || query.length > 300) {
    return res.status(400).json({ ok: false, error: "Provide a search query with ?q=..." });
  }

  const providers = [
    {
      name: "DuckDuckGo HTML",
      url: "https://html.duckduckgo.com/html/?q=" + encodeURIComponent(query) + "&kl=us-en&kp=-2&ia=web",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
      }
    },
    {
      name: "Bing RSS",
      url: "https://www.bing.com/search?format=rss&q=" + encodeURIComponent(query),
      headers: {
        "User-Agent": "VeilBrowse/1.0",
        "Accept": "application/rss+xml, application/xml, text/xml;q=0.9"
      }
    },
    {
      name: "Bing HTML",
      url: "https://www.bing.com/search?q=" + encodeURIComponent(query),
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9"
      }
    }
  ];

  const diagnostics = [];

  for (const provider of providers) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const upstream = await fetch(provider.url, {
        signal: controller.signal,
        headers: provider.headers,
        redirect: "follow"
      });
      const body = await upstream.text();
      const preview = body.replace(/\s+/g, " ").slice(0, 180);

      const diagnostic = {
        provider: provider.name,
        ok: upstream.ok,
        status: upstream.status,
        contentType: upstream.headers.get("content-type") || null,
        bytes: body.length,
        looksLikeHtml: /<html|<body/i.test(body),
        looksLikeXml: /<rss|<feed|<item/i.test(body),
        hasChallengeWords: /(captcha|unusual traffic|access denied|robot|automated)/i.test(body),
        preview
      };

      if (provider.name === "Bing RSS" && upstream.ok) {
        try {
          const { load } = await import("cheerio");
          const xmlDefault = load(body, { decodeEntities: true });
          const xmlRecommended = load(body, { xml: true });
          const summarize = ($) => {
            const items = [];
            $("item, entry").each((_, item) => {
              const title = $(item).find("title").first().text().trim();
              let href = $(item).find("link").first().text().trim();
              if (!href) href = $(item).find("link[href]").first().attr("href") || "";
              if (title && href) items.push({ title: title.slice(0, 120), href: href.slice(0, 300) });
            });
            return { itemNodes: $("item, entry").length, parseableItems: items.length, firstItems: items.slice(0, 3) };
          };
          diagnostic.parserDefault = summarize(xmlDefault);
          diagnostic.parserRecommended = summarize(xmlRecommended);
        } catch (parserError) {
          diagnostic.parserError = String(parserError?.message || parserError);
        }
      }

      diagnostics.push(diagnostic);
    } catch (error) {
      diagnostics.push({
        provider: provider.name,
        ok: false,
        error: error?.name === "AbortError" ? "timeout" : String(error?.message || error)
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  res.setHeader("Cache-Control", "no-store, private, max-age=0");
  res.json({
    ok: diagnostics.some((item) => item.ok),
    searchNetworkTest: true,
    diagnostics
  });
});

app.get("/search", async (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q.trim() : "";

  if (!query) return res.redirect("/");
  if (query.length > 300) return res.status(400).send("Search query is too long.");

  const providers = [
    {
      name: "DuckDuckGo HTML",
      method: "GET",
      url: "https://html.duckduckgo.com/html/?q=" + encodeURIComponent(query) + "&kl=us-en&kp=-2",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://duckduckgo.com/"
      },
      format: "html"
    },
    {
      name: "DuckDuckGo Lite",
      method: "GET",
      url: "https://lite.duckduckgo.com/lite/?q=" + encodeURIComponent(query) + "&kp=-2&kl=us-en",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://duckduckgo.com/"
      },
      format: "html"
    },
    {
      name: "Bing RSS",
      method: "GET",
      url: "https://www.bing.com/search?format=rss&q=" + encodeURIComponent(query),
      headers: {
        "User-Agent": "VeilBrowse/1.0",
        "Accept": "application/rss+xml, application/xml, text/xml;q=0.9",
        "Accept-Language": "en-US,en;q=0.9"
      },
      format: "xml"
    },
    {      name: "Bing",
      method: "GET",
      url: "https://www.bing.com/search?q=" + encodeURIComponent(query) + "&count=20&setlang=en-US",
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.bing.com/"
      },
      format: "html"
    }
  ];

  const escapeHtml = (value) => String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

  function extractResults($, providerName) {
    const results = [];
    const seen = new Set();

    const cleanText = (value) => String(value || "").replace(/\s+/g, " ").trim();

    const decodeRedirect = (href, provider) => {
      try {
        const parsed = new URL(href, provider.startsWith("Bing")
          ? "https://www.bing.com/"
          : "https://duckduckgo.com/");

        for (const key of ["uddg", "url", "u"]) {
          const encoded = parsed.searchParams.get(key);
          if (encoded) {
            try {
              return decodeURIComponent(encoded);
            } catch {
              return encoded;
            }
          }
        }

        return parsed.href;
      } catch {
        return href;
      }
    };

    const add = (title, href, snippet = "") => {
      const cleanTitle = cleanText(title);
      if (!cleanTitle || cleanTitle.length < 2 || !href) return;

      let resolved = String(href).trim();
      if (!resolved || resolved.startsWith("#") || /^(?:javascript|mailto|tel):/i.test(resolved)) return;

      resolved = decodeRedirect(resolved, providerName);

      try {
        const baseUrl = providerName.startsWith("Bing")
          ? "https://www.bing.com/"
          : "https://duckduckgo.com/";
        const parsed = new URL(resolved, baseUrl);

        if (!["http:", "https:"].includes(parsed.protocol)) return;

        const hostname = parsed.hostname.toLowerCase();

        // Search-engine navigation links are not useful result destinations.
        if (
          providerName.startsWith("DuckDuckGo") &&
          (hostname === "duckduckgo.com" || hostname.endsWith(".duckduckgo.com"))
        ) return;

        if (
          providerName.startsWith("Bing") &&
          (hostname === "bing.com" || hostname.endsWith(".bing.com"))
        ) return;

        const key = parsed.href;
        if (seen.has(key)) return;
        seen.add(key);

        results.push({
          title: cleanTitle,
          href: parsed.href,
          snippet: cleanText(snippet)
        });
      } catch {}
    };

    if (providerName === "Bing RSS") {
      $("item, entry").each((_, element) => {
        const row = $(element);
        const title = row.find("title").first().text();
        let href = row.find("link").first().text().trim();
        if (!href) href = row.find("link[href]").first().attr("href") || "";
        add(title, href, row.find("description, summary").first().text());
        if (results.length >= 20) return false;
      });
      return results.slice(0, 20);
    }

    // First use the documented/common result structures when present.
    if (providerName === "DuckDuckGo HTML" || providerName === "DuckDuckGo Lite") {
      $(
        ".result a.result__a[href], " +
        "a.result__a[href], " +
        "a.result-link[href]"
      ).each((_, element) => {
        const link = $(element);
        const row = link.closest(".result, article, tr, li, div");
        add(
          link.text(),
          link.attr("href"),
          row.find(".result__snippet, .result__body, .result__description, p, td").last().text()
        );
        if (results.length >= 20) return false;
      });
    }

    if (providerName === "Bing") {
      $("li.b_algo h2 a[href], li.b_algo h3 a[href], #b_results h2 a[href], #b_results h3 a[href]")
        .each((_, element) => {
          const link = $(element);
          const row = link.closest("li, article, div");
          add(
            link.text(),
            link.attr("href"),
            row.find(".b_caption p, p").first().text()
          );
          if (results.length >= 20) return false;
        });
    }

    // Markup changes frequently. As a provider-independent fallback, inspect
    // every external link and use its nearest heading/text as the result.
    // This keeps search functional when DDG/Bing change their CSS classes.
    if (results.length === 0) {
      $("a[href]").each((_, element) => {
        if (results.length >= 20) return false;

        const link = $(element);
        const href = link.attr("href") || "";
        const text = cleanText(link.text());

        if (!text || text.length < 3 || text.length > 300) return;

        let parsed;
        try {
          parsed = new URL(decodeRedirect(href, providerName),
            providerName.startsWith("Bing")
              ? "https://www.bing.com/"
              : "https://duckduckgo.com/");
        } catch {
          return;
        }

        const hostname = parsed.hostname.toLowerCase();
        if (
          hostname === "duckduckgo.com" ||
          hostname.endsWith(".duckduckgo.com") ||
          hostname === "bing.com" ||
          hostname.endsWith(".bing.com")
        ) return;

        const row = link.closest("article, li, tr, .result, div");
        const heading = row.find("h1,h2,h3,h4").first().text();
        const title = cleanText(heading) || text;

        // Ignore obvious page chrome/navigation.
        if (/^(images?|videos?|news|maps|shopping|settings|more|next|previous|sign in|menu)$/i.test(title)) {
          return;
        }

        add(title, href, row.find("p").first().text());
      });
    }

    return results.slice(0, 20);
  }
  function renderSearchPage(results, providerName) {
    const cards = results.length
      ? results.map((result) => {
          const proxied = proxyUrl(result.href, "https://veilbrowse.local/");
          let hostname = "";
          try {
            hostname = new URL(result.href).hostname;
          } catch {}

          return '<article class="result-card">' +
            '<div class="result-url">' + escapeHtml(hostname) + '</div>' +
            '<h2><a href="' + escapeHtml(proxied) + '">' + escapeHtml(result.title) + '</a></h2>' +
            (result.snippet ? '<p>' + escapeHtml(result.snippet) + '</p>' : '') +
            '</article>';
        }).join("")
      : '<div class="empty">No results were found. Try a different search.</div>';

    return '<!doctype html>' +
'<html lang="en"><head>' +
'<meta charset="utf-8">' +
'<meta name="viewport" content="width=device-width,initial-scale=1">' +
'<meta name="referrer" content="no-referrer">' +
'<meta name="robots" content="noindex,nofollow">' +
'<title>' + escapeHtml(query) + ' — VeilBrowse</title>' +
'<style>' +
':root{color-scheme:dark}*{box-sizing:border-box}' +
'body{margin:0;background:#08090c;color:#f4f4f5;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}' +
'.top{position:sticky;top:0;z-index:10;background:rgba(8,9,12,.94);backdrop-filter:blur(14px);border-bottom:1px solid #20232a;padding:10px 20px}' +
'.nav{max-width:980px;margin:0 auto;display:flex;gap:10px;align-items:center}' +
'.brand{color:#fff;text-decoration:none;font-weight:800;letter-spacing:.08em;font-size:14px;white-space:nowrap}' +
'.search-shell{display:flex;flex:1;min-width:0;align-items:flex-start;justify-content:flex-end;gap:8px}' +
'.search-shell form{display:flex;gap:8px;width:min(760px,100%);max-height:56px;overflow:hidden;opacity:1;transform:translateY(0);transition:max-height .24s ease,opacity .2s ease,transform .24s ease;margin:0;padding:0}' +
'.search-shell.collapsed form{max-height:0;opacity:0;transform:translateY(-10px);pointer-events:none;margin:0;padding:0}' +
'.search-toggle{height:40px;border:1px solid #30343d;border-radius:10px;padding:0 14px;background:#111318;color:#aeb5c1;font-family:inherit;font-size:14px;font-weight:600;cursor:pointer;transition:background .16s ease,color .16s ease}' +
'.search-toggle:hover{background:#181b21;color:#fff}' +
'.search-toggle:focus-visible{outline:2px solid #8ab4ff;outline-offset:2px}' +
'input{width:100%;height:40px;border:1px solid #30343d;border-radius:10px;background:#111318;color:#fff;padding:0 14px;font:inherit;outline:none}' +
'input:focus{border-color:#687386;box-shadow:0 0 0 3px rgba(120,130,150,.14)}' +
'button{height:40px;border:0;border-radius:10px;padding:0 16px;background:#f4f4f5;color:#090a0c;font-family:inherit;font-size:14px;font-weight:600;cursor:pointer}' +
'main{max-width:980px;margin:0 auto;padding:30px 20px 60px}' +
'.meta{color:#8d94a1;font-size:13px;margin-bottom:20px}' +
'.provider{color:#6f7785}' +
'.result-card{padding:0 0 25px;margin-bottom:25px;border-bottom:1px solid #1d2026}' +
'.result-url{font-size:12px;color:#7f8795;margin-bottom:5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
'h2{font-size:19px;line-height:1.35;margin:0 0 7px;font-weight:650}' +
'h2 a{color:#8ab4ff;text-decoration:none}' +
'h2 a:hover{text-decoration:underline}' +
'p{margin:0;color:#b8bec9;font-size:14px;line-height:1.55;max-width:760px}' +
'.empty{padding:40px 0;color:#aeb5c1}' +
'@media(max-width:600px){.top{padding:10px}.nav{gap:8px}.brand{display:none}main{padding:24px 14px 50px}}' +
'</style></head><body>' +
'<header class="top"><div class="nav">' +
'<a class="brand" href="/">VEILBROWSE</a>' +
'<div class="search-shell collapsed" id="searchShell">' +
'<form action="/search" method="get">' +
'<input name="q" value="' + escapeHtml(query) + '" aria-label="Search" autocomplete="off" spellcheck="false">' +
'<button type="submit">Search</button>' +
'</form>' +
'<button class="search-toggle" id="collapseSearch" type="button" aria-label="Show search bar" aria-expanded="false">Show</button>' +
'</div></div></header>' +
'<main><div class="meta">Search results for <strong>' + escapeHtml(query) + '</strong> <span class="provider">• Powered by ' + escapeHtml(providerName) + '</span></div>' +
cards +
'</main><script>(function(){const shell=document.getElementById("searchShell");const button=document.getElementById("collapseSearch");const form=shell?.querySelector("form");if(!shell||!button)return;button.addEventListener("click",function(){const collapsed=shell.classList.toggle("collapsed");button.setAttribute("aria-expanded",String(!collapsed));button.setAttribute("aria-label",collapsed?"Show search bar":"Hide search bar");button.textContent=collapsed?"Show":"Hide";if(!collapsed)form?.querySelector("input")?.focus();});})();</script></body></html>';
  }

  let lastError = null;

  for (const provider of providers) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const requestOptions = {
        method: provider.method || "GET",
        signal: controller.signal,
        headers: provider.headers,
        redirect: "follow"
      };
      if (provider.body) requestOptions.body = provider.body;

      const upstream = await fetch(provider.url, requestOptions);
      if (!upstream.ok) {
        lastError = new Error(provider.name + " returned HTTP " + upstream.status);
        continue;
      }

      const body = await upstream.text();
      if (!body || body.length < 200) {
        lastError = new Error(provider.name + " returned an empty response");
        continue;
      }

      const lowerBody = body.toLowerCase();
      if (
        provider.name.startsWith("DuckDuckGo") &&
        (lowerBody.includes("anomaly detected") ||
          lowerBody.includes("unusual traffic") ||
          lowerBody.includes("challenge-form") ||
          lowerBody.includes("challenge-spinner"))
      ) {
        lastError = new Error(provider.name + " returned a challenge page");
        continue;
      }

      const { load } = await import("cheerio");
      const $ = load(body, { decodeEntities: true });
      const results = extractResults($, provider.name);

      if (results.length === 0) {
        lastError = new Error(provider.name + " returned no parseable results");
        continue;
      }

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store, private, max-age=0");
      res.setHeader("Referrer-Policy", "no-referrer");
      return res.send(renderSearchPage(results, provider.name));
    } catch (error) {
      lastError = error;
    } finally {
      clearTimeout(timeout);
    }
  }

  const reason = lastError?.name === "AbortError"
    ? "Search provider timed out. Please try again."
    : lastError?.message?.includes("no parseable results")
      ? "The search provider responded, but VeilBrowse could not read its results. Please try again."
      : "Search is temporarily unavailable from the proxy server. Please try again.";

  return res.status(502).send(
    "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Search unavailable — VeilBrowse</title>" +
    "<style>body{margin:0;background:#08090c;color:#f4f4f5;font-family:system-ui;padding:40px}main{max-width:760px;margin:auto}a{color:#8ab4ff}</style></head>" +
    "<body><main><h1>Search unavailable</h1><p>" + escapeHtml(reason) + "</p><p><a href=\"/\">Back to VeilBrowse</a></p></main></body></html>"
  );
});
app.all("/proxy", async (req, res) => {
  const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";

  if (!rawUrl) {
    return res.status(400).send("Missing URL");
  }

  if (!["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(req.method)) {
    return res.status(405).send("Method not supported");
  }

  // Compatibility fallback for cached clients that send a plain search term
  // through /proxy. Never attempt DNS on a search term.
  if (!/^https?:\/\//i.test(rawUrl)) {
    return res.redirect("/search?q=" + encodeURIComponent(rawUrl));
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