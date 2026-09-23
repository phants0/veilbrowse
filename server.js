import express from "express";
import dns from "node:dns/promises";
import net from "node:net";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_DIR = fileURLToPath(new URL("./public/", import.meta.url));

app.disable("x-powered-by");

// Serve VeilBrowse's own frontend assets before the proxy/catch-all routes.
// This is required for /styles.css and /app.js to be returned with their
// actual file contents and MIME types in production hosts such as Wasmer.
app.use(express.static(PUBLIC_DIR, {
  index: false,
  fallthrough: true,
  etag: false,
  maxAge: 0
}));
app.set("trust proxy", false);

// Privacy defaults:
// - no request logging
// - no persistent cache
// - no server-side cookie jar
// - no analytics
// - no browsing-history database

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
  "content-encoding",
  "content-language",
  "etag",
  "last-modified",
  "location",
  "accept-ranges",
  "content-range"
];

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(Number.isNaN)) return false;

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

  if (!target.hostname) throw new Error("Missing hostname");

  const host = target.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host === "metadata.google.internal"
  ) {
    throw new Error("Private/local targets are blocked");
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

function rewriteCss(css, baseUrl) {
  return css.replace(
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

      return `url("${proxyUrl(trimmed, baseUrl)}")`;
    }
  );
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

  $("link[href]").each((_, element) => {
    const rel = ($(element).attr("rel") || "").toLowerCase();
    if (rel.includes("stylesheet")) {
      $(element).attr("href", proxyUrl($(element).attr("href"), baseUrl));
    }
  });

  $("[style]").each((_, element) => {
    const value = $(element).attr("style");
    if (value) $(element).attr("style", rewriteCss(value, baseUrl));
  });

  $("style").each((_, element) => {
    const value = $(element).html();
    if (value) $(element).html(rewriteCss(value, baseUrl));
  });

  $("base").remove();
  $("head").prepend(
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex,nofollow">'
  );

  return $.html();
}

function copyResponseHeaders(upstream, response) {
  for (const header of PASS_RESPONSE_HEADERS) {
    const value = upstream.headers.get(header);
    if (value) response.setHeader(header, value);
  }

  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Cache-Control", "no-store, private, max-age=0");
}

app.get("/health", (_req, res) => {
  res.json({ ok: true, persistentStorage: false });
});

app.get("/proxy", async (req, res) => {
  const rawUrl = typeof req.query.url === "string" ? req.query.url : "";

  if (!rawUrl) {
    return res.status(400).send("Missing URL");
  }

  let target;
  try {
    target = await assertSafeTarget(rawUrl);
  } catch (error) {
    return res.status(400).send(error.message);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    let currentTarget = target;
    let upstream;

    for (let redirects = 0; redirects <= 10; redirects++) {
      upstream = await fetch(currentTarget, {
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
          "Accept":
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.9"
        }
      });

      if (![301, 302, 303, 307, 308].includes(upstream.status)) break;

      const location = upstream.headers.get("location");
      if (!location) break;

      currentTarget = await assertSafeTarget(new URL(location, currentTarget).href);

      if (redirects === 10) {
        return res.status(508).send("Too many redirects.");
      }
    }

    copyResponseHeaders(upstream, res);

    const contentType = (upstream.headers.get("content-type") || "").toLowerCase();

    if (contentType.includes("text/html")) {
      const html = await upstream.text();
      const rewritten = await rewriteHtml(html, upstream.url || target.href);

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(upstream.status).send(rewritten);
    }

    if (contentType.includes("text/css")) {
      const css = await upstream.text();
      res.setHeader("Content-Type", "text/css; charset=utf-8");
      return res.status(upstream.status).send(rewriteCss(css, upstream.url || target.href));
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
