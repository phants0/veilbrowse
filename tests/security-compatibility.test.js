import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const source = await readFile(new URL("../server.js", import.meta.url), "utf8");

test("proxy accepts only explicitly supported HTTP methods", () => {
  assert.match(source, /\["GET",\s*"HEAD",\s*"POST",\s*"PUT",\s*"PATCH",\s*"DELETE",\s*"OPTIONS"\]\.includes\(req\.method\)/);
  assert.match(source, /status\(405\)\.send\("Method not supported"\)/);
});

test("proxy rejects non-HTTP protocols and credential-bearing URLs", () => {
  assert.match(source, /!\["http:",\s*"https:"\]\.includes\(target\.protocol\)/);
  assert.match(source, /target\.username\s*\|\|\s*target\.password/);
});

test("proxy blocks local hostnames and private IP address ranges", () => {
  for (const marker of [
    'host === "localhost"',
    'host.endsWith(".localhost")',
    'host.endsWith(".local")',
    'host === "metadata.google.internal"',
    "a === 10",
    "a === 127",
    "a === 0",
    "a === 169 && b === 254",
    "a === 172 && b >= 16 && b <= 31",
    "a === 192 && b === 168",
    'normalized === "::1"',
    'normalized.startsWith("fc")',
    'normalized.startsWith("fd")',
    'normalized.startsWith("fe80:")'
  ]) assert.ok(source.includes(marker), `Missing SSRF guard: ${marker}`);
  assert.match(source, /addresses\.some\(\(\{\s*address\s*\}\)\s*=>\s*isBlockedAddress\(address\)\)/);
});

test("redirect destinations are revalidated before being fetched", () => {
  assert.match(source, /currentTarget\s*=\s*await assertSafeTarget\(new URL\(location,\s*currentTarget\)\.href\)/);
  assert.match(source, /redirects <= 10/);
  assert.match(source, /status\(508\)\.send\("Too many redirects\."/);
});

test("HTML rewriting covers navigation, new tabs, and common resource URLs", () => {
  for (const entry of [
    '["a", "href"]', '["area", "href"]', '["link", "href"]',
    '["script", "src"]', '["img", "src"]', '["iframe", "src"]',
    '["form", "action"]'
  ]) assert.ok(source.includes(entry), `Missing HTML rewrite target: ${entry}`);
  assert.match(source, /target && !\["_self", "_top", "_parent"\]\.includes\(target\)/);
  assert.match(source, /\$\(element\)\.attr\("target", "_blank"\)/);
  assert.match(source, /runtimeBridgeScript\(currentTarget\.href\)/);
});

test("VeilBrowse shortcuts are installed independently of upstream page handlers", () => {
  assert.match(source, /__VEILBROWSE_OPEN_SEARCH__/);
  assert.match(source, /__VEILBROWSE_TOGGLE_CONSOLE__/);
  assert.match(source, /handleVeilShortcut/);
  assert.match(source, /window\.addEventListener\("keyup", handleVeilShortcutKeyup/);
  assert.match(source, /document\.addEventListener\("keyup", handleVeilShortcutKeyup/);
});

test("Search page exposes both VeilBrowse shortcuts", () => {
  assert.match(source, /veilbrowse-search-console-button/);
  assert.match(source, /consoleKey=event\.altKey&&event\.shiftKey/);
  assert.match(source, /key==="k"/);
});

test("rewriting preserves non-network URL schemes instead of proxying them", () => {
  assert.match(source, /value\.startsWith\("#"\)[\s\S]{0,120}value\.startsWith\("data:"\)[\s\S]{0,120}value\.startsWith\("blob:"\)/);
  assert.match(source, /Only HTTP and HTTPS URLs are supported/);
});

test("proxy responses avoid exposing upstream cookies and hop-by-hop headers", () => {
  for (const header of ["connection", "transfer-encoding", "host", "cookie", "set-cookie"]) {
    assert.ok(source.includes(`"${header}"`), `Missing blocked header: ${header}`);
  }
  assert.match(source, /HttpOnly; SameSite=Lax/);
  assert.match(source, /SESSION_TTL_MS\s*=\s*2\s*\*\s*60\s*\*\s*60\s*\*\s*1000/);
});

test("privacy-sensitive persistence and request logging remain absent", () => {
  assert.match(source, /no persistent browsing-history database/);
  assert.match(source, /no request logging/);
  assert.doesNotMatch(source, /\b(?:winston|morgan)\s*\(/);
});
