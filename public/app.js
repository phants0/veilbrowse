const form = document.querySelector("#go");
const input = document.querySelector("#url");

function looksLikeUrl(value) {
  const trimmed = value.trim();

  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^localhost(?::\d+)?(?:\/|$)/i.test(trimmed)) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:\/|$)/.test(trimmed)) return true;

  try {
    const candidate = new URL("https://" + trimmed);
    return candidate.hostname.includes(".") && !candidate.hostname.endsWith(".");
  } catch {
    return false;
  }
}

function normalizeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) return null;

  try {
    return new URL(trimmed.includes("://") ? trimmed : `https://${trimmed}`);
  } catch {
    return null;
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();

  const value = input.value.trim();
  if (!value) {
    input.focus();
    return;
  }

  if (!looksLikeUrl(value)) {
    window.location.assign(`/search?q=${encodeURIComponent(value)}`);
    return;
  }

  const url = normalizeUrl(value);
  if (!url || !["http:", "https:"].includes(url.protocol)) {
    input.setCustomValidity("Enter a valid website URL or search term.");
    input.reportValidity();
    return;
  }

  input.setCustomValidity("");
  window.location.assign(`/proxy?url=${encodeURIComponent(url.href)}`);
});
