const form = document.querySelector("#go");
const input = document.querySelector("#url");

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

  const url = normalizeUrl(input.value);
  if (!url || !["http:", "https:"].includes(url.protocol)) {
    input.setCustomValidity("Enter a valid HTTP or HTTPS website.");
    input.reportValidity();
    return;
  }

  input.setCustomValidity("");
  window.location.href = `/proxy?url=${encodeURIComponent(url.href)}`;
});
