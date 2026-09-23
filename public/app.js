const form = document.querySelector("#go");
const input = document.querySelector("#url");
const openFilesButton = document.querySelector("#openFiles");
const localFilesInput = document.querySelector("#localFiles");
const fileWorkspace = document.querySelector("#fileWorkspace");
const addFilesButton = document.querySelector("#addFiles");
const closeFilesButton = document.querySelector("#closeFiles");
const fileList = document.querySelector("#fileList");
const workspaceStatus = document.querySelector("#workspaceStatus");
const fileViewer = document.querySelector("#fileViewer");
const activeFileType = document.querySelector("#activeFileType");
const runSelectedButton = document.querySelector("#runSelected");
const runAllButton = document.querySelector("#runAll");
const stopScriptsButton = document.querySelector("#stopScripts");
const clearConsoleButton = document.querySelector("#clearConsole");
const selectAllButton = document.querySelector("#selectAllFiles");
const consoleOutput = document.querySelector("#consoleOutput");
const consoleState = document.querySelector("#consoleState");
const scriptSandbox = document.querySelector("#scriptSandbox");

const files = new Map();
let activeFileName = null;
let running = false;
let runToken = 0;

function hasExplicitScheme(value) {
  return /^[a-z][a-z0-9+.-]*:/i.test(value);
}

function looksLikeUrl(value) {
  const trimmed = value.trim();
  if (/^(?:https?:\/\/|\/\/)/i.test(trimmed)) return true;
  if (/^localhost(?::\d+)?(?:[/?#]|$)/i.test(trimmed)) return true;
  if (/^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:[/?#]|$)/.test(trimmed)) return true;
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
    const candidate = /^(?:https?:\/\/|\/\/)/i.test(trimmed)
      ? (trimmed.startsWith("//") ? "https:" + trimmed : trimmed)
      : "https://" + trimmed;
    return new URL(candidate);
  } catch {
    return null;
  }
}

form?.addEventListener("submit", (event) => {
  event.preventDefault();
  const value = input.value.trim();
  if (!value) {
    input.focus();
    return;
  }

  if (hasExplicitScheme(value) && !/^(?:https?:\/\/)/i.test(value)) {
    input.setCustomValidity("Only HTTP and HTTPS website URLs are supported.");
    input.reportValidity();
    return;
  }

  if (!looksLikeUrl(value)) {
    input.setCustomValidity("");
    window.location.assign("/search?q=" + encodeURIComponent(value));
    return;
  }

  const url = normalizeUrl(value);
  if (!url || !["http:", "https:"].includes(url.protocol)) {
    input.setCustomValidity("Enter a valid HTTP or HTTPS website URL.");
    input.reportValidity();
    return;
  }

  input.setCustomValidity("");
  window.location.assign("/proxy?url=" + encodeURIComponent(url.href));
});

function extension(name) {
  const match = name.toLowerCase().match(/\.([a-z0-9]+)$/);
  return match ? match[1] : "";
}

function kindOf(file) {
  const ext = extension(file.name);
  if (["js", "mjs"].includes(ext)) return "script";
  if (ext === "html" || ext === "htm") return "html";
  if (ext === "css") return "css";
  if (["json", "xml", "txt", "md", "ts"].includes(ext)) return "text";
  if (["pdf"].includes(ext)) return "pdf";
  if (["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp"].includes(ext)) return "image";
  return "unknown";
}

function isRunnable(file) {
  return ["script", "html"].includes(kindOf(file));
}

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}

function logConsole(message, type = "log") {
  const line = document.createElement("div");
  line.className = "console-line " + type;
  line.textContent = message;
  consoleOutput.appendChild(line);
  consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

function setRunning(value) {
  running = value;
  consoleState.textContent = value ? "Running" : "Idle";
  consoleState.classList.toggle("running", value);
  runSelectedButton.disabled = value || ![...files.values()].some((file) => file.selected && kindOf(file) === "script");
  runAllButton.disabled = value || ![...files.values()].some((file) => kindOf(file) === "script");
  stopScriptsButton.disabled = !value;
}

function renderFileList() {
  fileList.innerHTML = "";
  if (!files.size) {
    fileList.innerHTML = '<div class="empty-files">Choose files to begin.</div>';
    workspaceStatus.textContent = "No files loaded";
    runSelectedButton.disabled = true;
    runAllButton.disabled = true;
    return;
  }

  const groups = new Map();
  for (const file of files.values()) {
    const group = kindOf(file);
    if (!groups.has(group)) groups.set(group, []);
    groups.get(group).push(file);
  }

  for (const [group, groupFiles] of groups) {
    const heading = document.createElement("div");
    heading.className = "file-group-heading";
    heading.textContent = group === "script" ? "Scripts" : group.charAt(0).toUpperCase() + group.slice(1);
    fileList.appendChild(heading);

    for (const file of groupFiles) {
      const row = document.createElement("label");
      row.className = "file-row" + (file.name === activeFileName ? " active" : "");

      const check = document.createElement("input");
      check.type = "checkbox";
      check.checked = file.selected;
      check.disabled = kindOf(file) !== "script";
      check.addEventListener("change", () => {
        file.selected = check.checked;
        updateRunButtons();
      });

      const name = document.createElement("span");
      name.className = "file-name";
      name.textContent = file.name;

      const badge = document.createElement("span");
      badge.className = "file-badge";
      badge.textContent = kindOf(file);

      row.append(check, name, badge);
      row.addEventListener("click", (event) => {
        if (event.target !== check) openFile(file.name);
      });
      fileList.appendChild(row);
    }
  }

  workspaceStatus.textContent = files.size + (files.size === 1 ? " file" : " files") + " loaded";
  updateRunButtons();
}

function updateRunButtons() {
  const scripts = [...files.values()];
  runSelectedButton.disabled = running || !scripts.some((file) => file.selected && kindOf(file) === "script");
  runAllButton.disabled = running || !scripts.some((file) => kindOf(file) === "script");
}

async function openFile(name) {
  const file = files.get(name);
  if (!file) return;
  activeFileName = name;
  renderFileList();

  const kind = kindOf(file);
  activeFileType.textContent = kind.toUpperCase();

  if (kind === "image") {
    const url = URL.createObjectURL(file);
    fileViewer.innerHTML = "";
    const image = document.createElement("img");
    image.className = "local-image";
    image.src = url;
    image.alt = file.name;
    fileViewer.appendChild(image);
    return;
  }

  if (kind === "pdf") {
    const url = URL.createObjectURL(file);
    fileViewer.innerHTML = "";
    const frame = document.createElement("iframe");
    frame.className = "local-preview";
    frame.src = url;
    frame.title = file.name;
    fileViewer.appendChild(frame);
    return;
  }

  const text = await file.text();

  if (kind === "html") {
    const frame = document.createElement("iframe");
    frame.className = "local-preview";
    frame.sandbox.add("allow-scripts");
    frame.srcdoc = text;
    fileViewer.innerHTML = "";
    fileViewer.appendChild(frame);
    return;
  }

  const pre = document.createElement("pre");
  pre.className = "code-viewer";
  pre.textContent = text;
  fileViewer.innerHTML = "";
  fileViewer.appendChild(pre);
}

function addFiles(fileArray) {
  for (const file of fileArray) {
    files.set(file.name, Object.assign(file, {
      selected: kindOf(file) === "script"
    }));
  }
  if (!activeFileName && fileArray[0]) activeFileName = fileArray[0].name;
  fileWorkspace.hidden = false;
  renderFileList();
  if (activeFileName) openFile(activeFileName);
}

async function runScripts(selectedOnly) {
  if (running) return;

  const scripts = [...files.values()].filter((file) =>
    kindOf(file) === "script" && (!selectedOnly || file.selected)
  );

  if (!scripts.length) return;

  const token = ++runToken;
  setRunning(true);
  logConsole("Starting " + scripts.length + (scripts.length === 1 ? " script..." : " scripts..."), "system");

  const scriptSources = [];
  for (const file of scripts) {
    try {
      scriptSources.push({
        name: file.name,
        source: await file.text()
      });
    } catch (error) {
      logConsole(file.name + ": " + error.message, "error");
    }
  }

  if (token !== runToken) return;

  const payload = scriptSources.map(({name, source}) => {
    const safeName = JSON.stringify(name);
    const safeSource = source.replace(/<\/script/gi, "<\\/script");
    return `
      (function(){
        const __file = ${safeName};
        const __send = (type, args) => parent.postMessage({
          source: "veilbrowse-local-script",
          type,
          file: __file,
          args: args.map((value) => {
            try { return typeof value === "string" ? value : JSON.stringify(value); }
            catch { return String(value); }
          })
        }, "*");
        const console = {
          log: (...args) => __send("log", args),
          info: (...args) => __send("info", args),
          warn: (...args) => __send("warn", args),
          error: (...args) => __send("error", args)
        };
        try {
          ${safeSource}
        } catch (error) {
          __send("error", [error?.stack || error?.message || String(error)]);
        }
      })();
    `;
  }).join("\n");

  scriptSandbox.srcdoc = `
    <!doctype html>
    <meta charset="utf-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; connect-src 'none'; object-src 'none'; base-uri 'none';">
    <script>
      window.addEventListener("error", event => parent.postMessage({
        source: "veilbrowse-local-script", type: "error", file: "sandbox",
        args: [event.message || "Script error"]
      }, "*"));
    <\/script>
    <script>${payload.replace(/<\/script/gi, "<\\/script")}</script>
    <script>
      parent.postMessage({source:"veilbrowse-local-script",type:"done",file:"sandbox",args:[]}, "*");
    <\/script>
  `;
}

window.addEventListener("message", (event) => {
  if (event.source !== scriptSandbox.contentWindow || event.data?.source !== "veilbrowse-local-script") return;
  const data = event.data;
  if (data.type === "done") {
    setRunning(false);
    logConsole("Finished.", "system");
    return;
  }
  const prefix = data.file ? "[" + data.file + "] " : "";
  logConsole(prefix + (data.args || []).join(" "), data.type === "error" ? "error" : data.type === "warn" ? "warn" : "");
});

function stopScripts() {
  runToken++;
  scriptSandbox.srcdoc = "";
  setRunning(false);
  logConsole("Execution stopped.", "system");
}

openFilesButton?.addEventListener("click", () => localFilesInput.click());
addFilesButton?.addEventListener("click", () => localFilesInput.click());
localFilesInput?.addEventListener("change", () => {
  addFiles([...localFilesInput.files]);
  localFilesInput.value = "";
});

runSelectedButton?.addEventListener("click", () => runScripts(true));
runAllButton?.addEventListener("click", () => runScripts(false));
stopScriptsButton?.addEventListener("click", stopScripts);
clearConsoleButton?.addEventListener("click", () => {
  consoleOutput.textContent = "";
  consoleState.textContent = "Idle";
});
selectAllButton?.addEventListener("click", () => {
  for (const file of files.values()) {
    if (kindOf(file) === "script") file.selected = true;
  }
  renderFileList();
});
closeFilesButton?.addEventListener("click", () => {
  stopScripts();
  fileWorkspace.hidden = true;
});
fileWorkspace?.addEventListener("click", (event) => {
  if (event.target.matches("[data-close-files]")) {
    stopScripts();
    fileWorkspace.hidden = true;
  }
});
