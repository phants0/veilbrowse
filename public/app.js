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

const FILE_TYPES = {
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  ts: "typescript",
  tsx: "typescript",
  jsx: "javascript",
  py: "python",
  pyw: "python",
  java: "java",
  c: "c",
  h: "c",
  cpp: "cpp",
  cc: "cpp",
  cxx: "cpp",
  hpp: "cpp",
  cs: "csharp",
  go: "go",
  rs: "rust",
  rb: "ruby",
  php: "php",
  swift: "swift",
  kt: "kotlin",
  kts: "kotlin",
  scala: "scala",
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  ps1: "powershell",
  sql: "sql",
  css: "css",
  scss: "css",
  less: "css",
  html: "html",
  htm: "html",
  xml: "xml",
  svg: "image",
  json: "json",
  jsonc: "json",
  yaml: "yaml",
  yml: "yaml",
  toml: "toml",
  md: "markdown",
  markdown: "markdown",
  txt: "text",
  csv: "csv",
  pdf: "pdf",
  png: "image",
  jpg: "image",
  jpeg: "image",
  gif: "image",
  webp: "image",
  bmp: "image",
  wasm: "wasm"
};

function extension(name) {
  const filename = String(name || "").trim();
  const lastDot = filename.lastIndexOf(".");
  if (lastDot <= 0 || lastDot === filename.length - 1) return "";
  return filename.slice(lastDot + 1).toLowerCase();
}

function kindOf(file) {
  const ext = extension(file?.name);
  return FILE_TYPES[ext] || "unknown";
}

const LANGUAGE_LABELS = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  python: "Python",
  java: "Java",
  c: "C",
  cpp: "C++",
  csharp: "C#",
  go: "Go",
  rust: "Rust",
  ruby: "Ruby",
  php: "PHP",
  swift: "Swift",
  kotlin: "Kotlin",
  scala: "Scala",
  shell: "Shell",
  powershell: "PowerShell",
  sql: "SQL",
  css: "CSS",
  html: "HTML",
  xml: "XML",
  json: "JSON",
  yaml: "YAML",
  toml: "TOML",
  markdown: "Markdown",
  csv: "CSV",
  text: "Text",
  wasm: "WebAssembly",
  image: "Image",
  pdf: "PDF",
  unknown: "Unknown"
};

const RUNNABLE_KINDS = new Set(["javascript", "html"]);

function displayKind(kind) {
  return LANGUAGE_LABELS[kind] || kind.toUpperCase();
}

function isRunnable(file) {
  return RUNNABLE_KINDS.has(kindOf(file));
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}

const HIGHLIGHT_RULES = {
  javascript: {
    comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g],
    strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g, /\`(?:\\\\.|[^\`\\\\])*\`/g],
    keywords: /\b(?:as|async|await|break|case|catch|class|const|continue|debugger|default|delete|do|else|export|extends|finally|for|from|function|get|if|import|in|instanceof|let|new|of|return|set|static|super|switch|this|throw|try|typeof|var|void|while|with|yield)\b/g,
    literals: /\b(?:true|false|null|undefined|NaN|Infinity)\b/g,
    numbers: /\b(?:0x[\da-f]+|0b[01]+|0o[0-7]+|(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)\b/gi
  },
  typescript: {
    comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g],
    strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g, /\`(?:\\\\.|[^\`\\\\])*\`/g],
    keywords: /\b(?:as|async|await|break|case|catch|class|const|continue|declare|default|delete|do|else|enum|export|extends|finally|for|from|function|if|implements|import|in|infer|interface|keyof|let|module|namespace|new|of|private|protected|public|readonly|return|static|super|switch|this|throw|try|type|typeof|var|void|while|with|yield)\b/g,
    literals: /\b(?:true|false|null|undefined|never|unknown|any|void)\b/g,
    numbers: /\b(?:0x[\da-f]+|0b[01]+|0o[0-7]+|(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)\b/gi
  },
  python: {
    comments: /#[^\\n]*/g,
    strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g, /"""[\\s\\S]*?"""/g, /'''[\\s\\S]*?'''/g],
    keywords: /\b(?:and|as|assert|async|await|break|case|class|continue|def|del|elif|else|except|finally|for|from|global|if|import|in|is|lambda|match|nonlocal|not|or|pass|raise|return|try|while|with|yield)\b/g,
    literals: /\b(?:True|False|None|NotImplemented|Ellipsis)\b/g,
    numbers: /\b(?:0x[\da-f]+|0b[01]+|0o[0-7]+|(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)\b/gi
  },
  java: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:abstract|assert|boolean|break|byte|case|catch|char|class|const|continue|default|do|double|else|enum|extends|final|finally|float|for|if|implements|import|instanceof|int|interface|long|native|new|package|private|protected|public|return|short|static|strictfp|super|switch|synchronized|this|throw|throws|transient|try|void|volatile|while)\b/g, literals: /\b(?:true|false|null)\b/g, numbers: /\b\d+(?:\.\d+)?[fLd]?\b/gi },
  c: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:auto|break|case|char|const|continue|default|do|double|else|enum|extern|float|for|goto|if|inline|int|long|register|restrict|return|short|signed|sizeof|static|struct|switch|typedef|union|unsigned|void|volatile|while)\b/g, literals: /\b(?:true|false|NULL)\b/g, numbers: /\b(?:0x[\da-f]+|\d+(?:\.\d+)?)[uUlLfF]*\b/gi },
  cpp: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:alignas|auto|bool|break|case|catch|char|class|const|constexpr|continue|default|delete|do|double|else|enum|explicit|export|extern|false|float|for|friend|if|inline|int|long|namespace|new|nullptr|operator|private|protected|public|return|short|signed|sizeof|static|struct|switch|template|this|throw|true|try|typedef|typename|union|unsigned|using|virtual|void|volatile|while)\b/g, literals: /\b(?:true|false|nullptr)\b/g, numbers: /\b(?:0x[\da-f]+|0b[01]+|\d+(?:\.\d+)?)[uUlLfF]*\b/gi },
  csharp: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [@"(?:\\\\.|[^"\\\\])*".replace("@",""), /"(?:\\\\.|[^"\\\\])*"/g], keywords: /\b(?:abstract|as|base|bool|break|byte|case|catch|char|class|const|continue|decimal|default|delegate|do|double|else|enum|event|explicit|extern|false|finally|fixed|float|for|foreach|if|implicit|in|int|interface|internal|is|lock|long|namespace|new|null|object|operator|out|override|params|private|protected|public|readonly|ref|return|sbyte|sealed|short|sizeof|stackalloc|static|string|struct|switch|this|throw|true|try|typeof|uint|ulong|unchecked|unsafe|ushort|using|virtual|void|volatile|while)\b/g, literals: /\b(?:true|false|null)\b/g, numbers: /\b\d+(?:\.\d+)?[fDmM]?\b/gi },
  go: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /\`[\\s\\S]*?\`/g], keywords: /\b(?:break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go|goto|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b/g, literals: /\b(?:true|false|nil|iota)\b/g, numbers: /\b(?:0x[\da-f]+|0b[01]+|\d+(?:\.\d+)?)\b/gi },
  rust: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /r#*"[^"]*"#*/g], keywords: /\b(?:as|async|await|break|const|continue|crate|dyn|else|enum|extern|fn|for|if|impl|in|let|loop|match|mod|move|mut|pub|ref|return|self|Self|static|struct|super|trait|type|unsafe|use|where|while)\b/g, literals: /\b(?:true|false|Some|None)\b/g, numbers: /\b(?:0x[\da-f]+|0b[01]+|\d+(?:\.\d+)?)\b/gi },
  ruby: { comments: /#[^\\n]*/g, strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:alias|and|begin|break|case|class|def|defined|do|else|elsif|end|ensure|false|for|if|in|module|next|nil|not|or|redo|rescue|retry|return|self|super|then|true|undef|unless|until|when|while|yield)\b/g, literals: /\b(?:true|false|nil)\b/g, numbers: /\b\d+(?:\.\d+)?\b/g },
  php: { comments: [/\/\/[^\\n]*/g, /#[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:abstract|and|array|as|break|callable|case|catch|class|const|continue|default|do|echo|else|elseif|empty|extends|final|finally|fn|for|foreach|function|global|if|implements|include|interface|namespace|new|null|or|private|protected|public|require|return|static|switch|throw|trait|try|use|var|while|yield)\b/g, literals: /\b(?:true|false|null)\b/g, numbers: /\b\d+(?:\.\d+)?\b/g },
  swift: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g], keywords: /\b(?:actor|associatedtype|break|case|catch|class|continue|defer|deinit|do|else|enum|extension|fallthrough|for|func|guard|if|import|in|indirect|init|inout|internal|is|let|mutating|nil|open|operator|private|protocol|public|repeat|return|self|static|struct|subscript|super|switch|throw|try|typealias|var|while)\b/g, literals: /\b(?:true|false|nil)\b/g, numbers: /\b\d+(?:\.\d+)?\b/g },
  kotlin: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g, /"""[\\s\\S]*?"""/g], keywords: /\b(?:as|break|class|continue|do|else|false|for|fun|if|in|interface|is|null|object|package|return|super|this|throw|true|try|typealias|typeof|val|var|when|while)\b/g, literals: /\b(?:true|false|null)\b/g, numbers: /\b\d+(?:\.\d+)?\b/g },
  scala: { comments: [/\/\/[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/"(?:\\\\.|[^"\\\\])*"/g], keywords: /\b(?:abstract|case|catch|class|def|do|else|extends|false|final|finally|for|forSome|if|implicit|import|lazy|match|new|null|object|override|package|private|protected|return|sealed|super|this|throw|trait|try|true|type|val|var|while|with|yield)\b/g, literals: /\b(?:true|false|null)\b/g, numbers: /\b\d+(?:\.\d+)?\b/g },
  shell: { comments: /#[^\\n]*/g, strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:if|then|else|elif|fi|for|in|do|done|case|esac|while|function|select|until)\b/g, literals: /\b(?:true|false)\b/g, numbers: /\b\d+\b/g },
  powershell: { comments: /#[^\\n]*/g, strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /\b(?:begin|break|catch|class|continue|data|define|do|dynamicparam|else|elseif|end|exit|filter|finally|for|foreach|from|function|if|in|param|process|return|switch|throw|trap|try|until|using|while)\b/gi, literals: /\b(?:true|false|null)\b/gi, numbers: /\b\d+(?:\.\d+)?\b/g },
  sql: { comments: [/--[^\\n]*/g, /\/\*[\\s\\S]*?\*\//g], strings: [/'(?:''|[^'])*'/g, /"(?:\\"|[^"])*"/g], keywords: /\b(?:select|from|where|insert|into|values|update|set|delete|create|alter|drop|table|index|join|inner|left|right|full|outer|on|as|and|or|not|null|is|in|between|like|group|by|order|having|limit|offset|distinct|union|all|case|when|then|else|end|primary|key|foreign|references|view|database)\b/gi, literals: /\b(?:true|false|null)\b/gi, numbers: /\b\d+(?:\.\d+)?\b/g
  }
};

Object.assign(HIGHLIGHT_RULES, { css: { comments: /\/\*[\s\S]*?\*\//g, strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /@[a-z-]+/gi, literals: /\b(?:inherit|initial|unset|none|auto|block|inline|flex|grid)\b/gi, numbers: /\b\d+(?:\.\d+)?(?:px|em|rem|%|vh|vw|s|ms)?\b/gi }, xml: { comments: /<!--[\\s\\S]*?-->/g, strings: [/"[^"]*"/g, /'[^']*'/g], keywords: /<\/?[a-z][\w:-]*/gi }, markdown: { comments: /^\s*>.*$/gm, keywords: /^\s*#{1,6}\s.*$/gm, literals: /\*\*[^*]+\*\*|__[^_]+__/g }, toml: { comments: /#[^\n]*/g, strings: [/"(?:\\\\.|[^"\\\\])*"/g, /'(?:\\\\.|[^'\\\\])*'/g], keywords: /(^|\n)\s*[A-Za-z_][\w.-]*(?=\s*=)/g, literals: /\b(?:true|false)\b/gi, numbers: /\b\d+(?:\.\d+)?\b/g } });

function highlightCode(source, language) {
  if (language === "json" || language === "yaml" || language === "toml") {
    return highlightStructured(source, language);
  }

  const rules = HIGHLIGHT_RULES[language];
  if (!rules) return escapeHtml(source);

  const tokens = [];
  const stash = (html, className) => {
    const id = tokens.length;
    tokens.push('<span class="tok-' + className + '">' + html + '</span>');
    return " " + id + " ";
  };

  let value = escapeHtml(source);

  const patterns = [];
  (rules.comments || []).forEach((pattern) => patterns.push(["comment", pattern]));
  (rules.strings || []).forEach((pattern) => patterns.push(["string", pattern]));
  if (rules.keywords) patterns.push(["keyword", rules.keywords]);
  if (rules.literals) patterns.push(["literal", rules.literals]);
  if (rules.numbers) patterns.push(["number", rules.numbers]);

  // Protect comments/strings first, then highlight syntax in the remaining text.
  for (const [className, pattern] of patterns.slice(0, (rules.comments || []).length + (rules.strings || []).length)) {
    value = value.replace(pattern, (match) => stash(match, className));
  }

  const rest = value.replace(/ d+ /g, "");
  const placeholders = value.match(/ d+ /g) || [];
  const rebuilt = rest.replace(rules.keywords || /(?!)/g, (match) => stash(match, "keyword"))
    .replace(rules.literals || /(?!)/g, (match) => stash(match, "literal"))
    .replace(rules.numbers || /(?!)/g, (match) => stash(match, "number"));

  let output = rebuilt;
  let index = 0;
  output = value.replace(/ d+ |[sS]+/g, (part) => {
    if (/^ d+ $/.test(part)) return tokens[Number(part.slice(1, -1))];
    const highlighted = part.replace(rules.keywords || /(?!)/g, (match) => stash(match, "keyword"))
      .replace(rules.literals || /(?!)/g, (match) => stash(match, "literal"))
      .replace(rules.numbers || /(?!)/g, (match) => stash(match, "number"));
    index++;
    return highlighted;
  });

  return output;
}

function highlightStructured(source, language) {
  let html = escapeHtml(source);
  if (language === "json") {
    html = html
      .replace(/(&quot;(?:\\.|[^&])*?&quot;)(\s*:)/g, '<span class="tok-property">$1</span>$2')
      .replace(/(&quot;(?:\\.|[^&])*?&quot;)/g, '<span class="tok-string">$1</span>')
      .replace(/\b(true|false|null)\b/g, '<span class="tok-literal">$1</span>')
      .replace(/\b-?\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/gi, '<span class="tok-number">function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}</span>');
  } else {
    html = html
      .replace(/(^|\n)(\s*)([A-Za-z_][\w.-]*)(\s*:)/g, '$1$2<span class="tok-property">$3</span>$4')
      .replace(/(["'])(?:\\.|(?!\1).)*\1/g, '<span class="tok-string">function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}</span>')
      .replace(/\b(?:true|false|null|yes|no)\b/gi, '<span class="tok-literal">function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[char]));
}</span>');
  }
  return html;
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
      badge.textContent = displayKind(kindOf(file));

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


function normalizeLocalPath(value) {
  return String(value || "")
    .trim()
    .replace(/\\/g, "/")
    .replace(/^\.\/+/, "")
    .split("/")
    .filter((part) => part && part !== ".")
    .reduce((parts, part) => {
      if (part === "..") parts.pop();
      else parts.push(part);
      return parts;
    }, [])
    .join("/");
}

function findWorkspaceFile(reference, currentName = "") {
  const raw = String(reference || "").trim();
  if (!raw || /^(?:https?:|data:|blob:|javascript:|mailto:|#)/i.test(raw)) return null;

  const withoutQuery = raw.split(/[?#]/, 1)[0];
  const currentPath = normalizeLocalPath(currentName);
  const currentDir = currentPath.includes("/")
    ? currentPath.slice(0, currentPath.lastIndexOf("/"))
    : "";

  const candidates = [
    normalizeLocalPath(withoutQuery),
    normalizeLocalPath(currentDir ? currentDir + "/" + withoutQuery : withoutQuery)
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (files.has(candidate)) return files.get(candidate);
  }

  const basename = candidates[candidates.length - 1]?.split("/").pop();
  if (basename && files.has(basename)) return files.get(basename);

  return [...files.values()].find((workspaceFile) => {
    const normalized = normalizeLocalPath(workspaceFile.name);
    return candidates.includes(normalized) || (basename && normalized.endsWith("/" + basename));
  }) || null;
}

async function buildHtmlProject(file) {
  let html = await file.text();
  const scripts = [];
  const styles = [];
  const linkedFiles = new Set();

  const scriptPattern = /<script\b([^>]*?)\bsrc\s*=\s*["']([^"']+)["']([^>]*)>\s*<\/script\s*>/gi;
  html = html.replace(scriptPattern, (full, before, src, after) => {
    const dependency = findWorkspaceFile(src, file.name);
    if (!dependency || kindOf(dependency) !== "script") return full;

    linkedFiles.add(dependency.name);
    scripts.push({ name: dependency.name, source: null, attrs: before + after });
    return "<!-- VeilBrowse local script: " + escapeHtml(dependency.name) + " -->";
  });

  const stylesheetPattern = /<link\b([^>]*?)\bhref\s*=\s*["']([^"']+)["']([^>]*)>/gi;
  html = html.replace(stylesheetPattern, (full, before, href, after) => {
    const dependency = findWorkspaceFile(href, file.name);
    if (!dependency || kindOf(dependency) !== "css") return full;

    linkedFiles.add(dependency.name);
    styles.push({ name: dependency.name, source: null });
    return "<!-- VeilBrowse local stylesheet: " + escapeHtml(dependency.name) + " -->";
  });

  for (const entry of scripts) {
    const dependency = files.get(entry.name);
    if (dependency) entry.source = await dependency.text();
  }
  for (const entry of styles) {
    const dependency = files.get(entry.name);
    if (dependency) entry.source = await dependency.text();
  }

  const bridge =
    "<script>\n" +
    "(function () {\n" +
    "  const __send = (type, args) => parent.postMessage({source: \"veilbrowse-local-html\", type, file: " + JSON.stringify(file.name) + ", args: args.map((value) => { try { return typeof value === \"string\" ? value : JSON.stringify(value); } catch { return String(value); } })}, \"*\");\n" +
    "  const __console = window.console;\n" +
    "  window.console = {\n" +
    "    log: (...args) => { __console.log(...args); __send(\"log\", args); },\n" +
    "    info: (...args) => { __console.info(...args); __send(\"info\", args); },\n" +
    "    warn: (...args) => { __console.warn(...args); __send(\"warn\", args); },\n" +
    "    error: (...args) => { __console.error(...args); __send(\"error\", args); }\n" +
    "  };\n" +
    "  window.addEventListener(\"error\", (event) => __send(\"error\", [event.error?.stack || event.message || \"Script error\"]));\n" +
    "  window.addEventListener(\"unhandledrejection\", (event) => __send(\"error\", [event.reason?.stack || event.reason?.message || String(event.reason)]));\n" +
    "})();\n" +
    "</script>";

  const styleBlocks = styles.map((entry) => {
    const safeSource = String(entry.source || "").replace(/<\/style/gi, "<\\/style");
    return "<style data-veilbrowse-file=\"" + escapeHtml(entry.name) + "\">\n" + safeSource + "\n</style>";
  }).join("\n");

  const scriptBlocks = scripts.map((entry) => {
    const safeSource = String(entry.source || "").replace(/<\/script/gi, "<\\/script");
    const isModule = /\btype\s*=\s*["']module["']/i.test(entry.attrs || "");
    return "<script" + (isModule ? " type=\"module\"" : "") + " data-veilbrowse-file=\"" + escapeHtml(entry.name) + "\">\n" + safeSource + "\n</script>";
  }).join("\n");

  if (/<head\b[^>]*>/i.test(html)) {
    html = html.replace(/<head\b[^>]*>/i, (tag) => tag + "\n" + bridge + "\n" + styleBlocks);
  } else {
    html = bridge + "\n" + styleBlocks + "\n" + html;
  }

  if (/<\/body\s*>/i.test(html)) {
    html = html.replace(/<\/body\s*>/i, scriptBlocks + "\n</body>");
  } else {
    html += "\n" + scriptBlocks;
  }

  const csp = '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; img-src data: blob:; font-src data:; connect-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\';">';
  html = /<head\b/i.test(html)
    ? html.replace(/<head\b([^>]*)>/i, "<head$1>\n" + csp)
    : csp + "\n" + html;

  if (linkedFiles.size) {
    logConsole("HTML linked " + linkedFiles.size + " local file" + (linkedFiles.size === 1 ? "" : "s") + ".", "system");
  }

  return html;
}

async function openFile(name) {
  const file = files.get(name);
  if (!file) return;
  activeFileName = name;
  renderFileList();

  const kind = kindOf(file);
  activeFileType.textContent = displayKind(kind);

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
    frame.title = file.name;
    frame.srcdoc = await buildHtmlProject(file);
    fileViewer.innerHTML = "";
    fileViewer.appendChild(frame);
    return;
  }

  const pre = document.createElement("pre");
  pre.className = "code-viewer";

  let displayText = text;
  if (kind === "json") {
    try {
      displayText = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      displayText = text;
    }
  }

  pre.innerHTML = highlightCode(displayText, kind);
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
  const isScriptRunner = event.source === scriptSandbox.contentWindow && event.data?.source === "veilbrowse-local-script";
  const htmlFrame = fileViewer.querySelector("iframe.local-preview");
  const isHtmlPreview = htmlFrame && event.source === htmlFrame.contentWindow && event.data?.source === "veilbrowse-local-html";
  if (!isScriptRunner && !isHtmlPreview) return;
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
