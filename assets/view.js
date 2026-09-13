(function () {
  var THEMES = {
    "github-light": { file: "theme-github-light.css", dark: false, bg: "#fff", fg: "#24292e" },
    "github-dark": { file: "theme-github-dark.css", dark: true, bg: "#0d1117", fg: "#c9d1d9" },
    "solarized-light": { file: "theme-solarized-light.css", dark: false, bg: "#fdf6e3", fg: "#586e75" },
    "solarized-dark": { file: "theme-solarized-dark.css", dark: true, bg: "#002b36", fg: "#93a1a1" },
    nord: { file: "theme-nord.css", dark: true, bg: "#2e3440", fg: "#d8dee9" },
    "catppuccin-latte": { file: "theme-catppuccin-latte.css", dark: false, bg: "#eff1f5", fg: "#4c4f69" },
    "catppuccin-mocha": { file: "theme-catppuccin-mocha.css", dark: true, bg: "#1e1e2e", fg: "#cdd6f4" }
  };
  // Matches the <link> in view.html, so no second stylesheet loads on a
  // first visit unless the reader's system asks for the light one.
  var SHIPPED_THEME = "github-dark";
  // Keep "plain" first, then sort the bundled languages. An unavailable
  // language would silently fall back to auto-detection.
  var LANGS_REST = ["bash", "c", "cpp", "csharp", "css", "diff", "go", "graphql",
    "java", "javascript", "json", "kotlin", "less", "log", "lua", "makefile",
    "markdown", "nix", "objectivec", "perl", "php", "python", "r", "ruby", "rust",
    "scss", "shell", "sql", "swift", "toml", "typescript", "vbnet", "wasm", "xml",
    "yaml"].sort();
  var LANGS = ["plain"].concat(LANGS_REST);

  function storageGet(k) {
    try { return localStorage.getItem(k); } catch (e) { return null; }
  }
  function storageSet(k, v) {
    try { localStorage.setItem(k, v); } catch (e) {}
  }

  var defaultLink = document.getElementById("defaultTheme");
  var userLink = null;
  var c = document.getElementById("c");
  var bar = document.getElementById("bar");

  // Backgrounds and the status-line tint come from the THEMES table, not
  // computed style: stylesheet application timing is not observable reliably.
  function applyTheme(name) {
    var t = THEMES[name];
    if (!t) return;
    if (name !== SHIPPED_THEME) {
      defaultLink.disabled = true;
      if (!userLink) {
        userLink = document.createElement("link");
        userLink.rel = "stylesheet";
        userLink.id = "userTheme";
        document.head.appendChild(userLink);
      }
      userLink.disabled = false;
      userLink.href = "/assets/" + t.file;
    } else {
      defaultLink.disabled = false;
      if (userLink) userLink.disabled = true;
    }
    document.body.style.background = t.bg;
    bar.style.background = t.bg;
    bar.style.color = t.fg;
    bar.style.borderTopColor = t.dark ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.15)";
  }

  var select = document.getElementById("themepick");
  var stored = storageGet("scrip-theme");
  // Use the system theme until the reader saves a preference.
  var systemTheme = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
    ? "github-light" : SHIPPED_THEME;
  var current = stored && THEMES[stored] ? stored : systemTheme;

  var groups = { Dark: [], Light: [] };
  Object.keys(THEMES).forEach(function (name) {
    (THEMES[name].dark ? groups.Dark : groups.Light).push(name);
  });
  Object.keys(groups).forEach(function (label) {
    var og = document.createElement("optgroup");
    og.label = label;
    groups[label].sort().forEach(function (name) {
      var opt = document.createElement("option");
      opt.value = name;
      opt.textContent = "• " + name; // bullet: reads as a list when open
      if (name === current) opt.selected = true;
      og.appendChild(opt);
    });
    select.appendChild(og);
  });

  applyTheme(current);

  select.addEventListener("change", function () {
    storageSet("scrip-theme", select.value);
    applyTheme(select.value);
  });

  var slug = location.pathname.slice(1).split("/")[0];
  var params = new URLSearchParams(location.search);
  var lang = params.get("lang");
  var facts = document.getElementById("facts");
  var copyBtn = document.getElementById("copy");
  var langPick = document.getElementById("langpick");
  var raw = "";
  var highlighted = false;

  document.getElementById("rawlink").href = "/raw/" + slug;

  var linesBtn = document.getElementById("linestoggle");
  var linesOn = storageGet("scrip-lines") !== "off";
  var wrapBtn = document.getElementById("wraptoggle");
  var wrapOn = storageGet("scrip-wrap") !== "off";

  function applyLines() {
    c.classList.toggle("lines", linesOn);
    linesBtn.classList.toggle("off", !linesOn);
  }
  function applyWrap() {
    c.classList.toggle("nowrap", !wrapOn);
    wrapBtn.classList.toggle("off", !wrapOn);
  }

  linesBtn.addEventListener("click", function () {
    linesOn = !linesOn;
    storageSet("scrip-lines", linesOn ? "on" : "off");
    applyLines();
  });
  wrapBtn.addEventListener("click", function () {
    wrapOn = !wrapOn;
    storageSet("scrip-wrap", wrapOn ? "on" : "off");
    applyWrap();
  });
  applyWrap();

  function writeClipboard(text) {
    // navigator.clipboard is undefined outside a secure context, which a
    // plain-HTTP deployment on a LAN is.
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(ta);
      if (ok) { resolve(); } else { reject(); }
    });
  }

  function flash(cls, label) {
    var span = copyBtn.querySelector(".lbl");
    var previous = span.textContent;
    span.textContent = label;
    copyBtn.classList.add(cls);
    setTimeout(function () {
      span.textContent = previous;
      copyBtn.classList.remove(cls);
    }, 1600);
  }

  function doCopy() {
    writeClipboard(raw)
      .then(function () { flash("done", "copied"); })
      .catch(function () { flash("failed", "select and copy"); });
  }
  copyBtn.addEventListener("click", doCopy);

  function doDownload() {
    // Download the fetched body; a second /raw request would fail for a burn paste.
    var ext = lang && /^[a-z0-9]{1,12}$/.test(lang) ? lang : "txt";
    var url = URL.createObjectURL(new Blob([raw], { type: "text/plain" }));
    var a = document.createElement("a");
    a.href = url;
    a.download = slug + "." + ext;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  document.getElementById("download").addEventListener("click", doDownload);

  // #L7 or #L7-L9. Shift-click extends from the current first line.
  var hits = [];
  function parseHash() {
    var m = /^#L(\d+)(?:-L?(\d+))?$/.exec(location.hash);
    if (!m) return null;
    var a = parseInt(m[1], 10);
    var b = m[2] ? parseInt(m[2], 10) : a;
    return a <= b ? [a, b] : [b, a];
  }
  function paint(range) {
    hits.forEach(function (el) { el.classList.remove("hit"); });
    hits = [];
    if (!range) return;
    var lines = c.querySelectorAll(".line");
    for (var n = range[0]; n <= range[1]; n++) {
      var el = lines[n - 1];
      if (el) { el.classList.add("hit"); hits.push(el); }
    }
  }
  function selectLines(range, scroll) {
    paint(range);
    if (!range) { return; }
    var hash = range[0] === range[1] ? "#L" + range[0] : "#L" + range[0] + "-L" + range[1];
    history.replaceState(null, "", location.pathname + location.search + hash);
    if (scroll && hits.length) {
      hits[0].scrollIntoView({ block: "center" });
    }
  }
  function wireAnchors() {
    c.addEventListener("click", function (e) {
      var line = e.target.closest ? e.target.closest(".line") : null;
      if (!line) return;
      // Only the number gutter, or every click inside the paste would move
      // the anchor and fight text selection.
      if (e.clientX - line.getBoundingClientRect().left > 54) return;
      var all = Array.prototype.indexOf.call(c.querySelectorAll(".line"), line) + 1;
      var existing = parseHash();
      selectLines(e.shiftKey && existing ? [existing[0], all] : [all, all], false);
      e.preventDefault();
    });
    window.addEventListener("hashchange", function () { paint(parseHash()); });
  }

  // Save explicit choices, including "plain", in the URL. Omitting lang
  // enables auto-detection; lang=plain skips highlighting.
  function setLang(name) {
    lang = name;
    params.set("lang", name);
    var q = params.toString();
    history.replaceState(null, "", location.pathname + (q ? "?" + q : "") + location.hash);
    render();
  }
  // Measure the separator glyph separately: its fallback font can be wider
  // than the option text. Size the rule to the longest entry.
  function separatorFor(select, names) {
    var widest = names.reduce(function (a, b) { return b.length > a.length ? b : a; }, "");
    var n = 8;
    try {
      var ctx = document.createElement("canvas").getContext("2d");
      ctx.font = window.getComputedStyle(select).font;
      var dash = ctx.measureText("\u2500").width;
      var target = ctx.measureText("\u2022 " + widest).width;
      if (dash > 0 && target > 0) { n = Math.max(3, Math.round(target / dash)); }
    } catch (e) { /* keep the default */ }
    return new Array(n + 1).join("\u2500");
  }

  function langOption(name, parent) {
    var opt = document.createElement("option");
    opt.value = name;
    opt.textContent = "\u2022 " + name; // same bullet the theme picker uses
    parent.appendChild(opt);
  }
  // Use an optgroup label to separate "plain" from the sorted languages.
  langOption("plain", langPick);
  var rest = document.createElement("optgroup");
  rest.label = separatorFor(langPick, LANGS);
  LANGS_REST.forEach(function (name) { langOption(name, rest); });
  langPick.appendChild(rest);
  langPick.addEventListener("change", function () { setLang(langPick.value); });

  // Rewrap the highlighted markup one logical line per element so CSS
  // counters can number them. Highlight spans may cross newlines (block
  // comments); reopen the span stack on each line to keep markup valid.
  function wrapLines() {
    var openTags = [];
    var lines = c.innerHTML.split("\n");
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop();
    var out = lines.map(function (line) {
      var prefix = openTags.join("");
      var tokens = line.match(/<span[^>]*>|<\/span>/g) || [];
      tokens.forEach(function (t) {
        if (t === "</span>") openTags.pop();
        else openTags.push(t);
      });
      var suffix = "";
      for (var i = 0; i < openTags.length; i++) suffix += "</span>";
      // an empty block serializes to nothing on copy; a real newline inside
      // keeps blank lines present in selections
      var body = line === "" ? "\n" : prefix + line + suffix;
      return '<span class="line">' + body + "</span>";
    });
    // blocks break lines visually and copy as newlines; a joining "\n"
    // would double every break under pre-wrap
    c.innerHTML = out.join("");
  }

  // Highlighting adds a node per token and wrapping adds one per line.
  // Limit both text size and line count to avoid freezing the tab on minified
  // files or newline-heavy pastes. Raise these limits or use a worker if needed.
  var MAX_HL_CHARS = 128 * 1024;
  var MAX_HL_LINES = 20000;

  function tooBigToHighlight(t) {
    return t.length > MAX_HL_CHARS || t.split("\n").length > MAX_HL_LINES;
  }

  function humanBytes(n) {
    if (n >= 1048576) return (n / 1048576).toFixed(1) + " MiB";
    if (n >= 1024) return Math.round(n / 1024) + " KiB";
    return n + " B";
  }

  function render() {
    c.className = "";
    c.textContent = raw;
    // Clear highlight.js's marker so it can highlight again after a language change.
    delete c.dataset.highlighted;
    highlighted = false;
    // Trailing newline trimmed first, or the count is one ahead of the rows
    // wrapLines renders.
    var lineCount = raw.replace(/\n$/, "").split("\n").length;
    var parts = [humanBytes(new Blob([raw]).size), lineCount + " lines"];
    if (tooBigToHighlight(raw)) {
      c.className = "hljs";
      parts.push("highlighting off, large paste");
      linesBtn.hidden = true;
      langPick.hidden = true;
      facts.textContent = parts.join(" · ");
      return;
    }
    if (lang === "plain") {
      c.className = "hljs"; // theme colours, no tokenizer pass
      langPick.value = "plain";
    } else {
      if (lang && hljs.getLanguage(lang)) { c.className = "language-" + lang; }
      hljs.highlightElement(c);
      var m = /language-(\S+)/.exec(c.className);
      var detected = m ? m[1] : "plain";
      langPick.value = LANGS.indexOf(detected) >= 0 ? detected : "plain";
    }
    wrapLines();
    applyLines();
    applyWrap();
    highlighted = true;
    facts.textContent = parts.join(" · ");
    paint(parseHash());
  }

  document.addEventListener("keydown", function (e) {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var t = e.target.tagName;
    if (t === "INPUT" || t === "SELECT" || t === "TEXTAREA") return;
    if (e.key === "y") { doCopy(); }
    else if (e.key === "r") { window.open("/raw/" + slug, "_blank", "noopener"); }
    else if (e.key === "d") { doDownload(); }
    else if (e.key === "w") { wrapBtn.click(); }
    else if (e.key === "l") { linesBtn.click(); }
    else { return; }
    e.preventDefault();
  });

  fetch("/raw/" + slug)
    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.text(); })
    .then(function (t) {
      raw = t;
      render();
      wireAnchors();
      if (highlighted) { selectLines(parseHash(), true); }
    })
    .catch(function () { c.textContent = "paste not found"; });
})();
