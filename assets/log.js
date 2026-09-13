/*
 * Log highlighting for highlight.js: journalctl, syslog, and the bracketed
 * level lines most daemons emit. highlight.js has no syslog grammar of its
 * own, and its common bundle carries nothing close.
 *
 * Autodetect is off. Log lines are mostly prose, so this grammar matches a
 * little of almost any text and would win detection on ordinary pastes.
 * Reachable through the picker or ?lang=log only.
 *
 * case_insensitive is set on the language, not on the individual patterns:
 * highlight.js rebuilds every `begin` regex from its source and applies the
 * language flag, so an `i` on a pattern here is silently dropped. Months are
 * spelled out for the same reason, since [A-Z][a-z]{2} stops meaning
 * anything once the whole grammar is case-blind.
 */
hljs.registerLanguage("log", function () {
  var MONTH = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec";
  var BAD = "emerg|alert|crit|critical|fatal|error|err|fail|failed|warning|warn";
  var OK = "notice|info|debug|trace";
  return {
    name: "Log",
    aliases: ["journal", "journalctl", "syslog"],
    disableAutodetect: true,
    case_insensitive: true,
    contains: [
      // 2026-09-13T13:03:21.196780Z, 2026/09/13 15:08:39.477, with or without a zone
      {
        className: "meta",
        begin: /\b\d{4}[-/]\d{2}[-/]\d{2}[t ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:z|[+-]\d{2}:?\d{2})?/,
      },
      // syslog and journalctl's default: Sep 13 15:08:39
      { begin: new RegExp("\\b(?:" + MONTH + ") {1,2}\\d{1,2} \\d{2}:\\d{2}:\\d{2}\\b"), className: "meta" },
      // Levels before names, or "error:" would be tagged as a unit.
      { className: "keyword", begin: new RegExp("\\[?\\b(?:" + BAD + ")\\b\\]?") },
      { className: "literal", begin: new RegExp("\\[?\\b(?:" + OK + ")\\b\\]?") },
      // unit[pid]: and the bare unit: that tracing-style lines use
      { className: "title", begin: /\b[\w.@/-]+(?=\[\d+\]:)/ },
      { className: "number", begin: /\[\d+\]/ },
      { className: "title", begin: /\b[\w.@/-]+(?=:\s)/ },
      // addresses: v4 with an optional port, and bracketed v6
      { className: "number", begin: /\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b/ },
      { className: "number", begin: /\[[0-9a-f:]+\](?::\d+)?/ },
      // urls and absolute paths
      { className: "symbol", begin: /\b[a-z][a-z0-9+.-]*:\/\/[^\s'"]+/ },
      { className: "symbol", begin: /(?:^|\s)\/[\w./@-]+/ },
      { className: "string", begin: /'/, end: /'/, illegal: /\n/ },
      { className: "string", begin: /"/, end: /"/, illegal: /\n/ },
      // key=value, how structured logs and systemd both read
      { className: "attr", begin: /\b[\w.-]+(?==)/ },
      { className: "number", begin: /\b\d+(?:\.\d+)?\b/ },
    ],
  };
});
