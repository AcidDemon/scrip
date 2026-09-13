(function () {
  // System preference until the user picks; then localStorage wins.
  var root = document.documentElement;
  function storageGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function storageSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }

  var stored = storageGet("scrip-mode");
  var system = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches
    ? "light" : "dark";
  root.setAttribute("data-theme", stored === "light" || stored === "dark" ? stored : system);

  var toggle = document.getElementById("themetoggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      storageSet("scrip-mode", next);
    });
  }

  // Assemble the address on click to deter basic HTML scrapers. Browsers
  // that run JavaScript can still recover it.
  Array.prototype.forEach.call(document.querySelectorAll(".mail"), function (el) {
    if (!el.getAttribute("data-u") || !el.getAttribute("data-d")) {
      // Hide the control when contact_email is unset.
      if (el.parentNode) el.parentNode.removeChild(el);
      return;
    }
    el.addEventListener("click", function () {
      var addr = el.getAttribute("data-u") + String.fromCharCode(64) + el.getAttribute("data-d");
      var a = document.createElement("a");
      a.href = "mailto:" + addr;
      a.textContent = addr;
      a.className = "mail";
      el.replaceWith(a);
      a.focus();
      window.location.href = a.href;
    });
  });

  // Copy from data-cmd, not innerText: innerText includes any visible comment.
  Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target) return;
    btn.addEventListener("click", function () {
      done(write(target.getAttribute("data-cmd") || target.innerText));
    });
    function write(text) {
      // clipboard API is undefined outside a secure context (plain-HTTP LAN).
      if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise(function (resolve, reject) {
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.className = "offscreen";
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
        ta.remove();
        ok ? resolve() : reject();
      });
    }
    function done(p) {
      p.then(function () { flash("copied", "ok"); })
       .catch(function () { flash("select and copy", "fail"); });
    }
    function flash(label, cls) {
      var original = btn.getAttribute("data-label") || btn.textContent;
      btn.setAttribute("data-label", original);
      btn.textContent = label;
      btn.classList.add(cls);
      setTimeout(function () {
        btn.textContent = original;
        btn.classList.remove(cls);
      }, 1600);
    }
  });
  // Select the last section whose top has passed the trigger line.
  var links = document.querySelectorAll("nav a[href^='#']");
  if (links.length) {
    var targets = [];
    Array.prototype.forEach.call(links, function (a) {
      var el = document.getElementById(a.getAttribute("href").slice(1));
      if (el) targets.push({ link: a, el: el });
    });
    var ticking = false;
    var spy = function () {
      ticking = false;
      // Just under the viewport top, so a clicked link selects its own section.
      var line = window.scrollY + 100;
      var current = targets[0];
      // Document-absolute: offsetTop measures from the grid column, not the page.
      targets.forEach(function (t) {
        if (t.el.getBoundingClientRect().top + window.scrollY <= line) current = t;
      });
      targets.forEach(function (t) { t.link.classList.toggle("on", t === current); });
    };
    var onScroll = function () {
      if (ticking) return;
      ticking = true;
      window.requestAnimationFrame(spy);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    spy();
  }
})();
