/**
 * SecureLogAnalyzer — Application JavaScript
 * Handles: sidebar toggle, mobile drawer, password visibility,
 *          flash dismissal, upload dropzone UI, message expand.
 */
(function () {
  "use strict";

  /* ------------------------------------------------------------------
     Sidebar (desktop fixed + mobile drawer)
     ------------------------------------------------------------------ */
  function initSidebar() {
    var toggle = document.getElementById("sidebarToggle");
    var sidebar = document.getElementById("sidebar");
    var overlay = document.getElementById("sidebarOverlay");

    if (!toggle || !sidebar || !overlay) return;

    function setExpanded(expanded) {
      toggle.setAttribute("aria-expanded", String(expanded));
      sidebar.classList.toggle("open", expanded);
      overlay.classList.toggle("show", expanded);
    }

    toggle.addEventListener("click", function () {
      setExpanded(!sidebar.classList.contains("open"));
    });

    overlay.addEventListener("click", function () {
      setExpanded(false);
    });

    // Close drawer on Escape
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && sidebar.classList.contains("open")) {
        setExpanded(false);
      }
    });

    // Close drawer when nav link is clicked (mobile)
    sidebar.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        if (window.innerWidth < 1024) setExpanded(false);
      });
    });

    // Reset on resize
    window.addEventListener("resize", function () {
      if (window.innerWidth >= 1024) setExpanded(false);
    });
  }

  /* ------------------------------------------------------------------
     Password visibility toggle
     ------------------------------------------------------------------ */
  function initPasswordToggles() {
    var toggles = document.querySelectorAll("[data-password-toggle]");

    toggles.forEach(function (toggle) {
      // Replace eye icon with eye-off when visible
      toggle.addEventListener("click", function () {
        var targetId = toggle.getAttribute("data-password-toggle");
        var input = document.getElementById(targetId);
        if (!input) return;

        var isPassword = input.type === "password";
        input.type = isPassword ? "text" : "password";
        toggle.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
      });
    });
  }

  /* ------------------------------------------------------------------
     Flash / alert dismissal
     ------------------------------------------------------------------ */
  function initAlertDismiss() {
    var closers = document.querySelectorAll("[data-dismiss-alert]");

    closers.forEach(function (button) {
      button.addEventListener("click", function () {
        var alertEl = button.closest(".alert");
        if (alertEl) {
          alertEl.style.opacity = "0";
          alertEl.style.transform = "translateY(-6px)";
          setTimeout(function () {
            alertEl.remove();
          }, 180);
        }
      });
    });
  }

  /* ------------------------------------------------------------------
     Upload dropzone + file selection UI
     ------------------------------------------------------------------ */
  function initUpload() {
    var dropzone = document.getElementById("dropzone");
    var fileInput = document.getElementById("logfile");
    var fileSelected = document.getElementById("fileSelected");
    var fileNameEl = document.getElementById("fileName");
    var clearFileBtn = document.getElementById("clearFile");
    var form = document.getElementById("uploadForm");
    var analyzeBtn = document.getElementById("analyzeBtn");
    var progress = document.getElementById("uploadProgress");
    var progressBar = document.getElementById("progressBar");
    var progressLabel = document.getElementById("progressLabel");

    if (!fileInput) return;

    function showFile(name) {
      if (fileSelected) fileSelected.classList.add("show");
      if (fileNameEl) fileNameEl.textContent = name;
    }

    function clearFile() {
      fileInput.value = "";
      if (fileSelected) fileSelected.classList.remove("show");
      if (fileNameEl) fileNameEl.textContent = "";
    }

    function setLoading(isLoading) {
      if (!analyzeBtn) return;
      var label = analyzeBtn.querySelector(".btn-label");
      var spinner = analyzeBtn.querySelector(".spinner");
      analyzeBtn.disabled = isLoading;
      if (label) label.style.display = isLoading ? "none" : "";
      if (spinner) spinner.style.display = isLoading ? "inline-block" : "none";
    }

    function setProgress(percent, text) {
      if (progress) progress.classList.add("show");
      if (progressBar) progressBar.style.width = percent + "%";
      if (progressLabel) progressLabel.textContent = text;
    }

    // Drag & drop
    if (dropzone) {
      ["dragenter", "dragover"].forEach(function (type) {
        dropzone.addEventListener(type, function (e) {
          e.preventDefault();
          dropzone.classList.add("dragover");
        });
      });
      ["dragleave", "drop"].forEach(function (type) {
        dropzone.addEventListener(type, function (e) {
          e.preventDefault();
          dropzone.classList.remove("dragover");
        });
      });
      dropzone.addEventListener("drop", function (e) {
        var files = e.dataTransfer.files;
        if (files.length) {
          fileInput.files = files;
          showFile(files[0].name);
        }
      });
    }

    // File selection
    fileInput.addEventListener("change", function () {
      if (fileInput.files.length) showFile(fileInput.files[0].name);
    });

    if (clearFileBtn) {
      clearFileBtn.addEventListener("click", clearFile);
    }

    // Submit feedback (progress is simulated for the synchronous POST)
    if (form) {
      form.addEventListener("submit", function () {
        if (!fileInput.files.length) return;
        setLoading(true);
        var pct = 0;
        var timer = setInterval(function () {
          pct = Math.min(pct + 15, 90);
          setProgress(pct, "Processing…");
        }, 300);
        // Store timer reference for cleanup (the page will navigate on success)
        window._uploadTimer = timer;
        // If submission fails (validation), stop the spinner
        setTimeout(function () {
          if (window._uploadTimer && !form.checkValidity()) {
            clearInterval(window._uploadTimer);
            setLoading(false);
            setProgress(0, "");
          }
        }, 500);
      });
    }
  }

  /* ------------------------------------------------------------------
     Message expand/collapse in tables
     ------------------------------------------------------------------ */
  function initMessageExpand() {
    var buttons = document.querySelectorAll("[data-expand-message]");
    buttons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var cell = btn.closest(".message-cell");
        var truncated = cell ? cell.querySelector(".message-truncated") : null;
        if (!truncated) return;
        var expanded = truncated.classList.contains("expanded");
        if (expanded) {
          truncated.classList.remove("expanded");
          btn.textContent = "Show more";
        } else {
          truncated.classList.add("expanded");
          truncated.style.display = "";
          truncated.style.WebkitLineClamp = "none";
          btn.textContent = "Show less";
        }
      });
    });
  }

  /* ------------------------------------------------------------------
     Init
     ------------------------------------------------------------------ */
  document.addEventListener("DOMContentLoaded", function () {
    initSidebar();
    initPasswordToggles();
    initAlertDismiss();
    initUpload();
    initMessageExpand();
  });
})();