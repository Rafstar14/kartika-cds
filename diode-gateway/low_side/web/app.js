(() => {
  const $ = (s) => document.querySelector(s);
  const getJSON = async (u) => {
    const r = await fetch(u, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
  };

  // Clock in Topbar & Sidebar
  function updateClock() {
    const now = new Date();
    const timeStr = now.toTimeString().split(" ")[0];
    const topClock = $("#top-clock");
    const sbTime = $("#sb-time");
    if (topClock) topClock.textContent = timeStr;
    if (sbTime) sbTime.textContent = timeStr;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // Toast Notification Helper
  function showToast(msg) {
    const toast = $("#toast-notice");
    const toastText = $("#toast-text");
    if (toast && toastText) {
      toastText.textContent = msg;
      toast.classList.add("show");
      setTimeout(() => toast.classList.remove("show"), 3000);
    }
  }

  // Audio Beep Synthesizer via Web Audio API (Zero External Asset Dependency)
  function playBeep(success = true) {
    try {
      const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      
      if (success) {
        osc.frequency.setValueAtTime(587.33, audioCtx.currentTime); // D5
        osc.frequency.setValueAtTime(880, audioCtx.currentTime + 0.1); // A5
        gain.gain.setValueAtTime(0.12, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
      } else {
        osc.type = "sawtooth";
        osc.frequency.setValueAtTime(220, audioCtx.currentTime); // A3
        osc.frequency.setValueAtTime(164.81, audioCtx.currentTime + 0.12); // E3
        gain.gain.setValueAtTime(0.18, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.35);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.35);
      }
    } catch (e) {}
  }

  // =========================================================================
  // MODAL CONTROLLERS (PENGATURAN & BANTUAN)
  // =========================================================================
  const modalSettings = $("#modal-pengaturan");
  const modalHelp = $("#modal-bantuan");

  const navPengaturan = $("#nav-pengaturan");
  const navBantuan = $("#nav-bantuan");
  const btnCloseSettings = $("#btn-close-settings");
  const btnSaveSettings = $("#btn-save-settings");
  const btnResetSettings = $("#btn-reset-settings");

  const btnCloseHelp = $("#btn-close-help");
  const btnCloseHelpFooter = $("#btn-close-help-footer");
  const soundInput = $("#set-sound-alert");
  let soundEnabled = true;
  try {
    const saved = localStorage.getItem("kartika_cds_sound");
    if (saved !== null) soundEnabled = saved === "true";
  } catch (e) {
    // Browser storage can be unavailable; keep the default for this session.
  }
  if (soundInput) soundInput.checked = soundEnabled;

  // Open Settings Modal
  if (navPengaturan && modalSettings) {
    navPengaturan.addEventListener("click", (e) => {
      e.preventDefault();
      if (soundInput) soundInput.checked = soundEnabled;
      modalSettings.classList.add("active");
    });
  }

  // Close Settings Modal
  function closeSettings() {
    if (modalSettings) modalSettings.classList.remove("active");
    if (soundInput) soundInput.checked = soundEnabled;
  }
  if (btnCloseSettings) btnCloseSettings.addEventListener("click", closeSettings);

  // Save Settings
  if (btnSaveSettings) {
    btnSaveSettings.addEventListener("click", () => {
      soundEnabled = soundInput ? soundInput.checked : true;
      let stored = true;
      try {
        localStorage.setItem("kartika_cds_sound", String(soundEnabled));
      } catch (e) {
        stored = false;
      }
      showToast(stored ? "Preferensi suara disimpan di browser." : "Suara berlaku untuk sesi ini; browser tidak dapat menyimpannya.");
      closeSettings();
    });
  }

  // Reset the sound preference in the open dialog.
  if (btnResetSettings) {
    btnResetSettings.addEventListener("click", () => {
      if (soundInput) soundInput.checked = true;
      showToast("Suara bawaan dipilih. Simpan untuk menerapkan.");
    });
  }

  // Open Help Modal
  if (navBantuan && modalHelp) {
    navBantuan.addEventListener("click", (e) => {
      e.preventDefault();
      modalHelp.classList.add("active");
    });
  }

  // Close Help Modal
  function closeHelp() {
    if (modalHelp) modalHelp.classList.remove("active");
  }
  if (btnCloseHelp) btnCloseHelp.addEventListener("click", closeHelp);
  if (btnCloseHelpFooter) btnCloseHelpFooter.addEventListener("click", closeHelp);

  // Close modals when clicking backdrop
  [modalSettings, modalHelp].forEach((m) => {
    if (m) {
      m.addEventListener("click", (e) => {
        if (e.target === m) m.classList.remove("active");
      });
    }
  });

  // ESC key to close modal
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeSettings();
      closeHelp();
    }
  });

  // Standard Navigation tabs
  document.querySelectorAll(".nav-menu .nav-item a").forEach((a) => {
    a.addEventListener("click", (e) => {
      if (a.id === "nav-pengaturan" || a.id === "nav-bantuan") {
        return; // Handled by modals above
      }
      document.querySelectorAll(".nav-menu .nav-item").forEach((el) => el.classList.remove("active"));
      a.closest(".nav-item").classList.add("active");
    });
  });

  // Stage mapping helper
  const stageKeyMap = {
    intake: "stage-name-size",
    hash: "stage-sha256",
    magic: "stage-magic",
    structure: "stage-structure",
    yara: "stage-yara",
    clamav: "stage-clamav",
  };

  function updateStepper(stepIndex) {
    const steps = ["step-upload", "step-scan", "step-transfer"];
    steps.forEach((s, idx) => {
      const el = $(`#${s}`);
      if (!el) return;
      el.classList.remove("active", "done");
      if (idx < stepIndex) {
        el.classList.add("done");
      } else if (idx === stepIndex) {
        el.classList.add("active");
      }
    });
  }

  function displayInspectionResult(job, announce = false) {
    const fnBadge = $("#inspection-filename");
    if (fnBadge) fnBadge.textContent = job.name || "Berkas Diperiksa";

    const vBanner = $("#verdict-banner");
    const vTitle = $("#verdict-title");
    const vSub = $("#verdict-sub");

    // Reset items
    ["stage-name-size", "stage-sha256", "stage-magic", "stage-structure", "stage-yara", "stage-clamav"].forEach((id) => {
      const item = $(`#${id}`);
      if (item) {
        item.className = "stage-item";
        item.querySelector(".stage-status-text").textContent = "Siap";
      }
    });

    if (job.stages) {
      job.stages.forEach((s) => {
        const id = stageKeyMap[s.id];
        if (id) {
          const item = $(`#${id}`);
          if (item) {
            if (["pass", "fail", "skip"].includes(s.status)) item.classList.add(s.status);
            item.querySelector(".stage-status-text").textContent = ({ pass: "Lolos", fail: "Gagal", skip: "Dilewati", pending: "Belum diperiksa" })[s.status] || "Tidak diketahui";
          }
        }
      });
    }

    if (job.verdict === "ACCEPTED") {
      vBanner.className = "verdict-banner";
      vBanner.querySelector(".verdict-icon").innerHTML = "&#10003;";
      vTitle.textContent = "Berkas lolos gate";
      const transfer = job.transfer || {};
      const messages = {
        queued: "Menunggu antrean pengiriman.",
        sending: "Sedang mengirim paket UDP.",
        sent: "Paket dikirim tanpa ACK. Periksa brankas sisi dalam untuk memastikan penerimaan.",
        failed: "Pengiriman gagal. Periksa log audit untuk rincian.",
        none: "Status pengiriman belum tersedia.",
      };
      const state = transfer.state || "none";
      vSub.textContent = (job.degraded ? "Sebagian engine tidak wajib dilewati. " : "") + (messages[state] || messages.none);
      updateStepper(state === "sent" ? 3 : 2);
      if (announce && soundEnabled) playBeep(true);
    } else {
      vBanner.className = "verdict-banner fail";
      vBanner.querySelector(".verdict-icon").innerHTML = "&times;";
      vTitle.textContent = "File Ditolak & Dikarantina";
      vSub.textContent = job.reason ? `Alasan: ${job.reason}` : "Pelanggaran keamanan terdeteksi. Berkas tidak dikirim.";
      updateStepper(1);
      if (announce && soundEnabled) playBeep(false);
    }
  }

  // Upload handler
  async function upload(file) {
    const errBox = $("#err");
    if (errBox) errBox.textContent = "";

    updateStepper(0);

    const fd = new FormData();
    fd.append("file", file);
    try {
      const r = await fetch("/api/upload", {
        method: "POST",
        headers: { "X-Diode-Request": "1" },
        body: fd
      });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        throw new Error(body.error || "Server menolak berkas (kode " + r.status + ").");
      }
      if (body.job) {
        displayInspectionResult(body.job, true);
      }
    } catch (e) {
      if (errBox) errBox.textContent = "Unggahan gagal: " + e.message;
      updateStepper(0);
    }
    refreshData();
  }

  const fileInput = $("#file");
  if (fileInput) {
    fileInput.addEventListener("change", async (ev) => {
      for (const f of ev.target.files) await upload(f);
      ev.target.value = "";
    });
  }

  const drop = $("#drop");
  if (drop) {
    ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("over"); }));
    ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("over"); }));
    drop.addEventListener("drop", async (e) => {
      e.preventDefault();
      drop.classList.remove("over");
      for (const f of e.dataTransfer.files) await upload(f);
    });
  }

  function setText(selector, value) {
    const el = $(selector);
    if (el) el.textContent = value;
  }

  function renderStatus(status) {
    const engineText = (engine) => {
      if (!status) return "Status tidak tersedia";
      const required = (status.required || []).includes(engine);
      return `${status[engine] ? "Aktif" : "Tidak aktif"} (${required ? "wajib" : "tidak wajib"})`;
    };
    setText("#settings-yara", engineText("yara"));
    setText("#settings-clamav", engineText("clamav"));
    setText("#metric-yara", status ? (status.yara ? "Aktif" : "Tidak aktif") : "Tidak tersedia");
    setText("#metric-clamav", status ? (status.clamav ? "Aktif" : "Tidak aktif") : "Tidak tersedia");
    const gateText = !status ? "Tidak tersedia" : !status.ready ? "Belum siap" : status.degraded ? "Terbatas" : "Siap";
    setText("#metric-gate", gateText);
    setText("#sb-status", gateText);
    setText("#top-status-text", !status ? "Status tidak tersedia" : `Gate ${gateText.toLowerCase()}`);
    const badge = $("#top-status-badge");
    if (badge) badge.className = status && status.ready && !status.degraded ? "pill-badge normal" : "pill-badge";
  }

  function renderAudit(audit) {
    const chainBadge = $("#chain-badge");
    const tbody = $("#log-table-body");
    if (!audit) {
      setText("#metric-processed", "Tidak tersedia");
      if (chainBadge) {
        chainBadge.className = "pill-badge";
        chainBadge.style.color = "";
        chainBadge.textContent = "Status audit tidak tersedia";
      }
      if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Log audit tidak dapat dimuat. Periksa koneksi ke server.</td></tr>`;
      return;
    }

    const records = audit.records || [];
    setText("#metric-processed", String(records.filter(r => (r.event || "").startsWith("GATE_")).length));
    if (chainBadge) {
      const ok = audit.chain && audit.chain.ok;
      chainBadge.className = ok ? "pill-badge normal" : "pill-badge fail";
      chainBadge.style.color = ok ? "" : "var(--accent-red)";
      chainBadge.textContent = ok ? `Rantai hash terverifikasi (${audit.chain.records || 0})` : "Integritas log terputus";
    }
    if (!tbody) return;
    if (!records.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Belum ada catatan audit.</td></tr>`;
      return;
    }
    tbody.replaceChildren();
    records.slice(0, 15).forEach((record) => {
      let label = record.event || "Peristiwa";
      let detail = record.reason || record.code || "-";
      if (record.event === "GATE_ACCEPTED") {
        label = "LOLOS GATE";
        detail = record.degraded ? "Ada engine tidak wajib yang dilewati" : "Pemeriksaan gate selesai";
      } else if (record.event === "SENT_NO_ACK") {
        label = "DIKIRIM";
        detail = `${record.packets} paket dikirim tanpa ACK`;
      } else if (record.event === "GATE_REJECTED") {
        label = "DITOLAK";
      } else if (record.event === "SEND_FAILED") {
        label = "GAGAL KIRIM";
      }
      const row = document.createElement("tr");
      [(record.ts || "").slice(11, 19) || "--:--:--", record.name || (record.file_id ? `File [${record.file_id.slice(0, 8)}]` : "-"), label, detail].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = String(value);
        row.appendChild(cell);
      });
      tbody.appendChild(row);
    });
  }

  async function refreshData() {
    const [jobsResult, auditResult, statusResult] = await Promise.allSettled([
      getJSON("/api/jobs"), getJSON("/api/audit"), getJSON("/api/status")
    ]);
    renderStatus(statusResult.status === "fulfilled" ? statusResult.value : null);
    renderAudit(auditResult.status === "fulfilled" ? auditResult.value : null);
    if (jobsResult.status === "fulfilled") {
      if (jobsResult.value.length) displayInspectionResult(jobsResult.value[0]);
    } else {
      setText("#inspection-filename", "Status pemeriksaan tidak tersedia");
      setText("#verdict-title", "Status pemeriksaan tidak tersedia");
      setText("#verdict-sub", "Periksa koneksi ke server sisi luar.");
    }
  }

  refreshData();
  setInterval(refreshData, 2000);
})();
