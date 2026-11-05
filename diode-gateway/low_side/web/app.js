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

  // Navigation click handles
  document.querySelectorAll(".nav-item a").forEach((a) => {
    a.addEventListener("click", (e) => {
      document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active"));
      a.closest(".nav-item").classList.add("active");
    });
  });

  // Stage mapping helper
  const stageKeyMap = {
    "Nama dan ukuran": "stage-name-size",
    "SHA-256": "stage-sha256",
    "Tipe file (magic)": "stage-magic",
    "Pemeriksaan struktur": "stage-structure",
    "Aturan YARA": "stage-yara",
    "ClamAV": "stage-clamav",
  };

  function updateStepper(stepIndex) {
    const steps = ["step-upload", "step-scan", "step-analisis", "step-validasi", "step-enkripsi", "step-transfer"];
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

  function displayInspectionResult(job) {
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
        const id = stageKeyMap[s.label] || Object.keys(stageKeyMap).find(k => s.label.includes(k)) && stageKeyMap[Object.keys(stageKeyMap).find(k => s.label.includes(k))];
        if (id) {
          const item = $(`#${id}`);
          if (item) {
            item.classList.add(s.status === "pass" ? "pass" : s.status === "fail" ? "fail" : "skip");
            item.querySelector(".stage-status-text").textContent = s.status === "pass" ? "Lolos" : s.status === "fail" ? "Gagal" : "Dilewati";
          }
        }
      });
    }

    if (job.verdict === "ACCEPTED") {
      vBanner.className = "verdict-banner";
      vBanner.querySelector(".verdict-icon").innerHTML = "&#10003;";
      vTitle.textContent = "File Aman & Lolos Verifikasi";
      vSub.textContent = "Diteruskan ke Enklave Radar via UDP Simplex (Reed-Solomon RS(4,2) Protected).";
      updateStepper(5); // Completed transfer
    } else {
      vBanner.className = "verdict-banner fail";
      vBanner.querySelector(".verdict-icon").innerHTML = "&times;";
      vTitle.textContent = "File Ditolak & Dikarantina";
      vSub.textContent = job.reason ? `Alasan: ${job.reason}` : "Pelanggaran keamanan terdeteksi. Berkas tidak dikirim.";
      updateStepper(2); // Stop at inspection
    }
  }

  // Upload handler
  async function upload(file) {
    const errBox = $("#err");
    if (errBox) errBox.textContent = "";

    // Show step upload
    updateStepper(0);
    setTimeout(() => updateStepper(1), 300);

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
        displayInspectionResult(body.job);
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

  // Render Log Table & Metrics
  async function refreshData() {
    try {
      const [jobs, audit, status] = await Promise.all([
        getJSON("/api/jobs").catch(() => []),
        getJSON("/api/audit").catch(() => ({ records: [], chain: { ok: true } })),
        getJSON("/api/status").catch(() => ({ ready: true }))
      ]);

      // Metrics calculation
      const totalProcessed = audit.records.filter(r => r.event.startsWith("GATE_")).length || jobs.length;
      const countEl = $("#metric-processed");
      if (countEl) countEl.textContent = String(totalProcessed);

      // Latest job display in inspector if not set yet
      if (jobs.length > 0 && !window.__lastJobIdSet) {
        displayInspectionResult(jobs[0]);
        window.__lastJobIdSet = true;
      }

      // Chain integrity badge
      const chainBadge = $("#chain-badge");
      if (chainBadge) {
        if (audit.chain && audit.chain.ok) {
          chainBadge.className = "pill-badge normal";
          chainBadge.textContent = "Rantai Hash Terverifikasi (" + (audit.chain.records || 0) + ")";
        } else {
          chainBadge.className = "pill-badge fail";
          chainBadge.style.color = "var(--accent-red)";
          chainBadge.textContent = "Integritas Log Terputus!";
        }
      }

      // Populate Log Table
      const tbody = $("#log-table-body");
      if (tbody) {
        if (!audit.records.length && !jobs.length) {
          tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Belum ada file diperiksa. Serahkan file untuk memulai pengujian.</td></tr>`;
          return;
        }

        // Merge or prioritize audit logs
        const tableRows = [];
        const seenEvents = audit.records.slice().reverse().slice(0, 15);

        if (seenEvents.length > 0) {
          seenEvents.forEach((r) => {
            const time = (r.ts || "").slice(11, 19) || "--:--:--";
            const name = r.name || (r.file_id ? `File [${r.file_id.slice(0, 8)}]` : "Unknown");
            let isPass = false;
            let statusText = "MEMPROSES";
            let reasonText = "-";

            if (r.event === "GATE_ACCEPTED" || r.event === "SENT_NO_ACK") {
              isPass = true;
              statusText = "LOLOS";
              reasonText = r.event === "SENT_NO_ACK" ? `Terkirim (${r.packets} paket UDP)` : "Semua 6 tahap lolos";
            } else if (r.event === "GATE_REJECTED" || r.event === "SEND_FAILED") {
              isPass = false;
              statusText = "DITOLAK";
              reasonText = r.reason || r.code || "Pelanggaran aturan keamanan";
            } else {
              statusText = r.event;
            }

            tableRows.push(`
              <tr>
                <td class="cell-time">${time}</td>
                <td class="cell-filename">
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                  </svg>
                  ${name}
                </td>
                <td>
                  <span class="badge-status ${isPass ? 'pass' : 'fail'}">${statusText}</span>
                </td>
                <td class="cell-reason">${reasonText}</td>
              </tr>
            `);
          });
          tbody.innerHTML = tableRows.join("");
        }
      }

    } catch (e) {
      console.warn("Telemetry refresh error:", e);
    }
  }

  refreshData();
  setInterval(refreshData, 2000);
})();
