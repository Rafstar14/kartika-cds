(() => {
  const $ = (s) => document.querySelector(s);
  const getJSON = async (u) => {
    const r = await fetch(u, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
  };

  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");

  // Clock
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
    a.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach((el) => el.classList.remove("active"));
      a.closest(".nav-item").classList.add("active");
    });
  });

  async function refreshLive() {
    try {
      const d = await getJSON("/api/live");
      const age = Date.now() / 1000 - (d.updated || 0);

      const statusBadge = $("#top-status-badge");
      const statusText = $("#top-status-text");
      if (statusBadge && statusText) {
        if (age < 8) {
          statusBadge.className = "pill-badge normal";
          statusText.textContent = "Receiver Aktif (RX-Only)";
        } else {
          statusBadge.className = "pill-badge";
          statusBadge.style.borderColor = "var(--accent-amber)";
          statusBadge.style.color = "var(--accent-amber)";
          statusText.textContent = "Receiver Menunggu Sinyal";
        }
      }

      // OT Telemetry
      if (d.ot_radar) {
        if (d.ot_radar.firmware_version) $("#ot_fw").textContent = d.ot_radar.firmware_version;
        if (d.ot_radar.sweep_freq_mhz) $("#ot_freq").textContent = `${d.ot_radar.sweep_freq_mhz} MHz`;
        if (d.ot_radar.interlock_status) $("#ot_lock").textContent = d.ot_radar.interlock_status;
        if (d.ot_radar.unit) $("#ot_unit").textContent = d.ot_radar.unit;
      }

      // Stats counters
      const rxPacketsBadge = $("#rx-packets-badge");
      if (rxPacketsBadge) rxPacketsBadge.textContent = `Total Paket: ${d.stats?.packets || 0}`;

      const fecEl = $("#stat-fec-recovered");
      if (fecEl) {
        const totalRecovered = (d.active || []).reduce((acc, cur) => acc + (cur.recovered || 0), 0);
        fecEl.textContent = String(totalRecovered);
      }

      // Active transfers
      const activeBox = $("#active-transfers-box");
      if (activeBox) {
        if (!d.active || !d.active.length) {
          activeBox.innerHTML = `<p class="empty-state">Tidak ada transfer masuk saat ini. Menunggu emisi UDP satu arah dari Guard Daemon...</p>`;
        } else {
          activeBox.innerHTML = d.active.map((t) => {
            const pct = Math.round((100 * (t.received || 0)) / (t.total || 1));
            return `
              <div style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-weight:600;">
                  <span>${t.name} (${fmtSize(t.size)})</span>
                  <span style="color:var(--accent-emerald);">${pct}% (${t.received}/${t.total} paket)</span>
                </div>
                <div class="transfer-progress-bar">
                  <div class="transfer-progress-fill" style="width:${pct}%;"></div>
                </div>
                <div style="font-size:12px; color:var(--text-dim); margin-top:6px;">
                  Reed-Solomon RS(4,2) Pulih: <strong>${t.recovered || 0}</strong> paket | Duplikat diabaikan: ${t.dups || 0}
                </div>
              </div>
            `;
          }).join("");
        }
      }
    } catch (e) {
      console.warn("Live status error:", e);
    }
  }

  async function refreshVault() {
    try {
      const files = await getJSON("/api/vault");
      const vaultBadge = $("#vault-count-badge");
      if (vaultBadge) vaultBadge.textContent = `${files.length} Berkas Tersimpan`;

      const tbody = $("#vault-table-body");
      if (!tbody) return;

      if (!files.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Brankas masih kosong. Belum ada file yang lolos pemeriksaan & terkirim.</td></tr>`;
        return;
      }

      tbody.innerHTML = files.map((f) => {
        const time = (f.received_at || "").slice(11, 19) || "--:--:--";
        const shortUuid = (f.stored_as || "").slice(0, 16) + "…";
        const shortSha = (f.sha256 || "").slice(0, 16) + "…";
        const isFec = (f.recovered_by_fec > 0);
        return `
          <tr>
            <td class="cell-filename">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
              </svg>
              ${f.name}
            </td>
            <td class="cell-time">${shortUuid}</td>
            <td>${fmtSize(f.size)}</td>
            <td class="cell-time" title="${f.sha256}">${shortSha}</td>
            <td class="cell-time">${time}</td>
            <td>
              <span class="badge-status ${isFec ? 'pass' : 'pass'}" style="${isFec ? 'border-color:var(--accent-amber);color:var(--accent-amber);' : ''}">
                ${isFec ? `RS(4,2) Pulih (${f.recovered_by_fec})` : 'Penuh 100%'}
              </span>
            </td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      console.warn("Vault refresh error:", e);
    }
  }

  async function refreshAudit() {
    try {
      const a = await getJSON("/api/audit");
      const chainBadge = $("#chain-badge-high");
      if (chainBadge) {
        if (a.chain && a.chain.ok) {
          chainBadge.className = "pill-badge normal";
          chainBadge.textContent = `Rantai Hash Utuh (${a.chain.records || 0} Catatan)`;
        } else {
          chainBadge.className = "pill-badge fail";
          chainBadge.style.color = "var(--accent-red)";
          chainBadge.textContent = `Rantai Hash Putus Baris ${a.chain?.first_bad_line}!`;
        }
      }

      const tbody = $("#audit-table-body");
      if (!tbody) return;

      if (!a.records || !a.records.length) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Belum ada catatan audit masuk.</td></tr>`;
        return;
      }

      tbody.innerHTML = a.records.slice().reverse().slice(0, 15).map((r) => {
        const time = (r.ts || "").slice(11, 19) || "--:--:--";
        const label = r.name || (r.file_id ? `UUID [${r.file_id.slice(0, 8)}]` : "-");
        const code = r.code || r.event || "-";
        return `
          <tr>
            <td class="cell-time">${time}</td>
            <td style="font-weight:600; color:var(--accent-mint);">${r.event || "-"}</td>
            <td>${label}</td>
            <td class="cell-time">${code}</td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      console.warn("Audit refresh error:", e);
    }
  }

  refreshLive();
  refreshVault();
  refreshAudit();

  setInterval(refreshLive, 1000);
  setInterval(refreshVault, 2500);
  setInterval(refreshAudit, 3000);
})();
