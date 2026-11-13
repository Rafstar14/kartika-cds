(() => {
  const $ = (s) => document.querySelector(s);
  const getJSON = async (u) => {
    const r = await fetch(u, { cache: "no-store" });
    if (!r.ok) throw new Error(String(r.status));
    return r.json();
  };

  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : n >= 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B");
  const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[ch]);
  const setText = (selector, text) => { const el = $(selector); if (el) el.textContent = text; };

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
          statusBadge.style.borderColor = "";
          statusBadge.style.color = "";
          statusText.textContent = "Receiver Aktif (RX-Only)";
        } else {
          statusBadge.className = "pill-badge";
          statusBadge.style.borderColor = "var(--accent-amber)";
          statusBadge.style.color = "var(--accent-amber)";
          statusText.textContent = "Status receiver belum mutakhir";
        }
      }

      // OT Telemetry
      const ot = d.ot_radar || {};
      setText("#ot_fw", ot.firmware_version || "Belum tersedia");
      setText("#ot_freq", ot.sweep_freq_mhz ? `${ot.sweep_freq_mhz} MHz` : "Belum tersedia");
      setText("#ot_lock", ot.interlock_status || "Belum tersedia");
      setText("#ot_unit", ot.unit || "Status simulasi belum tersedia");

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
          activeBox.innerHTML = `<p class="empty-state">Tidak ada transfer masuk saat ini.</p>`;
        } else {
          activeBox.innerHTML = d.active.map((t) => {
            const pct = Math.max(0, Math.min(100, Math.round((100 * (Number(t.received) || 0)) / (Number(t.total) || 1))));
            return `
              <div style="margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-weight:600;">
                  <span>${escapeHTML(t.name)} (${escapeHTML(fmtSize(t.size))})</span>
                  <span style="color:var(--accent-emerald);">${pct}% (${escapeHTML(t.received)}/${escapeHTML(t.total)} paket)</span>
                </div>
                <div class="transfer-progress-bar">
                  <div class="transfer-progress-fill" style="width:${pct}%;"></div>
                </div>
                <div style="font-size:12px; color:var(--text-dim); margin-top:6px;">
                  Reed-Solomon RS(4,2) Pulih: <strong>${escapeHTML(t.recovered || 0)}</strong> paket | Duplikat diabaikan: ${escapeHTML(t.dups || 0)}
                </div>
              </div>
            `;
          }).join("");
        }
      }
    } catch (e) {
      const badge = $("#top-status-badge");
      if (badge) { badge.className = "pill-badge"; badge.style.color = ""; badge.style.borderColor = ""; }
      setText("#top-status-text", "Status receiver tidak tersedia");
      setText("#ot_fw", "Tidak tersedia");
      setText("#ot_freq", "Tidak tersedia");
      setText("#ot_lock", "Tidak tersedia");
      setText("#ot_unit", "Status simulasi tidak tersedia");
      setText("#rx-packets-badge", "Jumlah paket tidak tersedia");
      setText("#stat-fec-recovered", "Tidak tersedia");
      const activeBox = $("#active-transfers-box");
      if (activeBox) activeBox.innerHTML = `<p class="empty-state">Transfer tidak dapat dimuat. Periksa koneksi ke server.</p>`;
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
              ${escapeHTML(f.name)}
            </td>
            <td class="cell-time">${escapeHTML(shortUuid)}</td>
            <td>${escapeHTML(fmtSize(f.size))}</td>
            <td class="cell-time" title="${escapeHTML(f.sha256)}">${escapeHTML(shortSha)}</td>
            <td class="cell-time">${escapeHTML(time)}</td>
            <td>
              <span class="badge-status ${isFec ? 'pass' : 'pass'}" style="${isFec ? 'border-color:var(--accent-amber);color:var(--accent-amber);' : ''}">
                ${isFec ? `RS(4,2) Pulih (${escapeHTML(f.recovered_by_fec)})` : 'Tidak perlu pemulihan'}
              </span>
            </td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      setText("#vault-count-badge", "Brankas tidak tersedia");
      const tbody = $("#vault-table-body");
      if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="empty-state">Brankas tidak dapat dimuat. Periksa koneksi ke server.</td></tr>`;
    }
  }

  async function refreshAudit() {
    try {
      const a = await getJSON("/api/audit");
      const chainBadge = $("#chain-badge-high");
      if (chainBadge) {
        if (a.chain && a.chain.ok) {
          chainBadge.className = "pill-badge normal";
          chainBadge.style.color = "";
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
            <td class="cell-time">${escapeHTML(time)}</td>
            <td style="font-weight:600; color:var(--accent-mint);">${escapeHTML(r.event || "-")}</td>
            <td>${escapeHTML(label)}</td>
            <td class="cell-time">${escapeHTML(code)}</td>
          </tr>
        `;
      }).join("");
    } catch (e) {
      const badge = $("#chain-badge-high");
      if (badge) { badge.className = "pill-badge"; badge.style.color = ""; badge.textContent = "Status audit tidak tersedia"; }
      const tbody = $("#audit-table-body");
      if (tbody) tbody.innerHTML = `<tr><td colspan="4" class="empty-state">Audit tidak dapat dimuat. Periksa koneksi ke server.</td></tr>`;
    }
  }

  refreshLive();
  refreshVault();
  refreshAudit();

  setInterval(refreshLive, 1000);
  setInterval(refreshVault, 2500);
  setInterval(refreshAudit, 3000);
})();
