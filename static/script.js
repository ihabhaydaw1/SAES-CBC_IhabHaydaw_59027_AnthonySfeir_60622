/* ================================================================
   S-AES Crypto Studio — Frontend Logic
   ================================================================ */

document.addEventListener("DOMContentLoaded", () => {

    // ── Tab Navigation ──
    const tabBtns = document.querySelectorAll(".tab-btn");
    const panels  = document.querySelectorAll(".panel");

    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            panels.forEach(p => p.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(btn.dataset.target).classList.add("active");
        });
    });

    // ── File Drag & Drop ──
    function setupDragDrop(dropId, inputId, nameId) {
        const area  = document.getElementById(dropId);
        const input = document.getElementById(inputId);
        const name  = document.getElementById(nameId);

        ["dragenter", "dragover", "dragleave", "drop"].forEach(ev =>
            area.addEventListener(ev, e => { e.preventDefault(); e.stopPropagation(); }, false)
        );
        ["dragenter", "dragover"].forEach(ev =>
            area.addEventListener(ev, () => area.classList.add("dragover"))
        );
        ["dragleave", "drop"].forEach(ev =>
            area.addEventListener(ev, () => area.classList.remove("dragover"))
        );
        area.addEventListener("drop", e => { input.files = e.dataTransfer.files; show(); });
        input.addEventListener("change", show);

        function show() {
            name.textContent = input.files.length ? input.files[0].name : "";
        }
    }
    setupDragDrop("ed-drop-area", "ed-file", "ed-file-name");
    setupDragDrop("bf-drop-area", "bf-file", "bf-file-name");

    // ── Mode Toggle (File / Text) ──
    const modeToggle = document.getElementById("ed-mode-toggle");
    const formFile   = document.getElementById("ed-form-file");
    const formText   = document.getElementById("ed-form-text");

    modeToggle.querySelectorAll(".mode-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            modeToggle.querySelectorAll(".mode-btn").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            if (btn.dataset.mode === "file") {
                formFile.classList.remove("hidden");
                formText.classList.add("hidden");
            } else {
                formFile.classList.add("hidden");
                formText.classList.remove("hidden");
            }
        });
    });

    // ── Helper: show result ──
    function showResult(el, html, type) {
        el.innerHTML = html;
        el.className = "result-box " + (type || "");
        el.classList.remove("hidden");
    }

    function showError(el, msg) {
        showResult(el, `<div class="result-title">❌ Error</div><p>${msg}</p>`, "error");
    }

    // ────────────────────────────────────────────────────────────
    // TAB 1 — Encrypt / Decrypt
    // ────────────────────────────────────────────────────────────

    const edResult = document.getElementById("ed-result");

    // File mode
    async function processFile(action) {
        edResult.classList.add("hidden");
        const fileInput = document.getElementById("ed-file");
        const key = document.getElementById("ed-key-file").value.trim();
        const iv  = document.getElementById("ed-iv-file").value.trim();

        if (!fileInput.files.length) return showError(edResult, "Please select a file.");
        if (!key || !iv) return showError(edResult, "Please enter both Key and IV.");

        const fd = new FormData();
        fd.append("file", fileInput.files[0]);
        fd.append("key", key);
        fd.append("iv", iv);
        fd.append("action", action);

        try {
            const res = await fetch("/api/process_file", { method: "POST", body: fd });
            if (res.ok) {
                const blob = await res.blob();
                const url  = URL.createObjectURL(blob);
                const a    = document.createElement("a");
                a.href = url;

                let filename = action + "ed_file";
                const disp = res.headers.get("Content-Disposition");
                if (disp) {
                    const m = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(disp);
                    if (m) filename = m[1].replace(/['"]/g, "");
                }
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);

                showResult(edResult, `
                    <div class="result-title">✅ ${action === "encrypt" ? "Encryption" : "Decryption"} Complete</div>
                    <div class="result-row"><span class="result-label">Downloaded as</span><span class="result-value">${filename}</span></div>
                    <div class="result-row"><span class="result-label">Key</span><span class="result-value">${key}</span></div>
                    <div class="result-row"><span class="result-label">IV</span><span class="result-value">${iv}</span></div>
                `, "success");
            } else {
                const d = await res.json();
                showError(edResult, d.error || "Unknown error");
            }
        } catch (err) {
            showError(edResult, err.message);
        }
    }

    document.getElementById("btn-encrypt-file").addEventListener("click", () => processFile("encrypt"));
    document.getElementById("btn-decrypt-file").addEventListener("click", () => processFile("decrypt"));

    // Text mode
    async function processText(action) {
        edResult.classList.add("hidden");
        const text = document.getElementById("ed-text-input").value.trim();
        const key  = document.getElementById("ed-key-text").value.trim();
        const iv   = document.getElementById("ed-iv-text").value.trim();

        if (!text) return showError(edResult, "Please enter text.");
        if (!key || !iv) return showError(edResult, "Please enter both Key and IV.");

        try {
            const res = await fetch("/api/process_text", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action, text, key, iv }),
            });
            const d = await res.json();
            if (!res.ok || d.error) return showError(edResult, d.error || "Unknown error");

            if (action === "encrypt") {
                showResult(edResult, `
                    <div class="result-title">🔒 Encryption Result</div>
                    <div class="result-row"><span class="result-label">Key</span><span class="result-value">${key}</span></div>
                    <div class="result-row"><span class="result-label">IV</span><span class="result-value">${iv}</span></div>
                    <div class="result-row"><span class="result-label">Ciphertext length</span><span class="result-value">${d.result_len} bytes</span></div>
                    <div class="result-message-box">${d.result_hex}</div>
                `, "success");
            } else {
                showResult(edResult, `
                    <div class="result-title">🔓 Decryption Result</div>
                    <div class="result-row"><span class="result-label">Key</span><span class="result-value">${key}</span></div>
                    <div class="result-row"><span class="result-label">IV</span><span class="result-value">${iv}</span></div>
                    <div class="result-row"><span class="result-label">Plaintext length</span><span class="result-value">${d.result_len} bytes</span></div>
                    <div class="result-message-box">${escapeHtml(d.result_text)}</div>
                `, "success");
            }
        } catch (err) {
            showError(edResult, err.message);
        }
    }

    document.getElementById("btn-encrypt-text").addEventListener("click", () => processText("encrypt"));
    document.getElementById("btn-decrypt-text").addEventListener("click", () => processText("decrypt"));

    // ────────────────────────────────────────────────────────────
    // TAB 2 — Brute Force
    // ────────────────────────────────────────────────────────────

    const bfForm    = document.getElementById("bf-form");
    const bfResult  = document.getElementById("bf-result");
    const bfLoading = document.getElementById("bf-loading");

    bfForm.addEventListener("submit", async e => {
        e.preventDefault();
        bfResult.classList.add("hidden");
        bfLoading.classList.remove("hidden");

        const fd = new FormData(bfForm);

        try {
            const res  = await fetch("/api/brute_force", { method: "POST", body: fd });
            const data = await res.json();
            bfLoading.classList.add("hidden");

            if (!res.ok) return showError(bfResult, data.error || "Server error");

            if (data.success) {
                showResult(bfResult, `
                    <div class="result-title">⚡ Key Recovered!</div>
                    <div class="result-row"><span class="result-label">Found Key</span><span class="result-value key-found">${data.found_key}</span></div>
                    <div class="result-row"><span class="result-label">Time</span><span class="result-value">${data.time}s</span></div>
                    <div class="result-row"><span class="result-label">Keys Tested</span><span class="result-value">${data.keys_tested}</span></div>
                    ${data.preview ? `<div class="result-message-box">${escapeHtml(data.preview)}</div>` : ""}
                `, "success");
            } else {
                showResult(bfResult, `
                    <div class="result-title">❌ Attack Failed</div>
                    <div class="result-row"><span class="result-label">Result</span><span class="result-value key-failed">${data.message}</span></div>
                    <div class="result-row"><span class="result-label">Time</span><span class="result-value">${data.time}s</span></div>
                `, "error");
            }
        } catch (err) {
            bfLoading.classList.add("hidden");
            showError(bfResult, err.message);
        }
    });

    // ────────────────────────────────────────────────────────────
    // TAB 3 — Cryptanalysis
    // ────────────────────────────────────────────────────────────

    const caResult  = document.getElementById("ca-result");
    const caLoading = document.getElementById("ca-loading");
    const caLoadMsg = document.getElementById("ca-loading-msg");

    const attackLabels = {
        kpa:          "Running Known-Plaintext Attack…",
        differential: "Running Differential Cryptanalysis (may take a moment)…",
        linear:       "Running Linear Cryptanalysis (may take a moment)…",
        bitflip:      "Running CBC Bit-Flipping Attack…",
    };

    document.querySelectorAll(".attack-card").forEach(card => {
        card.addEventListener("click", async () => {
            const attack = card.dataset.attack;
            const key = document.getElementById("ca-key").value.trim() || "0x3A94";
            const iv  = document.getElementById("ca-iv").value.trim()  || "0xBEEF";

            caResult.classList.add("hidden");
            caLoadMsg.textContent = attackLabels[attack] || "Running…";
            caLoading.classList.remove("hidden");

            // Disable all cards during attack
            document.querySelectorAll(".attack-card").forEach(c => c.disabled = true);

            try {
                const res = await fetch("/api/cryptanalysis", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ attack_type: attack, key, iv }),
                });
                const data = await res.json();
                caLoading.classList.add("hidden");

                if (!res.ok || data.error) {
                    showError(caResult, data.error || "Server error");
                } else {
                    renderCryptoResult(attack, data);
                }
            } catch (err) {
                caLoading.classList.add("hidden");
                showError(caResult, err.message);
            }

            document.querySelectorAll(".attack-card").forEach(c => c.disabled = false);
        });
    });

    function renderCryptoResult(type, d) {
        let html = `<div class="result-title">${d.attack}</div>`;

        if (type === "kpa") {
            html += `
                <div class="result-row"><span class="result-label">Known Plaintext</span><span class="result-value">${d.known_pt}</span></div>
                <div class="result-row"><span class="result-label">Known Ciphertext</span><span class="result-value">${d.known_ct}</span></div>
                <div class="result-row"><span class="result-label">Keys Tested</span><span class="result-value">${d.keys_tested}</span></div>
                <div class="result-row"><span class="result-label">Time</span><span class="result-value">${d.time}</span></div>
                <div class="result-row"><span class="result-label">Found Key</span><span class="result-value ${d.match ? 'key-found' : 'key-failed'}">${d.found_key || 'Not found'}</span></div>
                <div class="result-row"><span class="result-label">Match</span><span class="result-value">${d.match ? '✅ Correct' : '❌ Mismatch'}</span></div>
            `;
        }

        else if (type === "differential") {
            html += `
                <div class="result-row"><span class="result-label">Best Differential</span><span class="result-value">Δin=${d.best_diff.dx} → Δout=${d.best_diff.dy} (p=${d.best_diff.prob})</span></div>
                <div class="result-row"><span class="result-label">Actual K2</span><span class="result-value">${d.actual_k2}</span></div>
                <div class="result-row"><span class="result-label">Time</span><span class="result-value">${d.time}</span></div>
            `;
            html += `<p style="margin-top:12px;color:var(--text-muted);font-size:0.84rem;">Top 5 Differentials:</p>`;
            html += buildTable(["Δin", "Δout", "Count", "Probability"], d.top_differentials.map(r => [r.dx, r.dy, r.count, r.prob]));
            html += `<p style="margin-top:12px;color:var(--text-muted);font-size:0.84rem;">Last-Round Key Candidates:</p>`;
            html += buildTable(
                ["Key", "Score", "Correct?"],
                d.candidates.map(c => [c.key, c.score, c.correct ? "✅" : ""]),
                d.candidates.map(c => c.correct)
            );
        }

        else if (type === "linear") {
            html += `
                <div class="result-row"><span class="result-label">Actual K2</span><span class="result-value">${d.actual_k2}</span></div>
                <div class="result-row"><span class="result-label">Time</span><span class="result-value">${d.time}</span></div>
            `;
            html += `<p style="margin-top:12px;color:var(--text-muted);font-size:0.84rem;">Top 5 Linear Approximations:</p>`;
            html += buildTable(["Input Mask", "Output Mask", "Bias", "|Bias|/16"], d.top_approximations.map(r => [r.a, r.b, r.bias, r.abs_bias]));
            html += `<p style="margin-top:12px;color:var(--text-muted);font-size:0.84rem;">Last-Round Key Candidates:</p>`;
            html += buildTable(
                ["Key", "Deviation", "Correct?"],
                d.candidates.map(c => [c.key, c.deviation, c.correct ? "✅" : ""]),
                d.candidates.map(c => c.correct)
            );
        }

        else if (type === "bitflip") {
            html += `
                <div class="result-row"><span class="result-label">Original Plaintext</span><span class="result-value">${escapeHtml(d.original_plaintext)}</span></div>
                <div class="result-row"><span class="result-label">Original Ciphertext</span><span class="result-value" style="font-size:0.78rem">${d.original_ct_hex}</span></div>
                <div class="result-row"><span class="result-label">Flip Position</span><span class="result-value">byte ${d.flip_position}</span></div>
                <div class="result-row"><span class="result-label">Flip Mask</span><span class="result-value">${d.flip_mask}</span></div>
                <div class="result-row"><span class="result-label">Modified Ciphertext</span><span class="result-value" style="font-size:0.78rem">${d.modified_ct_hex}</span></div>
                <div class="result-row"><span class="result-label">Modified Plaintext</span><span class="result-value key-found">${escapeHtml(d.modified_plaintext)}</span></div>
            `;
            html += `<div class="result-message-box">${escapeHtml(d.explanation)}</div>`;
        }

        showResult(caResult, html, d.success !== false ? "success" : "error");
    }

    // ────────────────────────────────────────────────────────────
    // TAB 4 — Step 4 Attack
    // ────────────────────────────────────────────────────────────

    const s4Btn     = document.getElementById("btn-step4");
    const s4Loading = document.getElementById("s4-loading");
    const s4Result  = document.getElementById("s4-result");

    s4Btn.addEventListener("click", async () => {
        s4Result.classList.add("hidden");
        s4Loading.classList.remove("hidden");
        s4Btn.disabled = true;

        try {
            const res  = await fetch("/api/step4_attack", { method: "POST" });
            const data = await res.json();
            s4Loading.classList.add("hidden");

            if (!res.ok || data.error) {
                showError(s4Result, data.error || "Server error");
            } else if (data.success) {
                showResult(s4Result, `
                    <div class="result-title">🎯 Attack Successful!</div>
                    <div class="result-row"><span class="result-label">Actual Key (hidden)</span><span class="result-value">${data.actual_key}</span></div>
                    <div class="result-row"><span class="result-label">Recovered Key</span><span class="result-value key-found">${data.found_key}</span></div>
                    <div class="result-row"><span class="result-label">Match</span><span class="result-value">${data.match ? '✅ Correct' : '❌ Mismatch'}</span></div>
                    <div class="result-row"><span class="result-label">IV</span><span class="result-value">${data.iv}</span></div>
                    <div class="result-row"><span class="result-label">Ciphertext Size</span><span class="result-value">${data.ct_length} bytes</span></div>
                    <div class="result-row"><span class="result-label">Known Header</span><span class="result-value">"${escapeHtml(data.known_header)}"</span></div>
                    <div class="result-row"><span class="result-label">Keys Tested</span><span class="result-value">${data.keys_tested}</span></div>
                    <div class="result-row"><span class="result-label">Time</span><span class="result-value">${data.time}</span></div>
                    <p style="margin-top:14px;color:var(--text-muted);font-size:0.84rem;">Decrypted Message:</p>
                    <div class="result-message-box">${escapeHtml(data.decrypted_message)}</div>
                `, "success");
            } else {
                showResult(s4Result, `
                    <div class="result-title">❌ Attack Failed</div>
                    <p>${data.message || "Could not recover the key."}</p>
                `, "error");
            }
        } catch (err) {
            s4Loading.classList.add("hidden");
            showError(s4Result, err.message);
        }
        s4Btn.disabled = false;
    });

    // ────────────────────────────────────────────────────────────
    // Utilities
    // ────────────────────────────────────────────────────────────

    function escapeHtml(s) {
        if (!s) return "";
        return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    }

    function buildTable(headers, rows, correctFlags) {
        let html = '<table class="result-table"><thead><tr>';
        headers.forEach(h => html += `<th>${h}</th>`);
        html += "</tr></thead><tbody>";
        rows.forEach((row, i) => {
            const cls = correctFlags && correctFlags[i] ? ' class="correct"' : "";
            html += `<tr${cls}>`;
            row.forEach(c => html += `<td>${c}</td>`);
            html += "</tr>";
        });
        html += "</tbody></table>";
        return html;
    }

});
