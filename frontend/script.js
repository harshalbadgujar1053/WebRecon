// =============================================
// SyknetScope — Frontend Logic
// Fixes: IST time, yesNo logic, WHOIS dates,
//        export panel (PDF / JSON / CSV / TXT)
// =============================================

const API_BASE = "http://127.0.0.1:8000";

// ---- IST Clock ----
function getIST() {
    return new Date().toLocaleString("en-IN", {
        timeZone: "Asia/Kolkata",
        year: "numeric", month: "2-digit", day: "2-digit",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: false
    }).replace(",", "") + " IST";
}

function updateClock() {
    const el = document.getElementById("clock");
    if (el) el.textContent = getIST();
}
setInterval(updateClock, 1000);
updateClock();

// ---- Globals ----
let lastScanData   = null;
let lastScanType   = null;
let lastScanDomain = null;

// ---- Helpers ----
function $(id) { return document.getElementById(id); }

function getDomain() {
    return $("domain").value.trim().replace(/^https?:\/\//, "").split("/")[0];
}

function setStatus(id, text, type = "ok") {
    const el = $("status-" + id);
    if (!el) return;
    el.textContent = text;
    el.className   = "card-status " + type;
}

function kv(label, value, valClass = "") {
    if (value === null || value === undefined || value === "")
        value = '<span class="no-data">—</span>';
    return `<div class="kv-row">
        <span class="kv-key">${label}</span>
        <span class="kv-val ${valClass}">${value}</span>
    </div>`;
}

function tag(text, color = "cyan") {
    return `<span class="tag tag-${color}">${escHTML(text)}</span>`;
}

function errorHTML(msg) {
    return `<div class="error-msg">⚠ ${escHTML(msg)}</div>`;
}

// FIX: goodIsTrue=true means green=YES, red=NO (e.g. HTTPS, DNSSEC enabled)
//      goodIsTrue=false means green=NO, red=YES (e.g. has_forms, has_login — bad features)
function yesNo(val, goodIsTrue = true) {
    if (val === true)
        return goodIsTrue
            ? '<span class="kv-val green">✓ YES</span>'
            : '<span class="kv-val amber">⚠ YES</span>';
    if (val === false)
        return goodIsTrue
            ? '<span class="kv-val red">✗ NO</span>'
            : '<span class="kv-val green">✓ NO</span>';
    return `<span class="kv-val">${escHTML(String(val ?? "—"))}</span>`;
}

// ---- Loading ----
const PASSIVE_STEPS = [
    "Resolving IP address...",
    "Querying WHOIS database...",
    "Fetching DNS records...",
    "Analyzing HTTP headers...",
    "Checking TLS certificate...",
    "Detecting firewall / WAF...",
    "Scanning tech stack...",
    "Running threat intelligence...",
    "Finalizing results..."
];
const ACTIVE_STEPS = [
    "Scanning ports 1–1024...",
    "Enumerating subdomains...",
    "Brute-forcing directories...",
    "Detecting API endpoints...",
    "Compiling results..."
];

let loadingTimer = null;

function showLoading(steps) {
    $("loadingOverlay").classList.remove("hidden");
    $("loadingFill").style.width = "0%";
    $("loadingLog").innerHTML    = "";
    let i = 0;
    function step() {
        if (i < steps.length) {
            $("loadingFill").style.width = Math.round(((i + 1) / steps.length) * 90) + "%";
            $("loadingText").textContent = steps[i];
            const line = document.createElement("div");
            line.className   = "log-line";
            line.textContent = "› " + steps[i];
            $("loadingLog").appendChild(line);
            $("loadingLog").scrollTop = 9999;
            i++;
            loadingTimer = setTimeout(step, 800 + Math.random() * 600);
        }
    }
    step();
}

function hideLoading() {
    clearTimeout(loadingTimer);
    $("loadingFill").style.width = "100%";
    setTimeout(() => $("loadingOverlay").classList.add("hidden"), 300);
}

// ---- Target banner ----
function showBanner(domain, type) {
    $("results-container").classList.remove("hidden");
    $("tbDomain").textContent = domain;
    $("tbType").textContent   = type;
    $("tbTime").textContent   = getIST();
}

// ====================================================
//  PASSIVE SCAN
// ====================================================
async function runPassiveScan() {
    const domain = getDomain();
    if (!domain) { alert("Enter a domain first"); return; }

    lastScanDomain = domain;
    lastScanType   = "passive";
    lastScanData   = null;
    hideExportPanel();

    $("passiveSection").classList.remove("hidden");
    $("activeSection").classList.add("hidden");
    showBanner(domain, "PASSIVE RECON");
    showLoading(PASSIVE_STEPS);
    setAllCardStatus("loading", "SCANNING...");

    try {
        const res  = await fetch(`${API_BASE}/scan?domain=${encodeURIComponent(domain)}`);
        const data = await res.json();
        hideLoading();
        lastScanData = data;
        renderPassiveResults(data);
        showExportPanel();
    } catch (err) {
        hideLoading();
        $("body-ip").innerHTML = errorHTML("Failed to reach backend. Is uvicorn running on port 8000?");
    }
}

function setAllCardStatus(type, text) {
    ["ip","whois","dns","tls","headers","email","tech","firewall","threat","page"]
        .forEach(id => setStatus(id, text, type));
}

function renderPassiveResults(data) {
    renderIPInfo(data.ip_info);
    renderWhois(data.whois);
    renderDNS(data.dns_records);
    renderTLS(data.ssl_chain, data.tls_cipher_suites, data.tls_security_config, data.tls_handshake);
    renderHeaders(data.http_info);
    renderEmailSec(data.email_configuration, data.dns_security);
    renderTech(data.tech_stack);
    renderFirewall(data.firewall_detection);
    renderThreat(data.threat_analysis);
    renderPage(data.page_analysis);
    $("rawJson").textContent = JSON.stringify(data, null, 2);
}

function renderIPInfo(d) {
    if (!d) return;
    if (d.error) { $("body-ip").innerHTML = errorHTML(d.error); setStatus("ip","ERROR","err"); return; }
    $("body-ip").innerHTML = [
        kv("IP Address", `<span class="kv-val cyan mono">${escHTML(d.ip || "—")}</span>`),
        kv("City",       escHTML(d.city    || "—")),
        kv("Region",     escHTML(d.region  || "—")),
        kv("Country",    escHTML(d.country || "—")),
        kv("ASN / Org",  escHTML(d.org     || "—")),
        kv("Coordinates",escHTML(d.location|| "—")),
    ].join("");
    setStatus("ip", "OK", "ok");
}

function renderWhois(d) {
    if (!d) return;
    if (d.error) { $("body-whois").innerHTML = errorHTML(d.error); setStatus("whois","ERROR","err"); return; }

    // FIX: dates are now pre-formatted strings from the fixed whois_lookup.py
    const dn = Array.isArray(d.domain_name) ? d.domain_name[0] : (d.domain_name || "—");
    const ns = Array.isArray(d.name_servers)
        ? d.name_servers.join(", ")
        : (d.name_servers || "—");

    $("body-whois").innerHTML = [
        kv("Domain",       escHTML(dn)),
        kv("Registrar",    escHTML(d.registrar       || "—")),
        kv("Created",      escHTML(d.creation_date   || "—")),
        kv("Expires",      escHTML(d.expiration_date || "—")),
        kv("Updated",      escHTML(d.updated_date    || "—")),
        kv("Name Servers", `<span class="kv-val mono" style="font-size:0.7rem">${escHTML(ns)}</span>`),
    ].join("");
    setStatus("whois", "OK", "ok");
}

function renderDNS(d) {
    if (!d) return;
    let html = "";
    ["A","AAAA","MX","NS","CNAME","TXT"].forEach(t => {
        const records = d[t];
        if (records && records.length) {
            const vals = records.map(r => `<span class="tag tag-cyan">${escHTML(r)}</span>`).join(" ");
            html += kv(t, vals);
        } else {
            html += kv(t, '<span class="no-data">—</span>');
        }
    });
    $("body-dns").innerHTML = html;
    setStatus("dns", "OK", "ok");
}

function renderTLS(chain, ciphers, config, handshake) {
    let html = "";
    if (chain && !chain.error) {
        html += kv("Subject",    escHTML(chain.subject?.commonName || "—"));
        html += kv("Issuer",     escHTML(chain.issuer?.organizationName || "—"));
        html += kv("Valid From", escHTML(chain.valid_from || "—"));
        html += kv("Valid To",   escHTML(chain.valid_to   || "—"));
        html += kv("Status", chain.expired
            ? '<span class="kv-val red">✗ EXPIRED</span>'
            : '<span class="kv-val green">✓ Valid</span>');
    } else if (chain?.error) {
        html += errorHTML(chain.error);
    }
    if (ciphers && !ciphers.error) {
        html += kv("Cipher Suite", `<span class="kv-val mono" style="font-size:0.7rem">${escHTML(ciphers.cipher_suite || "—")}</span>`);
        html += kv("Protocol",     escHTML(ciphers.protocol || "—"));
        html += kv("Key Size",     ciphers.key_size ? ciphers.key_size + " bits" : "—");
    }
    if (config) {
        const weak = config.weak_protocols_supported;
        html += kv("Weak Protocols", (weak && weak.length)
            ? `<span class="kv-val red">✗ ${escHTML(weak.join(", "))}</span>`
            : '<span class="kv-val green">✓ Secure</span>');
    }
    if (handshake) {
        html += kv("Handshake", handshake.handshake_successful
            ? `<span class="kv-val green">✓ Success (${escHTML(handshake.protocol)})</span>`
            : '<span class="kv-val red">✗ Failed</span>');
    }
    $("body-tls").innerHTML = html || '<span class="no-data">No TLS data</span>';
    setStatus("tls", chain?.expired ? "EXPIRED" : "OK", chain?.expired ? "err" : "ok");
}

function renderHeaders(d) {
    if (!d) return;
    if (d.error) { $("body-headers").innerHTML = errorHTML(d.error); setStatus("headers","ERROR","err"); return; }
    const sec = d.security_headers || {};
    const EXPECTED = [
        "Content-Security-Policy","X-Frame-Options",
        "X-Content-Type-Options","Referrer-Policy","Strict-Transport-Security"
    ];
    let html = kv("Status Code", d.status_code || "—");
    html += kv("Server", escHTML(d.server || "Hidden"));
    html += `<div style="margin-top:10px;font-size:0.68rem;color:var(--text-dim);letter-spacing:0.08em;margin-bottom:6px;">SECURITY HEADERS</div>`;
    EXPECTED.forEach(h => {
        html += `<div class="sec-header-row">
            <span class="sec-header-name">${h}</span>
            ${sec[h] ? '<span class="sec-header-val-present">✓ SET</span>' : '<span class="sec-header-val-missing">✗ MISSING</span>'}
        </div>`;
    });
    const missing = EXPECTED.filter(h => !sec[h]).length;
    $("body-headers").innerHTML = html;
    setStatus("headers", `${missing} MISSING`, missing > 0 ? "warn" : "ok");
}

function renderEmailSec(emailConf, dnsSec) {
    let html = "";
    if (dnsSec) {
        html += kv("DNSSEC", dnsSec.dnssec_enabled
            ? '<span class="kv-val green">✓ Enabled</span>'
            : '<span class="kv-val red">✗ Disabled</span>');
    }
    if (emailConf) {
        html += kv("SPF", emailConf.spf
            ? `<span class="kv-val green" style="font-size:0.7rem;word-break:break-all">${escHTML(emailConf.spf)}</span>`
            : '<span class="kv-val red">✗ Not configured</span>');
        html += kv("DMARC", emailConf.dmarc
            ? `<span class="kv-val green" style="font-size:0.7rem;word-break:break-all">${escHTML(emailConf.dmarc)}</span>`
            : '<span class="kv-val red">✗ Not configured</span>');
        html += kv("DKIM", escHTML(emailConf.dkim || "—"));
    }
    const issues = (!emailConf?.spf ? 1 : 0) + (!emailConf?.dmarc ? 1 : 0);
    $("body-email").innerHTML = html || '<span class="no-data">No data</span>';
    setStatus("email", issues > 0 ? `${issues} ISSUES` : "OK", issues > 0 ? "warn" : "ok");
}

function renderTech(d) {
    if (!d || d.error) {
        $("body-tech").innerHTML = d?.error ? errorHTML(d.error) : '<span class="no-data">No tech detected</span>';
        setStatus("tech", "N/A", "warn");
        return;
    }
    const entries = Object.entries(d);
    let html = entries.length === 0
        ? '<span class="no-data">No technologies detected</span>'
        : entries.map(([cat, techs]) =>
            kv(escHTML(cat), (Array.isArray(techs) ? techs : [techs]).map(t => tag(t, "cyan")).join(" "))
          ).join("");
    $("body-tech").innerHTML = html;
    setStatus("tech", entries.length + " FOUND", "ok");
}

function renderFirewall(d) {
    if (!d || d.error) {
        $("body-firewall").innerHTML = d?.error ? errorHTML(d.error) : '<span class="no-data">No data</span>';
        setStatus("firewall", "ERROR", "err");
        return;
    }
    let html = d.waf_detected
        ? kv("WAF Detected", `<span class="kv-val amber">✓ ${escHTML(d.provider?.toUpperCase() || "Unknown")}</span>`) +
          `<div style="margin-top:8px">${tag("WAF ACTIVE", "amber")}</div>`
        : kv("WAF Detected", '<span class="kv-val green">✗ None detected</span>');
    $("body-firewall").innerHTML = html;
    setStatus("firewall", d.waf_detected ? "WAF FOUND" : "NONE", d.waf_detected ? "warn" : "ok");
}

function renderThreat(d) {
    if (!d) return;
    const riskColors = { Low: "green", Medium: "amber", High: "red" };
    const riskColor  = riskColors[d.risk_level] || "cyan";

    const banner = $("riskBanner");
    banner.className = `risk-banner ${(d.risk_level || "low").toLowerCase()}`;
    banner.classList.remove("hidden");
    $("riskLevel").textContent   = `RISK: ${(d.risk_level || "UNKNOWN").toUpperCase()}`;
    $("riskFindings").textContent = (d.findings || []).join(" · ");

    let html = kv("Risk Level", `<span class="kv-val ${riskColor}" style="font-weight:700">${escHTML(d.risk_level)}</span>`);
    (d.findings || []).forEach(f => {
        const isGood = f.toLowerCase().includes("no obvious");
        html += `<div class="kv-row"><span class="kv-key">Finding</span>
            <span class="kv-val ${isGood ? "green" : "amber"}">${escHTML(f)}</span></div>`;
    });

    const vt = d.virustotal;
    if (vt?.enabled && vt.source) {
        html += `<div style="margin-top:10px;font-size:0.68rem;color:var(--text-dim);letter-spacing:0.08em;margin-bottom:6px;">VIRUSTOTAL</div>`;
        html += kv("Malicious",  `<span class="kv-val ${vt.malicious > 0 ? "red" : "green"}">${vt.malicious}</span>`);
        html += kv("Suspicious", `<span class="kv-val ${vt.suspicious > 0 ? "amber" : "green"}">${vt.suspicious}</span>`);
        html += kv("Harmless",   String(vt.harmless  || 0));
        html += kv("Reputation", String(vt.reputation || 0));
    }

    if (d.external_reports) {
        html += `<div style="margin-top:10px;font-size:0.68rem;color:var(--text-dim);letter-spacing:0.08em;margin-bottom:6px;">EXTERNAL REPORTS</div>`;
        Object.entries(d.external_reports).forEach(([name, url]) => {
            html += `<div class="kv-row"><span class="kv-key">${escHTML(name)}</span>
                <a href="${escHTML(url)}" target="_blank" rel="noopener" style="color:var(--cyan);font-size:0.7rem">${escHTML(url)}</a></div>`;
        });
    }
    $("body-threat").innerHTML = html;
    setStatus("threat", d.risk_level, d.risk_level === "High" ? "err" : d.risk_level === "Medium" ? "warn" : "ok");
}

function renderPage(d) {
    if (!d || d.error) {
        $("body-page").innerHTML = d?.error ? errorHTML(d.error) : '<span class="no-data">No data</span>';
        setStatus("page", "ERROR", "err");
        return;
    }
    let html = "";
    if (d.quality_metrics) {
        const q = d.quality_metrics;
        html += kv("Status Code",    String(q.status_code || "—"));
        html += kv("HTTPS",          yesNo(q.https));
        html += kv("Response Time",  q.response_time_ms ? Math.round(q.response_time_ms) + " ms" : "—");
        html += kv("Content Length", q.content_length ? formatBytes(q.content_length) : "—");
    }
    if (d.site_features) {
        const f = d.site_features;
        html += `<div style="margin-top:10px;font-size:0.68rem;color:var(--text-dim);letter-spacing:0.08em;margin-bottom:6px;">FEATURES DETECTED</div>`;
        // FIX: has_forms/has_login are bad indicators (attack surface), goodIsTrue=false → amber=YES
        html += kv("Has Forms",  yesNo(f.has_forms,  false));
        html += kv("Has Login",  yesNo(f.has_login,  false));
        html += kv("Uses JS",    yesNo(f.uses_javascript));
        html += kv("Has iFrame", yesNo(f.has_iframe, false));
    }
    $("body-page").innerHTML = html;
    setStatus("page", "OK", "ok");
}

// ====================================================
//  ACTIVE SCAN
// ====================================================
async function runActiveScan() {
    const domain = getDomain();
    if (!domain) { alert("Enter a domain first"); return; }

    if (!confirm("⚠ ACTIVE SCAN WARNING\n\nActive scanning sends traffic directly to the target.\nOnly scan systems you own or have explicit permission to test.\n\nContinue?"))
        return;

    lastScanDomain = domain;
    lastScanType   = "active";
    lastScanData   = null;
    hideExportPanel();

    $("activeSection").classList.remove("hidden");
    $("passiveSection").classList.add("hidden");
    showBanner(domain, "ACTIVE RECON");
    showLoading(ACTIVE_STEPS);
    ["ports","subdomains","dirs","api"].forEach(id => setStatus(id, "SCANNING...", "loading"));

    try {
        const res  = await fetch(`${API_BASE}/active-scan?domain=${encodeURIComponent(domain)}`);
        const data = await res.json();
        hideLoading();
        lastScanData = data;
        renderActiveScan(data);
        $("rawJsonActive").textContent = JSON.stringify(data, null, 2);
        showExportPanel();
    } catch (err) {
        hideLoading();
        $("body-ports").innerHTML = errorHTML("Failed to reach backend. Is uvicorn running on port 8000?");
    }
}

function renderActiveScan(data) {
    renderPorts(data.port_scan);
    renderSubdomains(data.subdomain_enum);
    renderDirs(data.directory_enum);
    renderAPI(data.api_discovery);
}

function renderPorts(d) {
    if (!d) { $("body-ports").innerHTML = '<span class="no-data">No data</span>'; return; }
    const ports = d.open_ports || [];
    const countHTML = `<div class="summary-counter">Scanned: <span class="count">${escHTML(d.scan_range || "")}</span> &nbsp;|&nbsp; Open: <span class="count">${ports.length}</span></div>`;
    if (!ports.length) {
        $("body-ports").innerHTML = countHTML + '<span class="no-data">No open ports found</span>';
        setStatus("ports", "0 OPEN", "ok"); return;
    }
    const rows = ports.map(p => `<tr>
        <td class="port-num">${p.port}</td>
        <td class="port-proto">${escHTML(p.protocol)}</td>
        <td class="port-service">${escHTML(p.service)}</td>
    </tr>`).join("");
    $("body-ports").innerHTML = countHTML + `<div class="port-table-wrap"><table>
        <thead><tr><th>PORT</th><th>PROTO</th><th>SERVICE</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`;
    setStatus("ports", ports.length + " OPEN", ports.length > 5 ? "warn" : "ok");
}

function renderSubdomains(d) {
    if (!d) { $("body-subdomains").innerHTML = '<span class="no-data">No data</span>'; return; }
    const found = d.found || [];
    const countHTML = `<div class="summary-counter">Tested: <span class="count">${d.total_tested}</span> &nbsp;|&nbsp; Found: <span class="count">${found.length}</span></div>`;
    if (!found.length) {
        $("body-subdomains").innerHTML = countHTML + '<span class="no-data">No subdomains discovered</span>';
        setStatus("subdomains", "0 FOUND", "ok"); return;
    }
    const items = found.map(s => `<div class="item-entry">
        <span class="item-url">${escHTML(s.subdomain)}</span>
        <span class="item-meta">${escHTML((s.ips || []).join(", "))}</span>
    </div>`).join("");
    $("body-subdomains").innerHTML = countHTML + `<div class="item-list">${items}</div>`;
    setStatus("subdomains", found.length + " FOUND", "warn");
}

function renderDirs(d) {
    if (!d) { $("body-dirs").innerHTML = '<span class="no-data">No data</span>'; return; }
    const found = d.found || [];
    const countHTML = `<div class="summary-counter">Tested: <span class="count">${d.total_tested}</span> &nbsp;|&nbsp; Found: <span class="count">${found.length}</span></div>`;
    if (!found.length) {
        $("body-dirs").innerHTML = countHTML + '<span class="no-data">No directories found</span>';
        setStatus("dirs", "0 FOUND", "ok"); return;
    }
    const items = found.map(f => `<div class="item-entry">
        <span class="item-url" style="font-size:0.7rem">${escHTML(f.url)}</span>
        <span class="item-meta item-status-${f.status_code}">${f.status_code} · ${escHTML(f.tag || "")}</span>
    </div>`).join("");
    $("body-dirs").innerHTML = countHTML + `<div class="item-list">${items}</div>`;
    setStatus("dirs", found.length + " FOUND", "warn");
}

function renderAPI(d) {
    if (!d) { $("body-api").innerHTML = '<span class="no-data">No data</span>'; return; }
    const found = d.found || [];
    const countHTML = `<div class="summary-counter">Tested: <span class="count">${d.total_tested}</span> &nbsp;|&nbsp; Found: <span class="count">${found.length}</span></div>`;
    if (!found.length) {
        $("body-api").innerHTML = countHTML + '<span class="no-data">No API endpoints found</span>';
        setStatus("api", "0 FOUND", "ok"); return;
    }
    const items = found.map(f => `<div class="item-entry">
        <span class="item-url" style="font-size:0.7rem">${escHTML(f.endpoint)}</span>
        <span class="item-meta item-status-${f.status_code}">${f.status_code} · ${escHTML(f.content_type || "")}</span>
    </div>`).join("");
    $("body-api").innerHTML = countHTML + `<div class="item-list">${items}</div>`;
    setStatus("api", found.length + " FOUND", "warn");
}

// ---- Raw JSON toggles ----
function toggleRaw()       { toggleAccordion("body-raw",        "rawArrow"); }
function toggleRawActive() { toggleAccordion("body-raw-active", "rawArrowActive"); }

function toggleAccordion(bodyId, arrowId) {
    $(bodyId).classList.toggle("hidden");
    $(arrowId).classList.toggle("open");
}

// ====================================================
//  EXPORT PANEL
// ====================================================
function showExportPanel() {
    const panel = $("exportPanel");
    if (panel) panel.classList.remove("hidden");
}
function hideExportPanel() {
    const panel = $("exportPanel");
    if (panel) panel.classList.add("hidden");
}

// ---- JSON ----
function exportJSON() {
    if (!lastScanData) return;
    const blob = new Blob([JSON.stringify(lastScanData, null, 2)], { type: "application/json" });
    triggerDownload(blob, `syknetscope_${lastScanDomain}_${lastScanType}.json`);
}

// ---- CSV ----
function exportCSV() {
    if (!lastScanData) return;
    const rows = [["Section", "Key", "Value"]];
    flattenToCSV(lastScanData, "", rows);
    const csv = rows.map(r => r.map(cell =>
        `"${String(cell ?? "").replace(/"/g, '""')}"`
    ).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    triggerDownload(blob, `syknetscope_${lastScanDomain}_${lastScanType}.csv`);
}

function flattenToCSV(obj, prefix, rows) {
    if (!obj || typeof obj !== "object") return;
    for (const [k, v] of Object.entries(obj)) {
        const key = prefix ? `${prefix} › ${k}` : k;
        if (Array.isArray(v)) {
            rows.push([prefix || "root", k, v.join(" | ")]);
        } else if (v && typeof v === "object") {
            flattenToCSV(v, key, rows);
        } else {
            const parts = key.split(" › ");
            rows.push([parts[0], parts.slice(1).join(" › ") || k, String(v ?? "")]);
        }
    }
}

// ---- TXT ----
function exportTXT() {
    if (!lastScanData) return;
    const lines = [
        "═══════════════════════════════════════════════════",
        "  SYKNETSCOPE — Security Reconnaissance Report",
        "═══════════════════════════════════════════════════",
        `  Target   : ${lastScanDomain}`,
        `  Scan Type: ${lastScanType.toUpperCase()} RECON`,
        `  Generated: ${getIST()}`,
        "═══════════════════════════════════════════════════",
        ""
    ];
    flattenToTXT(lastScanData, "", lines);
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    triggerDownload(blob, `syknetscope_${lastScanDomain}_${lastScanType}.txt`);
}

function flattenToTXT(obj, indent, lines) {
    if (!obj || typeof obj !== "object") return;
    for (const [k, v] of Object.entries(obj)) {
        if (Array.isArray(v)) {
            lines.push(`${indent}${k}:`);
            v.forEach(item => {
                if (typeof item === "object")
                    flattenToTXT(item, indent + "    ", lines);
                else
                    lines.push(`${indent}  - ${item}`);
            });
        } else if (v && typeof v === "object") {
            lines.push(`${indent}[${k}]`);
            flattenToTXT(v, indent + "  ", lines);
            lines.push("");
        } else {
            lines.push(`${indent}${k.padEnd(24)}: ${v ?? "—"}`);
        }
    }
}

// ---- PDF ----
function exportPDF() {
    if (!lastScanData) return;

    // Build a clean print-friendly HTML page and open it in a new window
    // User can then Ctrl+P → Save as PDF
    const ist = getIST();
    const domain = lastScanDomain;
    const type   = lastScanType.toUpperCase();

    const sections = buildPDFSections(lastScanData, lastScanType);

    const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>SyknetScope Report — ${domain}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'JetBrains Mono', monospace; background: #fff; color: #111; font-size: 11px; padding: 32px; }
  h1 { font-size: 18px; border-bottom: 2px solid #111; padding-bottom: 8px; margin-bottom: 4px; }
  .meta { color: #555; font-size: 10px; margin-bottom: 24px; }
  .section { margin-bottom: 20px; page-break-inside: avoid; }
  .section-title { background: #111; color: #00ff9f; font-size: 11px; font-weight: 700;
    letter-spacing: 0.1em; padding: 5px 10px; margin-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; }
  td { padding: 4px 8px; border-bottom: 1px solid #eee; vertical-align: top; }
  td:first-child { color: #555; width: 200px; font-size: 10px; white-space: nowrap; }
  td:last-child { word-break: break-all; }
  .risk-low    { color: #008000; font-weight: bold; }
  .risk-medium { color: #b85c00; font-weight: bold; }
  .risk-high   { color: #cc0000; font-weight: bold; }
  .footer { margin-top: 32px; border-top: 1px solid #ccc; padding-top: 8px; font-size: 9px; color: #999; }
  @media print { body { padding: 16px; } }
</style>
</head>
<body>
<h1>⬡ SyknetScope — Security Reconnaissance Report</h1>
<div class="meta">Target: <b>${domain}</b> &nbsp;|&nbsp; Scan: ${type} RECON &nbsp;|&nbsp; Generated: ${ist}</div>
${sections}
<div class="footer">⚠ This report is for authorized security testing and educational use only. — SyknetScope v1.0</div>
<script>window.onload = () => window.print();<\/script>
</body></html>`;

    const win = window.open("", "_blank");
    win.document.write(html);
    win.document.close();
}

function buildPDFSections(data, type) {
    if (type === "passive") return buildPassivePDF(data);
    return buildActivePDF(data);
}

function buildPassivePDF(d) {
    const riskClass = `risk-${(d.threat_analysis?.risk_level || "low").toLowerCase()}`;
    let out = "";

    out += pdfSection("IP INTELLIGENCE", [
        ["IP Address", d.ip_info?.ip],
        ["City / Region", `${d.ip_info?.city || ""}, ${d.ip_info?.region || ""}`],
        ["Country", d.ip_info?.country],
        ["ASN / Org", d.ip_info?.org],
        ["Coordinates", d.ip_info?.location]
    ]);

    out += pdfSection("WHOIS", [
        ["Domain", d.whois?.domain_name],
        ["Registrar", d.whois?.registrar],
        ["Created", d.whois?.creation_date],
        ["Expires", d.whois?.expiration_date],
        ["Name Servers", Array.isArray(d.whois?.name_servers) ? d.whois.name_servers.join(", ") : d.whois?.name_servers]
    ]);

    const dns = d.dns_records || {};
    out += pdfSection("DNS RECORDS", [
        ["A",     (dns.A     || []).join(", ")],
        ["AAAA",  (dns.AAAA  || []).join(", ")],
        ["MX",    (dns.MX    || []).join(", ")],
        ["NS",    (dns.NS    || []).join(", ")],
        ["TXT",   (dns.TXT   || []).join(" | ")]
    ]);

    const sc = d.ssl_chain || {};
    out += pdfSection("TLS / SSL", [
        ["Subject",    sc.subject?.commonName],
        ["Issuer",     sc.issuer?.organizationName],
        ["Valid From", sc.valid_from],
        ["Valid To",   sc.valid_to],
        ["Expired",    sc.expired ? "YES — EXPIRED" : "No"],
        ["Protocol",   d.tls_cipher_suites?.protocol],
        ["Cipher",     d.tls_cipher_suites?.cipher_suite],
        ["Weak Protos",(d.tls_security_config?.weak_protocols_supported || []).join(", ") || "None"]
    ]);

    const sec = d.http_info?.security_headers || {};
    out += pdfSection("HTTP SECURITY HEADERS", [
        ["Server", d.http_info?.server || "Hidden"],
        ["Status Code", d.http_info?.status_code],
        ["Content-Security-Policy",   sec["Content-Security-Policy"]   ? "✓ SET" : "✗ MISSING"],
        ["X-Frame-Options",           sec["X-Frame-Options"]           ? "✓ SET" : "✗ MISSING"],
        ["X-Content-Type-Options",    sec["X-Content-Type-Options"]    ? "✓ SET" : "✗ MISSING"],
        ["Referrer-Policy",           sec["Referrer-Policy"]           ? "✓ SET" : "✗ MISSING"],
        ["Strict-Transport-Security", sec["Strict-Transport-Security"] ? "✓ SET" : "✗ MISSING"]
    ]);

    const em = d.email_configuration || {};
    out += pdfSection("EMAIL SECURITY", [
        ["DNSSEC", d.dns_security?.dnssec_enabled ? "✓ Enabled" : "✗ Disabled"],
        ["SPF",    em.spf   || "Not configured"],
        ["DMARC",  em.dmarc || "Not configured"],
        ["DKIM",   em.dkim  || "—"]
    ]);

    const th = d.threat_analysis || {};
    out += pdfSection("THREAT ANALYSIS", [
        ["Risk Level", `<span class="${riskClass}">${th.risk_level || "—"}</span>`],
        ...((th.findings || []).map((f, i) => [`Finding ${i+1}`, f])),
        ["VT Malicious",  th.virustotal?.malicious  ?? "—"],
        ["VT Suspicious", th.virustotal?.suspicious ?? "—"],
        ["VT Harmless",   th.virustotal?.harmless   ?? "—"]
    ]);

    return out;
}

function buildActivePDF(d) {
    let out = "";

    const ports = (d.port_scan?.open_ports || []);
    out += pdfSection("OPEN PORTS", ports.length
        ? ports.map(p => [`Port ${p.port}`, `${p.protocol} — ${p.service}`])
        : [["Result", "No open ports found"]]);

    const subs = (d.subdomain_enum?.found || []);
    out += pdfSection("SUBDOMAINS", subs.length
        ? subs.map(s => [s.subdomain, (s.ips || []).join(", ")])
        : [["Result", "No subdomains found"]]);

    const dirs = (d.directory_enum?.found || []);
    out += pdfSection("DIRECTORIES", dirs.length
        ? dirs.map(f => [f.url, `${f.status_code} · ${f.tag || ""}`])
        : [["Result", "No directories found"]]);

    const apis = (d.api_discovery?.found || []);
    out += pdfSection("API ENDPOINTS", apis.length
        ? apis.map(a => [a.endpoint, `${a.status_code} · ${a.content_type || ""}`])
        : [["Result", "No API endpoints found"]]);

    return out;
}

function pdfSection(title, rows) {
    const validRows = rows.filter(r => r[1] !== null && r[1] !== undefined && r[1] !== "");
    const trs = validRows.map(([k, v]) =>
        `<tr><td>${escHTML(String(k))}</td><td>${v ?? "—"}</td></tr>`
    ).join("");
    return `<div class="section">
        <div class="section-title">◈ ${title}</div>
        <table><tbody>${trs}</tbody></table>
    </div>`;
}

function triggerDownload(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a   = document.createElement("a");
    a.href    = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ====================================================
//  UTILITIES
// ====================================================
function escHTML(str) {
    if (typeof str !== "string") str = String(str ?? "");
    return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function formatBytes(bytes) {
    if (bytes < 1024)    return bytes + " B";
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1048576).toFixed(1) + " MB";
}