const API_BASE = "http://127.0.0.1:8000";

function getDomain() {
    return document.getElementById("domain").value.trim();
}

/* ---------------- PASSIVE SCAN ---------------- */
async function runPassiveScan() {
    const domain = getDomain();
    const output = document.getElementById("passiveResult");

    if (!domain) {
        alert("Enter a domain");
        return;
    }

    output.textContent = "Running passive scan...";

    try {
        const res = await fetch(`${API_BASE}/scan?domain=${domain}`);
        const data = await res.json();
        output.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        output.textContent = "Error running passive scan";
    }
}

/* ---------------- ACTIVE SCAN ---------------- */
async function runActiveScan() {
    const domain = getDomain();

    const status = document.getElementById("activeStatus");
    const portsBody = document.querySelector("#portsTable tbody");

    const subdomainsBox = document.getElementById("subdomainResult");
    const directoriesBox = document.getElementById("directoryResult");
    const apiBox = document.getElementById("apiResult");
    const apiSubBox = document.getElementById("apiSubdomainResult");

    if (!domain) {
        alert("Enter a domain");
        return;
    }

    const confirmScan = confirm(
        "Active scanning interacts directly with the target.\n" +
        "Run only on authorized domains.\n\nProceed?"
    );
    if (!confirmScan) return;

    // Reset UI
    status.innerText = "Running active reconnaissance...";
    portsBody.innerHTML = "<tr><td colspan='3'>Scanning...</td></tr>";
    subdomainsBox.textContent = "Scanning...";
    directoriesBox.textContent = "Scanning...";
    apiBox.textContent = "Scanning...";
    apiSubBox.textContent = "Scanning...";

    try {
        const res = await fetch(`${API_BASE}/active-scan?domain=${domain}`);
        const data = await res.json();

        /* -------- PORT SCAN -------- */
        const ports =
            data.port_scan &&
            data.port_scan.open_ports;

        renderPortsTable(ports);

        /* -------- SUBDOMAINS -------- */
        subdomainsBox.textContent = JSON.stringify(
            data.subdomain_enum || {},
            null,
            2
        );

        /* -------- DIRECTORIES -------- */
        directoriesBox.textContent = JSON.stringify(
            data.directory_enum || {},
            null,
            2
        );

        /* -------- API DISCOVERY -------- */
        apiBox.textContent = JSON.stringify(
            data.api_discovery || {},
            null,
            2
        );

        /* -------- API SUBDOMAINS -------- */
        apiSubBox.textContent = JSON.stringify(
            data.api_subdomains || {},
            null,
            2
        );

        status.innerText = "Active scan completed ✅";

    } catch (err) {
        status.innerText = "Error running active scan";
        portsBody.innerHTML =
            "<tr><td colspan='3'>Failed to fetch data</td></tr>";
    }
}

/* ---------------- TABLE RENDER ---------------- */
function renderPortsTable(ports) {
    const tableBody = document.querySelector("#portsTable tbody");
    tableBody.innerHTML = "";

    if (!ports || ports.length === 0) {
        tableBody.innerHTML =
            "<tr><td colspan='3'>No open ports found</td></tr>";
        return;
    }

    ports.forEach(p => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${p.port}</td>
            <td>${p.protocol}</td>
            <td>${p.service}</td>
        `;
        tableBody.appendChild(row);
    });
}
