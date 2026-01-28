async function scanWebsite() {
    const domain = document.getElementById("domain").value;
    const resultBox = document.getElementById("result");

    if (!domain) {
        alert("Please enter a domain");
        return;
    }

    resultBox.textContent = "Scanning...";

    try {
        const response = await fetch(
            `http://127.0.0.1:8000/scan?domain=${domain}`
        );

        const data = await response.json();
        resultBox.textContent = JSON.stringify(data, null, 2);

    } catch (error) {
        resultBox.textContent = "Error connecting to backend";
    }
}
