document.addEventListener("DOMContentLoaded", function () {
    
    const select = document.getElementById("jsonFiles");

    function fetchFiles() {
        fetch(`/get_files?ts=${Date.now()}`)  // Prevent caching
            .then(response => response.json())
            .then(files => {
                const storedSelection = sessionStorage.getItem("selectedFile") || select.value;
                const latestFile = files[files.length - 1];

                // Get existing options
                const existingOptions = Array.from(select.options).map(option => option.value);
                const needsUpdate = files.length !== existingOptions.length || !files.every(file => existingOptions.includes(file));

                // Only update if needed (avoid overriding manual selection)
                if (needsUpdate) {
                    select.innerHTML = ""; // Clear dropdown
                    files.forEach(file => {
                        const option = document.createElement("option");
                        option.value = file;
                        option.textContent = file;
                        select.appendChild(option);
                    });

                    // Restore previous selection or set latest file
                    if (files.includes(storedSelection)) {
                        select.value = storedSelection;
                    } else {
                        select.value = latestFile;
                        sessionStorage.setItem("selectedFile", latestFile);
                    }
                }
            })
            .catch(error => console.error("Error fetching files:", error));
    }

    // Store selection before form submission
    select.addEventListener("change", function () {
        sessionStorage.setItem("selectedFile", this.value);
        setTimeout(() => {
            select.value = this.value;  // Ensure correct UI update
        }, 50);
        this.form.submit();
    });


    fetchFiles();
    
    setInterval(fetchFiles, 5000); // Auto-refresh file list every 3 seconds
  
    // Screenshot Pagination
    let screenEntries = document.querySelectorAll(".creen-entry"); // Assuming "creen" is intentional
    let screenIndex = 0;

    function showScreen(index) {
        screenEntries.forEach((entry, i) => {
            entry.style.display = i === index ? "block" : "none";
        });
    }

    function prevScreen() {
        if (screenEntries.length === 0) return;
        screenIndex = (screenIndex - 1 + screenEntries.length) % screenEntries.length;
        showScreen(screenIndex);
    }

    function nextScreen() {
        if (screenEntries.length === 0) return;
        screenIndex = (screenIndex + 1) % screenEntries.length;
        showScreen(screenIndex);
    }

    if (screenEntries.length > 0) showScreen(screenIndex);

    // Threat Intelligence Pagination
    let threatEntries = document.querySelectorAll(".threat-intel-entry");
    let threatIndex = 0;

    function showThreat(index) {
        threatEntries.forEach((entry, i) => {
            entry.style.display = i === index ? "block" : "none";
        });
    }

    function prevThreat() {
        if (threatEntries.length === 0) return;
        threatIndex = (threatIndex - 1 + threatEntries.length) % threatEntries.length;
        showThreat(threatIndex);
    }

    function nextThreat() {
        if (threatEntries.length === 0) return;
        threatIndex = (threatIndex + 1) % threatEntries.length;
        showThreat(threatIndex);
    }

    if (threatEntries.length > 0) showThreat(threatIndex);

    // Attach event listeners dynamically
    document.querySelectorAll(".pagination").forEach((pagination, index) => {
        let buttons = pagination.querySelectorAll("button");
        if (buttons.length === 2) {
            if (index === 0) {
                buttons[0].addEventListener("click", prevScreen);
                buttons[1].addEventListener("click", nextScreen);
            } else if (index === 1) {
                buttons[0].addEventListener("click", prevThreat);
                buttons[1].addEventListener("click", nextThreat);
            }
        }
    });

    // Charts Initialization
    window.onload = function () {

        let normalScore = parseFloat(document.getElementById("phishingScore").dataset.score);
        let advancedScore = parseFloat(document.getElementById("bertScore").dataset.score);
    
         
        new Chart(document.getElementById("normalChart"), {
            type: 'bar',
            data: { labels: ["Basic Analysis"], datasets: [{ label: "Score", data: [normalScore], backgroundColor: "blue" }] },
        });

        new Chart(document.getElementById("advancedChart"), {
            type: 'bar',
            data: { labels: ["Advanced Analysis"], datasets: [{ label: "Score", data: [advancedScore], backgroundColor: "red" }] },
        });
    };
});
