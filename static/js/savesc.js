document.addEventListener("DOMContentLoaded", function () {
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
