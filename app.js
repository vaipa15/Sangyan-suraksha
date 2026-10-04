const messageEl =
    document.getElementById("message");

const languageEl =
    document.getElementById("language");

const analyzeBtn =
    document.getElementById("analyzeBtn");

const clearBtn =
    document.getElementById("clearBtn");

const voiceBtn =
    document.getElementById("voiceBtn");

const resultEl =
    document.getElementById("result");

const riskLevelEl =
    document.getElementById("riskLevel");

const riskScoreEl =
    document.getElementById("riskScore");

const summaryEl =
    document.getElementById("summary");

const findingsEl =
    document.getElementById("findings");

const safeActionsEl =
    document.getElementById("safeActions");

const urlsBoxEl =
    document.getElementById("urlsBox");

const urlsEl =
    document.getElementById("urls");

const historyEl =
    document.getElementById("history");

const refreshHistoryBtn =
    document.getElementById("refreshHistory");


async function analyze() {

    const text =
        messageEl.value.trim();

    if (!text) {

        alert(
            "Please enter a message to analyse."
        );

        return;
    }

    analyzeBtn.disabled = true;

    analyzeBtn.textContent =
        "Analysing...";

    try {

        const response =
            await fetch("/api/analyze", {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({
                    text,
                    language:
                        languageEl.value
                })
            });

        const data =
            await response.json();

        if (!response.ok) {

            throw new Error(
                data.detail ||
                "Analysis failed."
            );
        }

        renderResult(data);

        loadHistory();

    } catch (error) {

        alert(error.message);

    } finally {

        analyzeBtn.disabled = false;

        analyzeBtn.textContent =
            "Analyse Risk";
    }
}


function renderResult(data) {

    resultEl.classList.remove(
        "hidden"
    );

    riskLevelEl.textContent =
        data.risk_level;

    riskScoreEl.textContent =
        data.risk_score;

    summaryEl.textContent =
        data.summary;

    findingsEl.innerHTML = "";

    if (data.findings.length === 0) {

        findingsEl.innerHTML =
            "<p>No specific red flags were detected.</p>";

    } else {

        data.findings.forEach(
            finding => {

                const div =
                    document.createElement(
                        "div"
                    );

                div.className =
                    "finding";

                div.innerHTML = `
                    <strong>
                        ${escapeHtml(finding.rule)}
                        — ${escapeHtml(finding.severity)}
                    </strong>

                    <div>
                        ${escapeHtml(finding.explanation)}
                    </div>

                    <div class="evidence">
                        Evidence:
                        ${escapeHtml(finding.evidence)}
                    </div>
                `;

                findingsEl.appendChild(div);
            }
        );
    }


    safeActionsEl.innerHTML = "";

    data.safe_actions.forEach(
        action => {

            const li =
                document.createElement("li");

            li.textContent =
                action;

            safeActionsEl.appendChild(li);
        }
    );


    urlsEl.innerHTML = "";

    if (data.urls.length) {

        urlsBoxEl.classList.remove(
            "hidden"
        );

        data.urls.forEach(
            url => {

                const li =
                    document.createElement("li");

                const a =
                    document.createElement("a");

                a.href = url;

                a.target = "_blank";

                a.rel = "noopener noreferrer";

                a.textContent = url;

                li.appendChild(a);

                urlsEl.appendChild(li);
            }
        );

    } else {

        urlsBoxEl.classList.add(
            "hidden"
        );
    }


    resultEl.scrollIntoView({
        behavior: "smooth"
    });
}


function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


async function loadHistory() {

    try {

        const response =
            await fetch(
                "/api/history?limit=10"
            );

        const data =
            await response.json();

        historyEl.innerHTML = "";

        if (!data.length) {

            historyEl.innerHTML =
                "<p>No checks yet.</p>";

            return;
        }


        data.forEach(item => {

            const div =
                document.createElement(
                    "div"
                );

            div.className =
                "history-item";

            const date =
                new Date(
                    item.created_at
                );

            div.innerHTML = `
                <div class="history-meta">
                    <span>
                        ${date.toLocaleString()}
                    </span>

                    <strong>
                        ${escapeHtml(item.risk_level)}
                        (${item.risk_score}/100)
                    </strong>
                </div>

                <div class="history-text">
                    ${escapeHtml(item.text)}
                </div>
            `;

            historyEl.appendChild(div);

        });

    } catch (error) {

        historyEl.innerHTML =
            "<p>Could not load history.</p>";
    }
}


clearBtn.addEventListener(
    "click",
    () => {

        messageEl.value = "";

        resultEl.classList.add(
            "hidden"
        );
    }
);


analyzeBtn.addEventListener(
    "click",
    analyze
);


refreshHistoryBtn.addEventListener(
    "click",
    loadHistory
);


let recognition = null;

if (
    "webkitSpeechRecognition"
    in window
    ||
    "SpeechRecognition"
    in window
) {

    const SpeechRecognition =
        window.SpeechRecognition ||
        window.webkitSpeechRecognition;

    recognition =
        new SpeechRecognition();

    recognition.continuous = false;

    recognition.interimResults = false;

    recognition.onstart = () => {

        voiceBtn.textContent =
            "🎙️ Listening...";
    };


    recognition.onresult =
        event => {

            const transcript =
                event.results[0][0]
                    .transcript;

            messageEl.value =
                transcript;
        };


    recognition.onerror =
        () => {

            alert(
                "Voice input could not be completed."
            );
        };


    recognition.onend = () => {

        voiceBtn.textContent =
            "🎙️ Speak";
    };

} else {

    voiceBtn.disabled = true;

    voiceBtn.title =
        "Speech recognition is not supported by this browser.";
}


voiceBtn.addEventListener(
    "click",
    () => {

        if (!recognition) {
            return;
        }

        recognition.lang =
            languageEl.value === "hi"
                ? "hi-IN"
                : "en-IN";

        recognition.start();
    }
);


loadHistory();
