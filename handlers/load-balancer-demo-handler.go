package handlers

import "net/http"

const loadBalancerDemoHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auth Service Load Test</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f5f5f5;
      --panel: #ffffff;
      --text: #181818;
      --muted: #626262;
      --line: #d8d8d8;
      --green: #157f3b;
      --teal: #007c89;
      --red: #b42318;
      --yellow: #f2c94c;
    }

    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 16px;
      letter-spacing: 0;
    }

    main {
      min-height: 100vh;
      display: grid;
      grid-template-columns: minmax(0, 1fr) 360px;
      gap: 24px;
      padding: 32px;
    }

    .stage {
      display: grid;
      align-content: center;
      gap: 24px;
      min-width: 0;
    }

    .eyebrow {
      margin: 0 0 8px;
      color: var(--teal);
      font-size: 0.9rem;
      font-weight: 700;
      text-transform: uppercase;
    }

    h1 {
      margin: 0;
      max-width: 760px;
      font-size: 2.75rem;
      line-height: 1.05;
    }

    .copy {
      margin: 0;
      max-width: 640px;
      color: var(--muted);
      line-height: 1.6;
    }

    .current {
      width: min(100%, 680px);
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 24px;
    }

    .letter {
      width: 116px;
      height: 116px;
      display: grid;
      place-items: center;
      border: 8px solid var(--yellow);
      border-radius: 8px;
      background: #fffdf2;
      color: var(--text);
      font-size: 4rem;
      font-weight: 800;
      line-height: 1;
    }

    .current-grid {
      display: grid;
      grid-template-columns: 116px minmax(0, 1fr);
      gap: 20px;
      align-items: center;
    }

    .meta {
      display: grid;
      gap: 8px;
      min-width: 0;
    }

    .label {
      color: var(--muted);
      font-size: 0.85rem;
      text-transform: uppercase;
    }

    .value {
      overflow-wrap: anywhere;
      font-family: "Courier New", Courier, monospace;
      font-size: 1rem;
    }

    .controls {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }

    button {
      border: 1px solid var(--text);
      border-radius: 8px;
      background: var(--text);
      color: #ffffff;
      min-height: 44px;
      padding: 0 16px;
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }

    button.secondary {
      background: #ffffff;
      color: var(--text);
    }

    button.danger {
      border-color: var(--red);
      background: var(--red);
    }

    aside {
      border-left: 1px solid var(--line);
      padding-left: 24px;
      min-width: 0;
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }

    .stat {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 16px;
    }

    .stat strong {
      display: block;
      color: var(--green);
      font-size: 2rem;
      line-height: 1;
    }

    .history {
      display: grid;
      gap: 10px;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .history li {
      border: 1px solid var(--line);
      border-radius: 8px;
      background: var(--panel);
      padding: 12px;
      overflow-wrap: anywhere;
    }

    .history strong {
      display: inline-grid;
      place-items: center;
      width: 28px;
      height: 28px;
      margin-right: 8px;
      border-radius: 6px;
      background: var(--teal);
      color: #ffffff;
    }

    .status {
      min-height: 24px;
      color: var(--muted);
    }

    @media (max-width: 840px) {
      main {
        grid-template-columns: minmax(0, 1fr);
        padding: 20px;
      }

      h1 {
        font-size: 2rem;
      }

      aside {
        border-left: 0;
        border-top: 1px solid var(--line);
        padding-left: 0;
        padding-top: 20px;
      }

      .current-grid {
        grid-template-columns: minmax(0, 1fr);
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="stage">
      <div>
        <p class="eyebrow">Auth service traffic</p>
        <h1>Call the service and watch the target task change.</h1>
      </div>
      <p class="copy">Start auto calls, then scale the ECS service past one healthy task. New task identities get labeled B, C, and onward as the load balancer sends traffic to them.</p>

      <section class="current" aria-live="polite">
        <div class="current-grid">
          <div class="letter" id="taskLetter">?</div>
          <div class="meta">
            <div>
              <div class="label">Current label</div>
              <div class="value" id="currentLabel">Waiting for first call</div>
            </div>
            <div>
              <div class="label">Instance id</div>
              <div class="value" id="instanceId">-</div>
            </div>
            <div>
              <div class="label">Task / host</div>
              <div class="value" id="taskMeta">-</div>
            </div>
          </div>
        </div>
      </section>

      <div class="controls">
        <button id="callNow" type="button">Call once</button>
        <button id="burst" type="button" class="secondary">Burst 20</button>
        <button id="auto" type="button" class="secondary">Start auto calls</button>
        <button id="reset" type="button" class="danger">Reset labels</button>
      </div>
      <div class="status" id="status">Ready.</div>
    </section>

    <aside>
      <div class="stats">
        <div class="stat">
          <span class="label">Calls</span>
          <strong id="callCount">0</strong>
        </div>
        <div class="stat">
          <span class="label">Tasks seen</span>
          <strong id="taskCount">0</strong>
        </div>
      </div>
      <p class="label">Recent calls</p>
      <ul class="history" id="history"></ul>
    </aside>
  </main>

  <script>
    const endpoint = "/api/v1/debug/instance";
    const labelsKey = "authServiceLoadBalancerDemo.labels";
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".split("");
    const state = {
      calls: 0,
      timer: null,
      labels: loadLabels(),
      history: []
    };

    const taskLetter = document.getElementById("taskLetter");
    const currentLabel = document.getElementById("currentLabel");
    const instanceId = document.getElementById("instanceId");
    const taskMeta = document.getElementById("taskMeta");
    const callCount = document.getElementById("callCount");
    const taskCount = document.getElementById("taskCount");
    const history = document.getElementById("history");
    const status = document.getElementById("status");
    const auto = document.getElementById("auto");

    document.getElementById("callNow").addEventListener("click", callInstance);
    document.getElementById("burst").addEventListener("click", burstCalls);
    auto.addEventListener("click", toggleAuto);
    document.getElementById("reset").addEventListener("click", resetLabels);

    callInstance();

    function loadLabels() {
      try {
        return JSON.parse(localStorage.getItem(labelsKey)) || {};
      } catch {
        return {};
      }
    }

    function saveLabels() {
      localStorage.setItem(labelsKey, JSON.stringify(state.labels));
    }

    function labelFor(id) {
      if (!state.labels[id]) {
        const used = Object.keys(state.labels).length;
        state.labels[id] = alphabet[used] || "#" + (used + 1);
        saveLabels();
      }
      return state.labels[id];
    }

    async function callInstance() {
      state.calls += 1;
      callCount.textContent = String(state.calls);
      status.textContent = "Calling " + endpoint + " ...";

      try {
        const response = await fetch(endpoint + "?t=" + Date.now() + "-" + state.calls, {
          cache: "no-store",
          headers: { "Accept": "application/json" }
        });
        if (!response.ok) {
          throw new Error("HTTP " + response.status);
        }
        const data = await response.json();
        render(data);
      } catch (error) {
        status.textContent = "Call failed: " + error.message;
      }
    }

    function render(data) {
      const id = data.instance_id || data.hostname || "unknown";
      const label = labelFor(id);
      const meta = [
        data.task_id ? "task " + data.task_id : "",
        data.hostname ? "host " + data.hostname : "",
        data.availability_zone || "",
        data.launch_type || ""
      ].filter(Boolean).join(" | ");

      taskLetter.textContent = label;
      currentLabel.textContent = "Target " + label + " from " + data.source;
      instanceId.textContent = data.display_id || id;
      taskMeta.textContent = meta || "-";
      taskCount.textContent = String(Object.keys(state.labels).length);
      status.textContent = "Last call at " + new Date().toLocaleTimeString();

      state.history.unshift({ label, id: data.display_id || id, source: data.source });
      state.history = state.history.slice(0, 12);
      history.innerHTML = state.history.map(item =>
        "<li><strong>" + escapeHTML(item.label) + "</strong>" +
        escapeHTML(item.id) + " <span class=\"label\">" +
        escapeHTML(item.source) + "</span></li>"
      ).join("");
    }

    function toggleAuto() {
      if (state.timer) {
        clearInterval(state.timer);
        state.timer = null;
        auto.textContent = "Start auto calls";
        auto.className = "secondary";
        status.textContent = "Auto calls stopped.";
        return;
      }

      state.timer = setInterval(callInstance, 700);
      auto.textContent = "Stop auto calls";
      auto.className = "";
      callInstance();
    }

    async function burstCalls() {
      status.textContent = "Sending a burst of 20 calls ...";
      await Promise.allSettled(Array.from({ length: 20 }, () => callInstance()));
      status.textContent = "Burst complete.";
    }

    function resetLabels() {
      state.labels = {};
      state.history = [];
      localStorage.removeItem(labelsKey);
      taskLetter.textContent = "?";
      currentLabel.textContent = "Waiting for first call";
      instanceId.textContent = "-";
      taskMeta.textContent = "-";
      taskCount.textContent = "0";
      history.innerHTML = "";
      status.textContent = "Labels reset.";
    }

    function escapeHTML(value) {
      return String(value).replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#039;"
      }[char]));
    }
  </script>
</body>
</html>`

func LoadBalancerDemoHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(loadBalancerDemoHTML))
}
