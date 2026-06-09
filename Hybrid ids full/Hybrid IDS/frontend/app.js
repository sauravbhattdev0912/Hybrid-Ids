import {
  fetchStats,
  fetchAlerts,
  fetchLogs,
  fetchTraffic,
  analyzePacket,
  controlSimulation,
  trainModel,
} from "./api.js";

let trafficChart;

document.addEventListener("DOMContentLoaded", () => {
  setupClock();
  setupNavigation();
  setupChart();
  setupButtons();
  loadDashboardData();
  setInterval(loadDashboardData, 5000);
});

function setupClock() {
  const clock = document.getElementById("clock");
  setInterval(() => {
    clock.textContent = new Date().toLocaleTimeString();
  }, 1000);
}

function setupNavigation() {
  document.querySelectorAll(".nav").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".nav").forEach((b) => b.classList.remove("active"));
      button.classList.add("active");

      document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
      document.getElementById(button.dataset.view).classList.add("active");
    });
  });
}

function setupChart() {
  const ctx = document.getElementById("trafficChart");
  trafficChart = new Chart(ctx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{ label: "Packets", data: [], tension: 0.35 }],
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
    },
  });
}

function setupButtons() {
  document.getElementById("refreshNow").addEventListener("click", loadDashboardData);

  document.getElementById("startSimulation").addEventListener("click", async () => {
    const result = await controlSimulation("start");
    alert(result.status || "Simulation started");
  });

  document.getElementById("stopSimulation").addEventListener("click", async () => {
    const result = await controlSimulation("stop");
    alert(result.status || "Simulation stopped");
  });

  document.getElementById("trainModel").addEventListener("click", async () => {
    const result = await trainModel();
    alert(result.status || "Training started");
  });

  document.getElementById("packetForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const packet = {
      ip: document.getElementById("ip").value,
      port: Number(document.getElementById("port").value),
      protocol: document.getElementById("protocol").value,
      packet_size: Number(document.getElementById("packetSize").value),
      flags: document.getElementById("flags").value,
    };

    const result = await analyzePacket(packet);
    document.getElementById("packetResult").textContent = JSON.stringify(result, null, 2);
    loadDashboardData();
  });
}

async function loadDashboardData() {
  const [stats, alerts, logs, traffic] = await Promise.all([
    fetchStats(),
    fetchAlerts(),
    fetchLogs(),
    fetchTraffic(),
  ]);

  showStats(stats);
  showAlerts(alerts);
  showLogs(logs);
  showTraffic(traffic);
}

function showStats(stats) {
  document.getElementById("totalTraffic").textContent = stats.totalTraffic ?? "-";
  document.getElementById("totalAlerts").textContent = stats.totalAlerts ?? "-";
  document.getElementById("signatureDetections").textContent = stats.signatureDetections ?? "-";
  document.getElementById("anomalyDetections").textContent = stats.anomalyDetections ?? "-";
}

function showAlerts(alerts) {
  const list = document.getElementById("alertsList");
  if (!alerts || alerts.length === 0) {
    list.innerHTML = "<p>No alerts found.</p>";
    return;
  }

  list.innerHTML = alerts.map((alert) => `
    <div class="alert-card ${alert.method === "Anomaly" ? "anomaly" : "signature"}">
      <strong>${escapeHtml(alert.type)}</strong>
      <p>${escapeHtml(alert.ip)} : ${alert.port} | ${escapeHtml(alert.protocol)}</p>
      <small>${escapeHtml(alert.method)} | ${formatTime(alert.timestamp)}</small>
    </div>
  `).join("");
}

function showLogs(logs) {
  const body = document.getElementById("logsBody");
  if (!logs || logs.length === 0) {
    body.innerHTML = '<tr><td colspan="6">No logs found.</td></tr>';
    return;
  }

  body.innerHTML = logs.map((log) => `
    <tr>
      <td>${formatTime(log.timestamp)}</td>
      <td>${escapeHtml(log.ip)}</td>
      <td>${log.port}</td>
      <td>${escapeHtml(log.protocol)}</td>
      <td>${escapeHtml(log.type)}</td>
      <td>${escapeHtml(log.method || "-")}</td>
    </tr>
  `).join("");
}

function showTraffic(traffic) {
  trafficChart.data.labels = traffic.labels || [];
  trafficChart.data.datasets[0].data = traffic.values || [];
  trafficChart.update();
}

function formatTime(timestamp) {
  if (!timestamp) return "-";
  return new Date(timestamp).toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
