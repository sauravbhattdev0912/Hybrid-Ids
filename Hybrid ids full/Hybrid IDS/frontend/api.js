// api.js
// Simple frontend API helper.
// First it tries backend. If backend is not running, it uses mock-data JSON.

const BASE_URL = "http://localhost:5000";
const MOCK_BASE = "./mock-data";

async function getData(endpoint, mockFile) {
  try {
    const response = await fetch(`${BASE_URL}${endpoint}`);
    if (response.ok) return await response.json();
  } catch (error) {
    console.warn("Backend not reachable. Using mock data.");
  }

  const fallback = await fetch(`${MOCK_BASE}/${mockFile}`);
  return await fallback.json();
}

export function fetchStats() {
  return getData("/api/stats", "stats.json");
}

export function fetchAlerts() {
  return getData("/api/alerts", "alerts.json");
}

export function fetchLogs() {
  return getData("/api/logs", "logs.json");
}

export function fetchTraffic() {
  return getData("/api/traffic", "traffic.json");
}

export async function analyzePacket(packet) {
  const response = await fetch(`${BASE_URL}/api/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(packet),
  });
  return await response.json();
}

export async function controlSimulation(action) {
  const response = await fetch(`${BASE_URL}/api/simulate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, rate_hz: 2, attack_prob: 0.15 }),
  });
  return await response.json();
}

export async function trainModel() {
  const response = await fetch(`${BASE_URL}/api/train`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ n_benign: 800, n_attack_each: 120, n_neighbors: 7 }),
  });
  return await response.json();
}
