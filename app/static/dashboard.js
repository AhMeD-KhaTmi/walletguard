"use strict";
const $ = (id) => document.getElementById(id);
let loading = false;
let timer = null;

function chip(id, state) {
  $(id).textContent = state === "ok" ? "Connected" : "Unavailable";
  $(id).classList.toggle("good", state === "ok");
  $(id).classList.toggle("pending", state !== "ok");
}
function cell(row, text) {
  const element = document.createElement("td");
  element.textContent = text;
  row.append(element);
}
function unavailable() {
  ["usage-requests", "usage-input", "usage-output", "usage-cost"].forEach((id) => { $(id).textContent = "—"; });
  chip("redis-status", "unavailable");
  chip("mock-status", "unavailable");
  $("waf-detail").textContent = "Snapshot unavailable";
  $("waf-status").textContent = "Unverified";
  $("decision-table").hidden = true;
  $("decision-empty").hidden = false;
  $("bans-list").replaceChildren();
  $("ban-empty").hidden = false;
  $("ban-empty").querySelector("h3").textContent = "Ban state unavailable";
}

async function refresh() {
  if (loading) return;
  loading = true;
  $("refresh-button").disabled = true;
  try {
    const response = await fetch("/dashboard/data", {cache: "no-store"});
    if (!response.ok) throw new Error(response.status === 403 ? "Management access denied. Use an allowed connection IP." : "Could not load the snapshot.");
    const data = await response.json();
    chip("redis-status", data.dependencies.redis);
    chip("mock-status", data.dependencies.mock_llm);
    $("dashboard-notice").textContent = data.mode === "off"
      ? "C0 · Intentionally vulnerable baseline. Usage is live; verified defenses and Person A’s components are not connected."
      : `WAF mode: ${data.mode}. Application checks are implemented; joint attack and kernel validation are pending.`;
    $("dashboard-notice").classList.toggle("warning", Object.values(data.dependencies).some((v) => v !== "ok"));
    if (Object.values(data.dependencies).some((v) => v !== "ok")) {
      $("dashboard-notice").textContent = "A dependency is unavailable. This snapshot may be partial; unavailable readings are shown as —. Integration remains disconnected.";
    }
    $("waf-detail").textContent = `Configured mode: ${data.mode}`;
    $("waf-status").textContent = data.mode === "off" ? "Off / baseline" : data.mode === "observe" ? "Observe / no blocking" : "Enforcing / app layer";
    $("snapshot-time").textContent = `Snapshot ${new Date(data.updated_ms).toLocaleTimeString()} · ${$("auto-refresh").checked ? "Auto-refresh on" : "Manual refresh"}`;
    $("usage-requests").textContent = data.usage ? data.usage.requests.toLocaleString() : "—";
    $("usage-input").textContent = data.usage ? data.usage.tokens_in.toLocaleString() : "—";
    $("usage-output").textContent = data.usage ? data.usage.tokens_out.toLocaleString() : "—";
    $("usage-cost").textContent = data.usage ? `$${data.usage.cost_usd.toFixed(6)}` : "—";
    $("decision-table").hidden = !data.decisions?.length;
    $("decision-empty").hidden = Boolean(data.decisions?.length);
    $("decisions-body").replaceChildren();
    (data.decisions || []).forEach((entry) => {
      const row = document.createElement("tr");
      cell(row, `${entry.ip} · ${entry.route}`);
      cell(row, entry.decision);
      cell(row, `${entry.reason || "—"} / ${entry.anomaly_score || "—"}`);
      $("decisions-body").append(row);
    });
    $("bans-list").replaceChildren();
    $("ban-empty").hidden = Boolean(data.bans?.length);
    $("ban-empty").querySelector("h3").textContent = data.bans === null ? "Ban state unavailable" : "No active application bans";
    (data.bans || []).forEach((ban) => {
      const item = document.createElement("li");
      const identity = document.createElement("div");
      const ip = document.createElement("strong");
      const reason = document.createElement("small");
      const ttl = document.createElement("span");
      ip.textContent = ban.ip;
      reason.textContent = ban.reason;
      ttl.textContent = `${ban.ttl_s}s left`;
      identity.append(ip, reason);
      item.append(identity, ttl);
      $("bans-list").append(item);
    });
    $("ban-limit").textContent = data.bans_truncated ? "Limited snapshot: first 200 matching ban keys scanned." : data.telemetry_note;
  } catch (error) {
    unavailable();
    $("dashboard-notice").textContent = error.message || "Snapshot unavailable. Try refreshing.";
    $("dashboard-notice").classList.add("warning");
    $("snapshot-time").textContent = "Latest refresh failed; data is unavailable";
  } finally {
    loading = false;
    $("refresh-button").disabled = false;
  }
}
function schedule() {
  clearInterval(timer);
  timer = null;
  if ($("auto-refresh").checked && !document.hidden) timer = setInterval(refresh, 5000);
}
$("refresh-button").addEventListener("click", refresh);
$("auto-refresh").addEventListener("change", () => { schedule(); refresh(); });
document.addEventListener("visibilitychange", schedule);
window.addEventListener("pagehide", () => clearInterval(timer));
refresh();
