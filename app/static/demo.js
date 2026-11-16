"use strict";
const $ = (id) => document.getElementById(id);
let token = null;
let page = 1;
let pageCount = 1;
let generating = false;

async function api(path, options = {}) {
  const response = await fetch(path, {cache: "no-store", ...options});
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    let message = typeof body.detail === "string" ? body.detail : (body.error || `Request failed (${response.status}).`);
    if (Array.isArray(body.detail)) message = "Check your input: output tokens must be a positive whole number.";
    if (response.headers.get("retry-after")) message += ` Retry after ${response.headers.get("retry-after")} seconds.`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

function status(id, text, error = false) {
  $(id).textContent = text;
  $(id).classList.toggle("error", error);
}

function authView(username = "") {
  $("login-form").hidden = Boolean(token);
  $("signed-in").hidden = !token;
  $("account-name").textContent = username;
  $("chat-button").disabled = !token || generating;
  $("password").value = "";
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-button").disabled = true;
  status("auth-status", "Signing in…");
  try {
    const username = $("username").value;
    const result = await api("/login", {method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify({username, password: $("password").value})});
    token = result.token;
    authView(username);
    status("auth-status", "Signed in. Your chat session is ready.");
    status("chat-status", "Ready for a prompt.");
  } catch (error) {
    status("auth-status", error.message || "Could not reach the application.", true);
  } finally {
    $("login-button").disabled = false;
  }
});

$("logout-button").addEventListener("click", async () => {
  const previous = token;
  token = null;
  authView();
  status("chat-status", "Sign in to send a prompt.");
  try {
    await api("/logout", {method: "POST", headers: {authorization: `Bearer ${previous}`}});
    status("auth-status", "Signed out. Server session revoked.");
  } catch (_) {
    status("auth-status", "Local session cleared. Server revocation failed; the server session will expire normally.", true);
  }
});

$("chat-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!token || generating) return;
  generating = true;
  $("chat-button").disabled = true;
  $("logout-button").disabled = true;
  $("response-state").textContent = "GENERATING";
  $("chat-output").textContent = "Waiting for a response…";
  ["tokens-in", "tokens-out", "chat-cost"].forEach((id) => { $(id).textContent = "—"; });
  status("chat-status", "Calling the local mock LLM…");
  const start = performance.now();
  try {
    const result = await api("/chat", {method: "POST", headers: {"content-type": "application/json", authorization: `Bearer ${token}`}, body: JSON.stringify({prompt: $("prompt").value, max_output_tokens: Number($("max-output").value)})});
    $("chat-output").textContent = result.text.slice(0, 8000) + (result.text.length > 8000 ? "\n[Display truncated; usage reflects the full response.]" : "");
    $("tokens-in").textContent = result.usage.tokens_in.toLocaleString();
    $("tokens-out").textContent = result.usage.tokens_out.toLocaleString();
    $("chat-cost").textContent = `$${result.usage.cost_usd.toFixed(6)}`;
    $("response-state").textContent = "COMPLETE";
    status("chat-status", `Response received in ${((performance.now() - start) / 1000).toFixed(2)}s · Cost is simulated.`);
  } catch (error) {
    $("response-state").textContent = "REQUEST FAILED";
    $("chat-output").textContent = "No successful response for this request. A timeout can leave usage uncertain.";
    status("chat-status", error.message || "Could not reach the application.", true);
    if (error.status === 401) {
      token = null;
      authView();
      status("auth-status", "Session expired. Please sign in again.", true);
    }
  } finally {
    generating = false;
    $("chat-button").disabled = !token;
    $("logout-button").disabled = false;
  }
});

async function loadProducts(target) {
  $("previous-page").disabled = true;
  $("next-page").disabled = true;
  status("products-status", "Loading products…");
  try {
    const data = await api(`/products?page=${target}&per_page=5`);
    page = target;
    pageCount = Math.ceil(data.total / 5);
    $("products-body").replaceChildren();
    data.items.forEach((item) => {
      const row = document.createElement("tr");
      [item.name, `P20-${String(item.id).padStart(4, "0")}`, `$${Number(item.price).toFixed(2)}`, "In catalogue"].forEach((value, index) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        if (index === 3) cell.className = "available";
        row.append(cell);
      });
      $("products-body").append(row);
    });
    $("catalogue-total").textContent = `${data.total.toLocaleString()} synthetic products`;
    status("products-status", `Page ${page.toLocaleString()} of ${pageCount.toLocaleString()}`);
  } catch (error) {
    status("products-status", error.message || "Catalogue unavailable. Try again.", true);
    $("retry-products").hidden = false;
  } finally {
    $("previous-page").disabled = page <= 1;
    $("next-page").disabled = page >= pageCount;
  }
}
$("previous-page").addEventListener("click", () => loadProducts(page - 1));
$("next-page").addEventListener("click", () => loadProducts(page + 1));
$("retry-products").addEventListener("click", () => { $("retry-products").hidden = true; loadProducts(page); });

async function health() {
  try {
    const data = await api("/health");
    const mode = data.waf_mode;
    $("mode-notice").textContent = mode === "off"
      ? "C0 · Intentionally vulnerable baseline. Protection is off. All LLM output and costs are simulated."
      : `WAF mode: ${mode}. Joint attack/kernel checks are pending. All LLM output and costs are simulated.`;
  } catch (_) {
    $("mode-notice").textContent = "Application dependencies are unavailable. Login or chat may fail. Cost is always simulated.";
    $("mode-notice").classList.add("warning");
  }
}
authView();
health();
loadProducts(1);
