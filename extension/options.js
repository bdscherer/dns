const DEFAULTS = { serverUrl: "", extensionKey: "", enabled: true };
const $ = (id) => document.getElementById(id);

function setStatus(text, ok) {
  const el = $("status");
  el.textContent = text;
  el.className = ok ? "ok" : "err";
}

async function load() {
  const cfg = await chrome.storage.local.get(DEFAULTS);
  $("serverUrl").value = cfg.serverUrl || "";
  $("extensionKey").value = cfg.extensionKey || "";
  $("enabled").checked = cfg.enabled !== false;
}

async function save() {
  await chrome.storage.local.set({
    serverUrl: $("serverUrl").value.trim(),
    extensionKey: $("extensionKey").value.trim(),
    enabled: $("enabled").checked
  });
  setStatus("Saved.", true);
}

async function test() {
  const url = $("serverUrl").value.trim().replace(/\/$/, "");
  if (!url) { setStatus("Enter a server URL first.", false); return; }
  try {
    const resp = await fetch(url + "/api/extension/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Extension-Key": $("extensionKey").value.trim()
      },
      body: JSON.stringify({ events: [] })
    });
    if (resp.ok) setStatus("Connected — server accepted the key.", true);
    else if (resp.status === 401) setStatus("Wrong extension key.", false);
    else if (resp.status === 403) setStatus("Extension reporting is disabled on the server.", false);
    else setStatus("Server responded " + resp.status, false);
  } catch (e) {
    setStatus("Could not reach the server.", false);
  }
}

$("save").addEventListener("click", save);
$("test").addEventListener("click", test);
document.addEventListener("DOMContentLoaded", load);
