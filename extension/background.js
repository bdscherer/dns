/*
 * FaithFilter Accountability — background service worker (Manifest V3)
 *
 * Zero device slowdown by design: no VPN tunnel, no screen capture, no
 * on-device analysis. It watches top-level navigations, extracts the search
 * term from known search engines, and batches events to the FaithFilter
 * server's /api/extension/events endpoint. Only the destination hostname and
 * search terms are sent — never page content.
 */

const DEFAULTS = { serverUrl: "", extensionKey: "", enabled: true };
const FLUSH_ALARM = "faithfilter-flush";
const MAX_BATCH = 50;

// Search engines whose query parameter we can read from the URL.
const SEARCH_ENGINES = [
  { host: "google.",        param: "q",     name: "google" },
  { host: "bing.com",       param: "q",     name: "bing" },
  { host: "duckduckgo.com", param: "q",     name: "duckduckgo" },
  { host: "search.yahoo.",  param: "p",     name: "yahoo" },
  { host: "youtube.com",    param: "search_query", name: "youtube" },
  { host: "reddit.com",     param: "q",     name: "reddit" },
  { host: "ecosia.org",     param: "q",     name: "ecosia" },
  { host: "startpage.com",  param: "query", name: "startpage" },
  { host: "brave.com",      param: "q",     name: "brave" }
];

let queue = [];

async function getConfig() {
  const stored = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...stored };
}

function classify(urlStr) {
  let url;
  try { url = new URL(urlStr); } catch (e) { return null; }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  const host = url.hostname.toLowerCase();

  for (const engine of SEARCH_ENGINES) {
    if (host.includes(engine.host)) {
      const term = url.searchParams.get(engine.param);
      if (term && term.trim()) {
        return { engine: engine.name, query: term.trim(), url: "" };
      }
    }
  }
  // Not a search — record the visited hostname only (no path, no content).
  return { engine: "", query: "", url: host };
}

async function onNavigation(details) {
  // frameId 0 = top-level page only; ignore sub-frames and prerenders.
  if (details.frameId !== 0) return;
  const cfg = await getConfig();
  if (!cfg.enabled || !cfg.serverUrl) return;
  const event = classify(details.url);
  if (!event) return;
  event.ts = Date.now();
  queue.push(event);
  if (queue.length >= MAX_BATCH) flush();
}

async function flush() {
  const cfg = await getConfig();
  if (!cfg.enabled || !cfg.serverUrl || queue.length === 0) return;
  const batch = queue.splice(0, MAX_BATCH);
  try {
    const resp = await fetch(cfg.serverUrl.replace(/\/$/, "") +
                             "/api/extension/events", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Extension-Key": cfg.extensionKey || ""
      },
      body: JSON.stringify({ events: batch })
    });
    if (!resp.ok) {
      // Put them back to retry on the next flush (bounded).
      queue = batch.concat(queue).slice(0, 500);
    }
  } catch (e) {
    queue = batch.concat(queue).slice(0, 500);
  }
}

chrome.webNavigation.onCommitted.addListener(onNavigation);
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(FLUSH_ALARM, { periodInMinutes: 1 });
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(FLUSH_ALARM, { periodInMinutes: 1 });
});
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === FLUSH_ALARM) flush();
});
