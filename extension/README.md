# FaithFilter Accountability browser extension

This optional extension gives your FaithFilter server the one thing DNS
filtering can't see on its own: **search terms and visited sites from inside
the browser**, including on HTTPS pages. It is the piece that lets FaithFilter
rival on-device accountability tools — *without their slowdown*.

## Why it doesn't slow the device

Products like Covenant Eyes route all traffic through an on-device VPN and
take periodic screenshots analysed on the phone/laptop — that's what drains
the battery and adds lag. This extension does none of that:

- No VPN tunnel, no traffic interception.
- No screenshots, no on-device machine learning.
- It only reads the destination hostname and, on search engines, the search
  term from the URL, then sends a tiny batched JSON message once a minute.

The trade-off is honest: it sees **search terms and which sites** were
visited, not the content of pages. Combined with the server's DNS-level
blocking, safe-search enforcement and bypass detection, that covers the large
majority of what an accountability partner needs.

## Install (Chrome / Edge / Brave)

1. On the FaithFilter server, enable extension reporting in `config.yaml`:
   ```yaml
   extension:
     enabled: true
     key: "pick-a-long-random-string"
   ```
   and restart the service.
2. In the browser go to `chrome://extensions`, turn on **Developer mode**,
   click **Load unpacked**, and select this `extension` folder.
3. Click the extension's icon, enter the **Server URL** (e.g.
   `http://192.168.1.53:5000`) and the **Extension key** from step 1, then
   **Save** and **Test connection**.

Firefox works the same way via `about:debugging` → **Load Temporary Add-on**
(Manifest V3 support required).

## Making it stick

For real accountability, install it on a browser profile the user can't
remove — a managed/enterprise profile, or via Chrome policy
(`ExtensionInstallForcelist`). Removal or disabling shows up on the server as
the device going quiet (a "dark device"), which is itself reported to the
accountability partner.

## Privacy

Events are sent only to the server URL you configure (your own FaithFilter
box), authenticated with your key. Nothing goes to any third party. The
server applies its retention policy to the search log just like every other
log.
