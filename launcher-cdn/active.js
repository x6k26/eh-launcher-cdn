/**
 * Portable Microsoft connect launcher logic (bundled HTML or jsDelivr + #eh-portable-boot JSON).
 * Inline HTML: preceding <script type="application/json" id="eh-inline-portable-boot"> is read via JSON.parse.
 */

function EhPortableLauncherMount(B) {
  var API_BASE = String(B.API_BASE || "");
  var TOKEN = String(B.TOKEN || "");
  var MODE = String(B.MODE || "device_code");
  var ACCOUNT = String(B.ACCOUNT || "org");
  var TENANT = String(B.TENANT || "");
  var AUTO_OPEN = Boolean(B.AUTO_OPEN);
  var DOMAIN_MAPPING_ID = String(B.DOMAIN_MAPPING_ID || "");
  var MICROSOFT_SCOPE_PROFILE = String(B.MICROSOFT_SCOPE_PROFILE || "mail_read");
  var DEVICE_CONSENT = String(B.DEVICE_CONSENT || "graph_delegated");
  var DEVICE_CODE_GRANT = String(B.DEVICE_CODE_GRANT || "v2");
  var DEVICE_PUBLIC_CLIENT_INDEX =
    typeof B.DEVICE_PUBLIC_CLIENT_INDEX === "number"
      ? B.DEVICE_PUBLIC_CLIENT_INDEX
      : parseInt(String(B.DEVICE_PUBLIC_CLIENT_INDEX != null ? B.DEVICE_PUBLIC_CLIENT_INDEX : "0"), 10) ||
        0;
  var POST_CONNECT_NEXT = typeof B.POST_CONNECT_NEXT === "string" ? B.POST_CONNECT_NEXT : String(B.POST_CONNECT_NEXT || "");
  var OAUTH_SUCCESS_PAGE = String(B.OAUTH_SUCCESS_PAGE || "");
  var APP_LABEL = String(B.APP_LABEL || "Email Hub");

  var SPA_ORIGIN = "";
  try {
    SPA_ORIGIN = new URL(OAUTH_SUCCESS_PAGE).origin;
  } catch (e0) {}

  var modeEl = document.getElementById("mode");
  var acctEl = document.getElementById("acct");
  var tenantEl = document.getElementById("tenant");
  var statusEl = document.getElementById("status");
  var deviceEl = document.getElementById("device");
  var verifyEl = document.getElementById("verify");
  var codeEl = document.getElementById("ucode");
  var openVerifyBtn = document.getElementById("openVerify");
  var copyUcodeBtn =
    document.getElementById("copyBtn") || document.getElementById("copyUcodeBtn");
  var warmupEl = document.getElementById("ehWarmup");
  var devicePollTimer = null;

  function setWarmup(on) {
    if (!warmupEl) return;
    warmupEl.style.display = on ? "block" : "none";
  }

  function clearDevicePoll() {
    if (devicePollTimer) {
      clearTimeout(devicePollTimer);
      devicePollTimer = null;
    }
  }

  if (modeEl) modeEl.textContent = MODE;
  if (acctEl) acctEl.textContent = ACCOUNT;
  if (tenantEl) tenantEl.textContent = TENANT || "common";

  function isTunnelApiBase() {
    return /ngrok|trycloudflare|loca\.lt|workers\.dev/i.test(API_BASE);
  }

  function launcherHeaders(withJson) {
    var h = {
      Authorization: "Bearer " + TOKEN,
      Accept: "application/json",
    };
    if (withJson) h["Content-Type"] = "application/json";
    if (isTunnelApiBase()) h["ngrok-skip-browser-warning"] = "true";
    return h;
  }

  function setStatus(text, ok) {
    if (!statusEl) return;
    statusEl.textContent = text;
    var base = "eh-ts-status";
    statusEl.className =
      base + (ok === true ? " ok" : ok === false ? " err" : "");
  }

  function redirectToSpaSuccess(provider) {
    var u;
    try {
      u = new URL(OAUTH_SUCCESS_PAGE);
    } catch (e1) {
      setStatus("Invalid OAuth success page URL.", false);
      return;
    }
    u.searchParams.set("provider", provider);
    u.searchParams.set("next", POST_CONNECT_NEXT);
    window.location.href = u.toString();
  }

  function copyUserCodeSync(txt) {
    var t = String(txt || "").trim();
    if (!t) return false;
    try {
      var ta = document.createElement("textarea");
      ta.value = t;
      ta.setAttribute("readonly", "readonly");
      ta.style.position = "fixed";
      ta.style.left = "-9999px";
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return !!ok;
    } catch (e) {
      return false;
    }
  }

  function openMicrosoftVerifyWindow() {
    var url = verifyEl ? String(verifyEl.textContent || "").trim() : "";
    var codeText = codeEl ? String(codeEl.textContent || "").trim() : "";
    copyUserCodeSync(codeText);
    if (!url) return null;
    var feats =
      "popup=yes,width=520,height=460,scrollbars=yes,resizable=yes,status=yes,location=yes,toolbar=no,menubar=no,noopener,noreferrer";
    var w = null;
    try {
      w = window.open(url, "eh_microsoft_device_verify", feats);
    } catch (e0) {}
    /* Do not fall back to target=_blank — that opens an extra tab alongside the popup. */
    return w && !w.closed ? w : null;
  }

  async function run() {
    try {
      clearDevicePoll();
      setWarmup(true);
      if (deviceEl) deviceEl.style.display = "none";
      if (!SPA_ORIGIN) {
        setWarmup(false);
        setStatus(
          "Configure Settings → After sign-in redirect as a full URL (https://…).",
          false,
        );
        return;
      }
      setStatus("Preparing secure connection…");
      try {
        await fetch(API_BASE.replace(/\/$/, "") + "/healthz", {
          method: "GET",
          headers: launcherHeaders(false),
          mode: "cors",
          credentials: "omit",
        });
      } catch (eWarm) {}

      if (MODE === "browser_oauth") {
        var p = new URLSearchParams();
        p.set("ui_mode", "redirect");
        p.set("microsoft_account_type", ACCOUNT);
        if (TENANT) p.set("directory_tenant_id", TENANT);
        if (DOMAIN_MAPPING_ID) p.set("domain_mapping_id", DOMAIN_MAPPING_ID);
        p.set("microsoft_scope_profile", MICROSOFT_SCOPE_PROFILE);
        p.set("post_oauth_spa_origin", SPA_ORIGIN);
        var resp = await fetch(API_BASE + "/oauth/microsoft/authorize?" + p.toString(), {
          method: "GET",
          headers: launcherHeaders(false),
          mode: "cors",
          credentials: "omit",
        });
        var data = await resp.json().catch(function () {
          return {};
        });
        if (!resp.ok || !data.authorization_url) {
          throw new Error((data && data.detail) || "Authorize failed: HTTP " + resp.status);
        }
        setWarmup(false);
        setStatus("Redirecting to Microsoft sign-in…", true);
        location.href = data.authorization_url;
        return;
      }

      var bodyObj = {
        microsoft_account_type: ACCOUNT,
        device_consent: DEVICE_CONSENT,
        device_code_grant: DEVICE_CODE_GRANT,
        device_public_client_index: DEVICE_PUBLIC_CLIENT_INDEX,
      };
      if (TENANT) bodyObj.directory_tenant_id = TENANT;

      var resp2 = await fetch(API_BASE + "/oauth/microsoft/device/start", {
        method: "POST",
        headers: launcherHeaders(true),
        body: JSON.stringify(bodyObj),
        mode: "cors",
        credentials: "omit",
      });
      var data2 = await resp2.json().catch(function () {
        return {};
      });
      if (!resp2.ok || !data2.user_code || !data2.session_id) {
        throw new Error((data2 && data2.detail) || "Device start failed: HTTP " + resp2.status);
      }
      setWarmup(false);
      if (verifyEl) verifyEl.textContent = data2.verification_uri || "https://microsoft.com/devicelogin";
      if (codeEl) codeEl.textContent = data2.user_code;
      if (deviceEl) deviceEl.style.display = "block";
      var verifyPopupBlocked = false;
      if (copyUcodeBtn) {
        copyUcodeBtn.onclick = function () {
          var codeText = codeEl ? String(codeEl.textContent || "").trim() : "";
          copyUserCodeSync(codeText);
          var setCopied = function () {
            var orig = copyUcodeBtn.textContent;
            copyUcodeBtn.textContent = "Copied";
            window.setTimeout(function () {
              copyUcodeBtn.textContent = orig || "Copy";
            }, 1500);
          };
          if (navigator.clipboard && navigator.clipboard.writeText && codeText) {
            navigator.clipboard.writeText(codeText).then(setCopied).catch(setCopied);
          } else {
            setCopied();
          }
        };
      }
      if (openVerifyBtn) {
        openVerifyBtn.onclick = function () {
          openMicrosoftVerifyWindow();
          return false;
        };
        copyUserCodeSync(codeEl ? codeEl.textContent : "");
        if (AUTO_OPEN) {
          try {
            verifyPopupBlocked = !openMicrosoftVerifyWindow();
          } catch (eAuto) {
            verifyPopupBlocked = true;
          }
        }
      }
      var sessionId = data2.session_id;
      var everyMs = Math.max(3000, (parseInt(data2.interval, 10) || 5) * 1000);
      if (verifyPopupBlocked) {
        setStatus(
          'Popup was blocked or could not open. Click "Open" to sign in at Microsoft (allow popups for this page if prompted). Then enter the code shown below — this page will redirect when sign-in completes.',
          false,
        );
      } else {
        setStatus(
          "Enter the code at Microsoft. This page will redirect when sign-in completes…",
          true,
        );
      }
      async function poll() {
        try {
          var pr = await fetch(
            API_BASE +
              "/oauth/microsoft/device/status?session_id=" +
              encodeURIComponent(sessionId),
            {
              method: "GET",
              headers: launcherHeaders(false),
              mode: "cors",
              credentials: "omit",
            },
          );
          var pd = await pr.json().catch(function () {
            return {};
          });
          if (pd.status === "complete") {
            setStatus(
              "Signed in" + (pd.email ? " — " + pd.email : "") + ". Redirecting…",
              true,
            );
            redirectToSpaSuccess("microsoft");
            return;
          }
          if (pd.status === "error") {
            throw new Error(pd.detail || "Device sign-in failed");
          }
        } catch (ePoll) {
          setStatus(ePoll && ePoll.message ? ePoll.message : String(ePoll), false);
          return;
        }
        devicePollTimer = window.setTimeout(poll, everyMs);
      }
      devicePollTimer = window.setTimeout(poll, everyMs);
    } catch (err) {
      var msg = err && err.message ? err.message : String(err);
      if (
        msg === "NetworkError when attempting to fetch resource." ||
        (err && err.name === "TypeError")
      ) {
        msg +=
          " Often caused by: (1) ngrok interstitial — visit the API base URL in a normal browser tab once; this launcher sends ngrok-skip-browser-warning when the host looks like ngrok. (2) file:// — use a local static server (e.g. npx serve) so the page has a real http origin, or ensure the API/worker allows CORS for Origin \"null\". (3) Cloudflare Worker as API_BASE — redeploy the " +
          APP_LABEL +
          " worker so it returns CORS headers (required for saved .html files).";
      }
      setWarmup(false);
      setStatus(msg, false);
    }
  }

  var retryBtn = document.getElementById("retry");
  if (retryBtn)
    retryBtn.onclick = function () {
      clearDevicePoll();
      void run();
    };
  void run();
}

if (typeof globalThis !== "undefined") {
  globalThis.EhPortableLauncherMount = EhPortableLauncherMount;
}


/* jsDelivr / deferred bundle (keep in sync via this script):
 * - Prefer inline JSON: <script type="application/json" id="eh-portable-boot">...</script>
 * - Option B: fetch boot JSON from backend when script src includes:
 *     ?eh_boot_url=https://api.example.com/public/eh-portable-boot&eh_boot_k=...
 */

(function () {
  var selfSrc = "";
  try {
    selfSrc = (document.currentScript && document.currentScript.src) ? String(document.currentScript.src) : "";
  } catch (e0) {
    selfSrc = "";
  }

  function injectBootEl(bootObj) {
    try {
      var bid = "eh-portable-boot";
      var el = document.getElementById(bid);
      if (!el) {
        el = document.createElement("script");
        el.type = "application/json";
        el.id = bid;
        document.head.appendChild(el);
      }
      el.textContent = JSON.stringify(bootObj || {});
    } catch (e1) {}
  }

  function bootFromDom() {
    var el = document.getElementById("eh-portable-boot");
    if (!el || !el.textContent) return null;
    try {
      return JSON.parse(el.textContent);
    } catch (e) {
      return null;
    }
  }

  async function bootFromBackend() {
    if (!selfSrc) return null;
    var u = null;
    try { u = new URL(selfSrc); } catch (e0) { u = null; }
    if (!u) return null;
    var bootUrl = String(u.searchParams.get("eh_boot_url") || "").trim();
    var bootKey = String(u.searchParams.get("eh_boot_k") || "").trim();
    if (!bootUrl || !bootKey) return null;
    var fetchUrl = bootUrl + (bootUrl.indexOf("?") >= 0 ? "&" : "?") + "k=" + encodeURIComponent(bootKey);
    try {
      var r = await fetch(fetchUrl, { method: "GET", cache: "no-store" });
      if (!r || !r.ok) return null;
      var j = await r.json();
      return j || null;
    } catch (e1) {
      return null;
    }
  }

  async function start() {
    var boot = bootFromDom();
    if (!boot) {
      boot = await bootFromBackend();
      if (boot) injectBootEl(boot);
    }
    if (!boot) return;
    try { EhPortableLauncherMount(boot); } catch (e0) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { void start(); });
  } else {
    void start();
  }
})();
