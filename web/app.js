// @ts-check
import {
  PRF_SALT, b64u, b64uDecode, deriveKEK, wrapVaultKey, wrapRawVaultKey,
  unwrapVaultKey, generateRawVaultKey, encryptEntry, decryptEntry,
  generateRecoveryCode, parseRecoveryCode, deriveRecoveryKEK, deriveRecoveryVerifier,
} from "/crypto.js";
import { mapBitwarden } from "/import.js";
import { totpCode, totpRemaining } from "/totp.js";

let vaultKey = null; // non-extractable CryptoKey while unlocked
let username = null;
let entries = []; // [{id, data: {name, website, username, password, notes}}]
let clipboardTimer = null;
// The credential that unlocked this session and its wrapped vault key: lets
// us re-obtain an extractable vault key (fresh PRF assertion) when wrapping
// for a new passkey or recovery code, without keeping raw key bytes around.
let unlockCred = null; // {idBytes: Uint8Array, wrapped: Uint8Array}

const $ = (id) => document.getElementById(id);

async function api(path, body, method) {
  let res;
  try {
    res = await fetch(path, {
      method: method || (body === undefined ? "GET" : "POST"),
      headers: { "X-GK-CSRF": "1", ...(body !== undefined && { "Content-Type": "application/json" }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new Error("Cannot reach the server — is it running? Then reload this page.");
  }
  if (res.status === 401 && vaultKey) { lock(); throw new Error("Session expired — unlock again."); }
  if (!res.ok) throw new Error((await res.text()).trim() || `HTTP ${res.status}`);
  return (res.headers.get("Content-Type") || "").includes("json") ? res.json() : null;
}

function show(view) {
  for (const v of ["login", "register", "recover", "recovery-code", "vault"]) $(v).hidden = v !== view;
  $("error").textContent = "";
}

function showPanel(panel) {
  for (const p of ["browser", "editor", "settings", "import"]) $(p).hidden = p !== panel;
  $("btn-settings").textContent = panel === "settings" ? "Back" : "Settings";
}

function fail(err) {
  console.error(err);
  $("error").textContent = err?.message || String(err);
}

function supported() {
  return window.PublicKeyCredential
    && PublicKeyCredential.parseCreationOptionsFromJSON
    && PublicKeyCredential.parseRequestOptionsFromJSON;
}

// --- auth (unchanged from milestone 2) ---

// Create a passkey, asking the authenticator to evaluate PRF right away.
// Returns {cred, prfOut} — prfOut is null if this authenticator only
// evaluates PRF on assertions (caller falls back to getPRFOutput, which
// costs one extra ceremony).
async function createPasskey(optionsJSON) {
  const options = PublicKeyCredential.parseCreationOptionsFromJSON(optionsJSON);
  options.extensions = { ...options.extensions, prf: { eval: { first: PRF_SALT } } };
  const cred = await navigator.credentials.create({ publicKey: options });
  const prf = cred.getClientExtensionResults().prf;
  if (!prf?.enabled && !prf?.results) {
    throw new Error("This authenticator does not support the PRF extension; pick another one.");
  }
  return { cred, prfOut: prf.results?.first ? new Uint8Array(prf.results.first) : null };
}

async function getPRFOutput(credentialIdBytes) {
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: "public-key", id: credentialIdBytes }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const out = cred.getClientExtensionResults().prf?.results?.first;
  if (!out) throw new Error("This passkey does not support the PRF extension.");
  return new Uint8Array(out);
}

async function register() {
  const token = new URLSearchParams(location.search).get("invite");
  const begin = await api("/api/register/begin", { token });
  const { cred, prfOut: fromCreate } = await createPasskey(begin.publicKey);
  const finish = await api("/api/register/finish", cred.toJSON());
  username = finish.username;

  let prfOut = fromCreate;
  if (!prfOut) {
    // Without this, the assertion prompt right after creation looks like a
    // surprise login and confuses people.
    await guide("Almost done",
      "Your passkey is created. Your authenticator needs one more confirmation with it to set up encryption — this is still part of setup, not a login.");
    prfOut = await getPRFOutput(cred.rawId);
  }
  const kek = await deriveKEK(prfOut);
  prfOut.fill(0);
  const rawVK = generateRawVaultKey();
  const wrapped = await wrapRawVaultKey(kek, rawVK);
  vaultKey = await unwrapVaultKey(kek, wrapped);
  await api("/api/credentials/vault-key", { credentialId: finish.credentialId, wrapped: b64u(wrapped) });
  unlockCred = { idBytes: new Uint8Array(cred.rawId), wrapped };

  // Set up the recovery code while we still hold the raw key bytes.
  const code = generateRecoveryCode();
  await uploadRecovery(code, await wrapRawVaultKey(await deriveRecoveryKEK(parseRecoveryCode(code)), rawVK));
  rawVK.fill(0);

  history.replaceState(null, "", "/");
  showRecoveryCode(code, async () => {
    await enterVault();
    // Optional: offer a second passkey right away. The recovery code is the
    // emergency backup; a second passkey is the everyday one.
    try {
      await guide("Add a second passkey?",
        "Your recovery code is the emergency backup. For day-to-day safety, add a second passkey on another device — e.g. your phone or a security key. You can also do this later in Settings.",
        { button: "Add second passkey", cancel: "Maybe later" });
    } catch { return; }
    await addPasskey();
  });
}

async function uploadRecovery(code, wrappedRec) {
  const verifier = await deriveRecoveryVerifier(parseRecoveryCode(code));
  await api("/api/recovery", { verifier: b64u(verifier), wrapped: b64u(wrappedRec) });
}

function showRecoveryCode(code, onDone) {
  $("code-text").textContent = code;
  $("btn-code-copy").onclick = () => navigator.clipboard.writeText(code);
  $("btn-code-done").onclick = () => { Promise.resolve(onDone()).catch(fail); };
  show("recovery-code");
}

async function login() {
  const begin = await api("/api/login/begin", {});
  const options = PublicKeyCredential.parseRequestOptionsFromJSON(begin.publicKey);
  options.extensions = { ...options.extensions, prf: { eval: { first: PRF_SALT } } };
  const cred = await navigator.credentials.get({ publicKey: options });
  const ext = cred.getClientExtensionResults();
  const finish = await api("/api/login/finish", cred.toJSON());
  username = finish.username;

  let prfOut = ext.prf?.results?.first ? new Uint8Array(ext.prf.results.first) : null;
  if (!prfOut) prfOut = await getPRFOutput(cred.rawId);
  const kek = await deriveKEK(prfOut);
  prfOut.fill(0);

  let wrapped;
  if (finish.wrappedVaultKey) {
    wrapped = b64uDecode(finish.wrappedVaultKey);
    vaultKey = await unwrapVaultKey(kek, wrapped);
  } else if (finish.hasEntries) {
    // This passkey never finished setup and the vault is not empty: creating
    // a fresh vault key here would strand the existing entries.
    await api("/api/logout", {}).catch(() => {});
    throw new Error("This passkey has no vault key yet. Unlock with another passkey and use “finish setup” in Settings.");
  } else {
    const rawVK = generateRawVaultKey();
    wrapped = await wrapRawVaultKey(kek, rawVK);
    vaultKey = await unwrapVaultKey(kek, wrapped);
    rawVK.fill(0);
    await api("/api/credentials/vault-key", { credentialId: finish.credentialId, wrapped: b64u(wrapped) });
  }
  unlockCred = { idBytes: new Uint8Array(cred.rawId), wrapped };
  await enterVault();
}

// Recover access with username + recovery code: registers a fresh passkey,
// then rewraps the vault key for it using the code-derived KEK.
async function recover() {
  const name = $("r-username").value.trim();
  const codeBytes = parseRecoveryCode($("r-code").value);
  const verifier = await deriveRecoveryVerifier(codeBytes);
  const begin = await api("/api/recover/begin", { username: name, verifier: b64u(verifier) });
  const { cred, prfOut: fromCreate } = await createPasskey(begin.publicKey);
  const finish = await api("/api/recover/finish", cred.toJSON());
  username = finish.username;

  const kekRec = await deriveRecoveryKEK(codeBytes);
  const vk = await unwrapVaultKey(kekRec, b64uDecode(finish.recoveryWrappedKey), true);
  let prfOut = fromCreate;
  if (!prfOut) {
    await guide("Almost done",
      "Your new passkey is created. One more confirmation with it re-encrypts your vault key — still part of recovery, not a login.");
    prfOut = await getPRFOutput(cred.rawId);
  }
  const kekNew = await deriveKEK(prfOut);
  prfOut.fill(0);
  const wrapped = await wrapVaultKey(kekNew, vk);
  await api("/api/credentials/vault-key", { credentialId: finish.credentialId, wrapped: b64u(wrapped) });
  vaultKey = await unwrapVaultKey(kekNew, wrapped); // swap to non-extractable
  unlockCred = { idBytes: new Uint8Array(cred.rawId), wrapped };
  $("r-code").value = "";
  await enterVault();
}

// Fresh PRF assertion with the unlock credential → extractable vault key,
// used transiently to wrap for a new passkey or recovery code.
async function extractableVaultKey() {
  const prfOut = await getPRFOutput(unlockCred.idBytes);
  const kek = await deriveKEK(prfOut);
  prfOut.fill(0);
  return unwrapVaultKey(kek, unlockCred.wrapped, true);
}

// --- settings: passkey + recovery management ---

async function openSettings() {
  const info = await api("/api/credentials");
  const list = $("cred-list");
  list.replaceChildren();
  for (const c of info.credentials) {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.className = "entry-info";
    const name = document.createElement("strong");
    name.textContent = c.name || `passkey ${c.id.slice(0, 8)}`;
    const meta = document.createElement("small");
    meta.textContent = new Date(c.createdAt * 1000).toLocaleDateString()
      + (c.hasVaultKey ? "" : " — no vault key, cannot unlock");
    label.append(name, meta);
    let fix = null;
    if (!c.hasVaultKey) {
      fix = document.createElement("button");
      fix.textContent = "finish setup";
      fix.className = "copy";
      fix.onclick = async () => {
        try {
          await guide("Finish setup — step 1 of 2",
            "Confirm with the passkey you used to unlock the vault just now. This releases your vault key for re-encryption.");
          await provisionVaultKey(c.id, async () => {
            await guide("Finish setup — step 2 of 2",
              "Now use the passkey being set up — scan the QR code if it lives on your phone.");
            return getPRFOutput(b64uDecode(c.id));
          });
          await openSettings();
        } catch (err) { fail(err); }
      };
    }
    const rename = document.createElement("button");
    rename.textContent = "rename";
    rename.className = "copy";
    rename.onclick = async () => {
      const n = prompt("Name this passkey:", c.name);
      if (n === null) return;
      await api("/api/credentials/rename", { credentialId: c.id, name: n }).catch(fail);
      openSettings().catch(fail);
    };
    const del = document.createElement("button");
    del.textContent = "revoke";
    del.className = "copy danger-text";
    del.onclick = async () => {
      if (!confirm("Revoke this passkey? It will no longer unlock the vault.")) return;
      await api("/api/credentials/delete", { credentialId: c.id }).catch(fail);
      openSettings().catch(fail);
    };
    li.append(label, ...(fix ? [fix] : []), rename, del);
    list.append(li);
  }
  $("recovery-status").textContent = info.hasRecovery
    ? "A recovery code is set." : "No recovery code set — lose all passkeys and the vault is gone.";
  showPanel("settings");
}

// Step-guide modal: shown before each passkey prompt in multi-ceremony flows
// so the user knows WHICH passkey the next browser dialog is about. The
// Continue click also provides fresh user activation for the WebAuthn call.
// opts: {input: placeholder} shows a text field and resolves with its value;
// {button: label} and {cancel: label} override the button labels.
function guide(title, text, opts = {}) {
  return new Promise((resolve, reject) => {
    $("guide-title").textContent = title;
    $("guide-text").textContent = text;
    const inp = $("guide-input");
    inp.hidden = !opts.input;
    inp.value = "";
    inp.placeholder = opts.input || "";
    $("btn-guide").textContent = opts.button || "Continue";
    $("btn-guide-cancel").textContent = opts.cancel || "Cancel";
    const dlg = $("guide");
    const done = (ok) => {
      dlg.close();
      ok ? resolve(opts.input ? inp.value.trim() : undefined) : reject(new Error("Cancelled."));
    };
    $("btn-guide").onclick = () => done(true);
    $("btn-guide-cancel").onclick = () => done(false);
    dlg.oncancel = () => done(false);
    dlg.showModal();
    if (opts.input) inp.focus();
  });
}

async function addPasskey() {
  await guide("Add passkey — step 1 of 3",
    "First you'll create the NEW passkey. In the next browser dialog, pick where it should live — e.g. scan the QR code with your phone.");
  const begin = await api("/api/credentials/add/begin", {});
  const { cred, prfOut: fromCreate } = await createPasskey(begin.publicKey);
  const finish = await api("/api/credentials/add/finish", cred.toJSON());
  await guide("Add passkey — step 2 of 3",
    "Now confirm with a passkey you ALREADY use on this device. This unlocks your vault key so the new passkey can be granted access.");
  await provisionVaultKey(finish.credentialId, async () => {
    if (fromCreate) return fromCreate;
    await guide("Add passkey — one more step",
      "Your authenticator needs one extra touch: use the NEW passkey once (scan the QR code again if it's on your phone).");
    return getPRFOutput(cred.rawId);
  });
  // The passkey works from here on — a cancelled name step is not an error.
  const name = await guide("Add passkey — step 3 of 3",
    "Give the new passkey a name so you can recognize it later.",
    { input: "e.g. phone, yubikey, macbook", button: "Save" }).catch(() => null);
  if (name) await api("/api/credentials/rename", { credentialId: finish.credentialId, name });
  await openSettings();
}

// Wrap the vault key for another credential: one assertion with the unlock
// passkey, plus the target's PRF output from the given source.
async function provisionVaultKey(credentialId, getPrf) {
  const vk = await extractableVaultKey();
  const prfOut = await getPrf();
  const kekNew = await deriveKEK(prfOut);
  prfOut.fill(0);
  const wrapped = await wrapVaultKey(kekNew, vk);
  await api("/api/credentials/vault-key", { credentialId, wrapped: b64u(wrapped) });
}

// --- Bitwarden import ---

async function pickImportFile() {
  const input = $("import-file");
  input.value = "";
  input.onchange = async () => {
    try {
      const file = input.files[0];
      if (!file) return;
      const { entries: toImport, skipped } = mapBitwarden(JSON.parse(await file.text()));
      previewImport(toImport, skipped);
    } catch (err) {
      fail(err);
    }
  };
  input.click();
}

function previewImport(toImport, skipped) {
  const skippedText = Object.entries(skipped)
    .map(([label, n]) => `${n} ${label}${n > 1 ? "s" : ""}`).join(", ");
  $("import-summary").textContent =
    `${toImport.length} entries will be imported as new entries (existing ones are untouched).`
    + (skippedText ? ` Not supported and skipped: ${skippedText}.` : "");
  const list = $("import-list");
  list.replaceChildren();
  for (const e of toImport) {
    const li = document.createElement("li");
    const name = document.createElement("strong");
    name.textContent = e.name || "(unnamed)";
    const meta = document.createElement("small");
    meta.textContent = " " + [e.website, e.username].filter(Boolean).join(" — ");
    li.append(name, meta);
    list.append(li);
  }
  const run = $("btn-import-run");
  run.textContent = `Import ${toImport.length} entries`;
  run.disabled = toImport.length === 0;
  run.onclick = () => runImport(toImport).catch(fail);
  showPanel("import");
}

async function runImport(toImport) {
  const run = $("btn-import-run");
  run.disabled = true;
  let done = 0;
  // Encrypt + upload in small parallel batches; each entry is its own
  // ciphertext with a fresh IV, exactly like manual creation.
  for (let i = 0; i < toImport.length; i += 20) {
    await Promise.all(toImport.slice(i, i + 20).map(async (data) => {
      const id = crypto.randomUUID();
      await api(`/api/entries/${id}`, { ciphertext: b64u(await encryptEntry(vaultKey, data)) }, "PUT");
      entries.push({ id, data });
    }));
    done = Math.min(i + 20, toImport.length);
    run.textContent = `Importing… ${done}/${toImport.length}`;
  }
  showList();
}

async function regenerateRecovery() {
  // extractableVaultKey only accepts the passkey this session was unlocked
  // with (its wrapped vault key is the one we hold) — say so up front.
  await guide("New recovery code",
    "The old code stops working. Confirm with the passkey you unlocked the vault with just now — the browser will not offer your other passkeys here.",
    { button: "Generate" });
  const vk = await extractableVaultKey();
  const code = generateRecoveryCode();
  const wrappedRec = await wrapVaultKey(await deriveRecoveryKEK(parseRecoveryCode(code)), vk);
  await uploadRecovery(code, wrappedRec);
  showRecoveryCode(code, () => { show("vault"); openSettings().catch(fail); });
}

function lock() {
  vaultKey = null;
  unlockCred = null;
  entries = [];
  $("list").replaceChildren();
  show("login");
}

// --- auto-lock: idle timeout, plus lock when the tab was hidden too long
// (phone pocketed, app switched away). The vault key only lives in memory,
// so locking is just dropping it.
const AUTO_LOCK_MS = 5 * 60_000;
let idleTimer = null;
let hiddenAt = null;

function armAutoLock() {
  clearTimeout(idleTimer);
  if (!vaultKey) return;
  idleTimer = setTimeout(() => { if (vaultKey) lock(); }, AUTO_LOCK_MS);
}

function initAutoLock() {
  for (const ev of ["pointerdown", "keydown"]) {
    addEventListener(ev, armAutoLock, { passive: true });
  }
  addEventListener("visibilitychange", () => {
    if (document.hidden) {
      hiddenAt = Date.now();
    } else {
      if (vaultKey && hiddenAt && Date.now() - hiddenAt > AUTO_LOCK_MS) lock();
      hiddenAt = null;
      armAutoLock();
    }
  });
}

async function logout() {
  try { await api("/api/logout", {}); } catch {}
  lock();
}

// --- vault ---

async function enterVault() {
  $("whoami").textContent = username;
  const raw = await api("/api/entries");
  entries = await Promise.all(raw.map(async (e) => ({
    id: e.id,
    data: await decryptEntry(vaultKey, b64uDecode(e.ciphertext)),
  })));
  show("vault");
  showList();
  armAutoLock();
}

function sortedFiltered() {
  const q = $("search").value.trim().toLowerCase();
  return entries
    .filter((e) => !q || [e.data.name, e.data.website, e.data.username]
      .some((f) => (f || "").toLowerCase().includes(q)))
    .sort((a, b) => (a.data.name || "").localeCompare(b.data.name || ""));
}

function showList() {
  showPanel("browser");
  renderList();
  $("search").focus();
}

function renderList() {
  const list = $("list");
  list.replaceChildren();
  for (const e of sortedFiltered()) {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.className = "entry-info";
    const name = document.createElement("button");
    name.className = "entry-name";
    name.onclick = () => openEditor(e);
    const strong = document.createElement("strong");
    strong.textContent = e.data.name || "(unnamed)";
    name.append(strong);
    info.append(name, siteLine(e.data.website));
    li.append(info,
      copyButton("user", () => e.data.username),
      copyButton("pass", () => e.data.password));
    if (e.data.totp) li.append(copyButton("2FA", () => totpCode(e.data.totp)));
    list.append(li);
  }
  $("empty").hidden = entries.length > 0;
}

// The website as a link when it parses as a web address, plain text otherwise.
// The scheme is optional in the field ("example.com"), so default to https.
function siteLine(website) {
  const small = document.createElement("small");
  small.textContent = website || "";
  if (!website) return small;
  let url = null;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:/i.test(website) ? website : `https://${website}`); } catch {}
  if (!url || (url.protocol !== "https:" && url.protocol !== "http:")) return small;
  const a = document.createElement("a");
  a.className = "entry-site";
  a.href = url.href;
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  a.append(small);
  return a;
}

const COPY_ICON = `<svg viewBox="0 0 24 24" width="13" height="13" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2" d="M9 4h11v13M4 8h11v13H4z" stroke-linejoin="round"/></svg>`;

function copyButton(label, getValue) {
  const btn = document.createElement("button");
  btn.innerHTML = `${label} ${COPY_ICON}`; // static markup only, no user data
  btn.className = "copy";
  btn.onclick = async () => {
    try {
      // getValue may be async (TOTP codes are computed on demand).
      await navigator.clipboard.writeText((await getValue()) || "");
    } catch (err) { fail(err); return; }
    btn.textContent = "✓";
    setTimeout(() => { btn.innerHTML = `${label} ${COPY_ICON}`; }, 1200);
    // Best-effort clipboard clear. May overwrite something the user copied
    // in between; acceptable for a password manager.
    clearTimeout(clipboardTimer);
    clipboardTimer = setTimeout(() => navigator.clipboard.writeText(" ").catch(() => {}), 30_000);
  };
  return btn;
}

function openEditor(entry) {
  showPanel("editor");
  $("editor-title").textContent = entry ? "Edit entry" : "New entry";
  $("btn-delete").hidden = !entry;
  $("editor").dataset.id = entry?.id || "";
  for (const f of ["name", "website", "username", "password", "totp", "notes"]) {
    $(`f-${f}`).value = entry?.data[f] || "";
  }
  $("f-password").type = "password";
  updateTotpPreview();
  $("f-name").focus();
}

// Live preview of the current TOTP code next to the secret field.
async function updateTotpPreview() {
  const el = $("totp-preview");
  const secret = $("f-totp").value.trim();
  if ($("editor").hidden || !secret) { el.textContent = ""; return; }
  try {
    el.textContent = `${await totpCode(secret)} · ${totpRemaining(secret)}s`;
  } catch {
    el.textContent = "invalid secret";
  }
}

async function saveEntry() {
  const data = {};
  for (const f of ["name", "website", "username", "password", "totp", "notes"]) {
    data[f] = $(`f-${f}`).value;
  }
  if (!data.name && !data.website) throw new Error("Give the entry a name or website.");
  const id = $("editor").dataset.id || crypto.randomUUID();
  const ciphertext = await encryptEntry(vaultKey, data);
  await api(`/api/entries/${id}`, { ciphertext: b64u(ciphertext) }, "PUT");
  const existing = entries.find((e) => e.id === id);
  if (existing) existing.data = data;
  else entries.push({ id, data });
  showList();
}

async function deleteEntry() {
  const id = $("editor").dataset.id;
  if (!id || !confirm("Delete this entry?")) return;
  await api(`/api/entries/${id}`, undefined, "DELETE");
  entries = entries.filter((e) => e.id !== id);
  showList();
}

function generatePassword() {
  // 24 chars from a 72-symbol alphabet (~148 bits), rejection-sampled.
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_+=";
  let out = "";
  while (out.length < 24) {
    const [b] = crypto.getRandomValues(new Uint8Array(1));
    if (b < 256 - (256 % alphabet.length)) out += alphabet[b % alphabet.length];
  }
  $("f-password").value = out;
  $("f-password").type = "text";
}

function init() {
  if (!supported()) {
    $("error").textContent = "This browser does not support the required WebAuthn features.";
    return;
  }
  $("btn-login").onclick = () => login().catch(fail);
  $("btn-register").onclick = () => register().catch(fail);
  $("btn-lock").onclick = lock;
  $("btn-logout").onclick = () => logout().catch(fail);
  $("btn-add").onclick = () => openEditor(null);
  $("btn-save").onclick = () => saveEntry().catch(fail);
  $("btn-cancel").onclick = showList;
  $("btn-delete").onclick = () => deleteEntry().catch(fail);
  $("btn-generate").onclick = generatePassword;
  $("btn-reveal").onclick = () => {
    const f = $("f-password");
    f.type = f.type === "password" ? "text" : "password";
  };
  $("search").oninput = renderList;
  $("f-totp").oninput = updateTotpPreview;
  setInterval(updateTotpPreview, 1000);
  $("totp-row").append(copyButton("copy", () => {
    const secret = $("f-totp").value.trim();
    return secret ? totpCode(secret) : "";
  }));
  $("btn-settings").onclick = () => {
    if ($("settings").hidden) openSettings().catch(fail);
    else showList();
  };
  $("btn-add-passkey").onclick = () => addPasskey().catch(fail);
  $("btn-regen-recovery").onclick = () => regenerateRecovery().catch(fail);
  $("btn-import").onclick = pickImportFile;
  $("btn-import-cancel").onclick = () => showPanel("settings");
  $("btn-show-recover").onclick = () => show("recover");
  $("btn-recover-cancel").onclick = () => show("login");
  $("btn-recover").onclick = () => recover().catch(fail);

  initAutoLock();
  navigator.serviceWorker?.register("/sw.js").catch(() => {});

  show(new URLSearchParams(location.search).get("invite") ? "register" : "login");
}

init();
