// @ts-check
import {
  PRF_SALT, b64u, b64uDecode, deriveKEK, wrapVaultKey, wrapRawVaultKey,
  unwrapVaultKey, generateRawVaultKey, encryptEntry, decryptEntry,
  generateRecoveryCode, parseRecoveryCode, deriveRecoveryKEK, deriveRecoveryVerifier,
} from "/crypto.js";

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
  const res = await fetch(path, {
    method: method || (body === undefined ? "GET" : "POST"),
    headers: { "X-GK-CSRF": "1", ...(body !== undefined && { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 401 && vaultKey) { lock(); throw new Error("Session expired — unlock again."); }
  if (!res.ok) throw new Error((await res.text()).trim() || `HTTP ${res.status}`);
  return (res.headers.get("Content-Type") || "").includes("json") ? res.json() : null;
}

function show(view) {
  for (const v of ["login", "register", "recover", "recovery-code", "vault"]) $(v).hidden = v !== view;
  $("error").textContent = "";
}

function showPanel(panel) {
  for (const p of ["browser", "editor", "settings"]) $(p).hidden = p !== panel;
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

  const prfOut = fromCreate || await getPRFOutput(cred.rawId);
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
  showRecoveryCode(code, enterVault);
}

async function uploadRecovery(code, wrappedRec) {
  const verifier = await deriveRecoveryVerifier(parseRecoveryCode(code));
  await api("/api/recovery", { verifier: b64u(verifier), wrapped: b64u(wrappedRec) });
}

function showRecoveryCode(code, onDone) {
  $("code-text").textContent = code;
  $("btn-code-copy").onclick = () => navigator.clipboard.writeText(code);
  $("btn-code-done").onclick = () => { onDone(); };
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
  const prfOut = fromCreate || await getPRFOutput(cred.rawId);
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
function guide(title, text) {
  return new Promise((resolve, reject) => {
    $("guide-title").textContent = title;
    $("guide-text").textContent = text;
    $("btn-guide").textContent = "Continue";
    const dlg = $("guide");
    const done = (ok) => { dlg.close(); ok ? resolve() : reject(new Error("Cancelled.")); };
    $("btn-guide").onclick = () => done(true);
    $("btn-guide-cancel").onclick = () => done(false);
    dlg.oncancel = () => done(false);
    dlg.showModal();
  });
}

async function addPasskey() {
  await guide("Add passkey — step 1 of 2",
    "First you'll create the NEW passkey. In the next browser dialog, pick where it should live — e.g. scan the QR code with your phone.");
  const begin = await api("/api/credentials/add/begin", {});
  const { cred, prfOut: fromCreate } = await createPasskey(begin.publicKey);
  const finish = await api("/api/credentials/add/finish", cred.toJSON());
  await guide("Add passkey — step 2 of 2",
    "Now confirm with a passkey you ALREADY use on this device. This unlocks your vault key so the new passkey can be granted access.");
  await provisionVaultKey(finish.credentialId, async () => {
    if (fromCreate) return fromCreate;
    await guide("Add passkey — one more step",
      "Your authenticator needs one extra touch: use the NEW passkey once (scan the QR code again if it's on your phone).");
    return getPRFOutput(cred.rawId);
  });
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

async function regenerateRecovery() {
  if (!confirm("Generate a new recovery code? The old one stops working.")) return;
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
    const info = document.createElement("button");
    info.className = "entry-info";
    info.onclick = () => openEditor(e);
    const name = document.createElement("strong");
    name.textContent = e.data.name || "(unnamed)";
    const site = document.createElement("small");
    site.textContent = e.data.website || "";
    info.append(name, site);
    li.append(info,
      copyButton("user", () => e.data.username),
      copyButton("pass", () => e.data.password));
    list.append(li);
  }
  $("empty").hidden = entries.length > 0;
}

function copyButton(label, getValue) {
  const btn = document.createElement("button");
  btn.textContent = label;
  btn.className = "copy";
  btn.onclick = async () => {
    await navigator.clipboard.writeText(getValue() || "");
    btn.textContent = "✓";
    setTimeout(() => { btn.textContent = label; }, 1200);
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
  for (const f of ["name", "website", "username", "password", "notes"]) {
    $(`f-${f}`).value = entry?.data[f] || "";
  }
  $("f-password").type = "password";
  $("f-name").focus();
}

async function saveEntry() {
  const data = {};
  for (const f of ["name", "website", "username", "password", "notes"]) {
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
  $("btn-settings").onclick = () => openSettings().catch(fail);
  $("btn-settings-back").onclick = showList;
  $("btn-add-passkey").onclick = () => addPasskey().catch(fail);
  $("btn-regen-recovery").onclick = () => regenerateRecovery().catch(fail);
  $("btn-show-recover").onclick = () => show("recover");
  $("btn-recover-cancel").onclick = () => show("login");
  $("btn-recover").onclick = () => recover().catch(fail);

  show(new URLSearchParams(location.search).get("invite") ? "register" : "login");
}

init();
