// End-to-end test of the passkey flows, using Chromium's virtual
// authenticator (CDP WebAuthn domain) with PRF support. Builds the gk binary,
// starts it against a throwaway database, and walks the whole journey:
// register → recovery code → entry → lock/login → new recovery code →
// lose the passkey → recover with the code.
import { test, expect } from "@playwright/test";
import { totpCode } from "../web/totp.js";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const ORIGIN = "http://localhost:8199";
const USERNAME = "alice";

let dir, server, inviteToken, bin, db;

test.beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "gk-e2e-"));
  bin = join(dir, "gk");
  db = join(dir, "gk.db");
  await run("go", ["build", "-o", bin, "."]);
  const { stdout } = await run(bin, ["invite", "-db", db, "-origin", ORIGIN, USERNAME]);
  inviteToken = stdout.match(/invite=(\S+)/)[1];
  server = spawn(bin, ["serve", "-listen", "127.0.0.1:8199", "-db", db, "-origin", ORIGIN], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  // Wait until the server answers.
  for (let i = 0; ; i++) {
    try { await fetch(ORIGIN + "/"); break; }
    catch { if (i > 50) throw new Error("gk serve did not come up"); await new Promise((r) => setTimeout(r, 100)); }
  }
});

test.afterAll(async () => {
  server?.kill();
  if (dir) await rm(dir, { recursive: true, force: true });
});

// A virtual CTAP2 authenticator with PRF (hmac-secret) support. Presence and
// user verification are simulated automatically, so WebAuthn prompts resolve
// without interaction.
async function addAuthenticator(page, opts = {}) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
      ...opts,
    },
  });
  return { cdp, authenticatorId };
}

// The app shows step-guide dialogs before some passkey prompts (which ones
// depends on whether the authenticator evaluates PRF at creation). Auto-click
// through them; name the first passkey "first key"; decline the optional
// "add a second passkey" offer.
function autoGuide(page) {
  return page.addInitScript(() => {
    setInterval(() => {
      if (window.__noAutoGuide) return;
      const dlg = document.getElementById("guide");
      if (!dlg?.open) return;
      const title = document.getElementById("guide-title")?.textContent || "";
      if (title.includes("second passkey")) document.getElementById("btn-guide-cancel")?.click();
      else if (title.startsWith("Name your")) {
        document.getElementById("guide-input").value = "first key";
        document.getElementById("btn-guide")?.click();
      } else if (document.getElementById("guide-input")?.hidden) document.getElementById("btn-guide")?.click();
    }, 100);
  });
}

test("register, entries, re-login, recovery code rotation and recovery", async ({ page }) => {
  page.on("dialog", (d) => d.accept());
  await autoGuide(page);
  const auth = await addAuthenticator(page);

  // --- register via invite; the recovery code is shown exactly once
  await page.goto(`/?invite=${inviteToken}`);
  await page.click("#btn-register");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  const firstCode = (await page.locator("#code-text").textContent()).trim();
  expect(firstCode.replace(/-/g, "")).toHaveLength(32);
  await page.click("#btn-code-done");
  await expect(page.locator("#vault")).toBeVisible();
  await expect(page.locator("#whoami")).toHaveText(USERNAME);

  // --- create an entry; the website renders as a link opening in a new tab
  await page.click("#btn-add");
  await page.fill("#f-name", "Example");
  await page.fill("#f-website", "example.com");
  await page.fill("#f-username", "alice@example.com");
  await page.fill("#f-password", "hunter2!");
  await page.click("#btn-save");
  const site = page.locator("#list a.entry-site");
  await expect(site).toHaveAttribute("href", "https://example.com/");
  await expect(site).toHaveAttribute("target", "_blank");
  await expect(site).toHaveAttribute("rel", /noopener/);

  // --- lock, then unlock with the same passkey; the entry decrypts again
  await page.click("#btn-lock");
  await expect(page.locator("#login")).toBeVisible();
  await page.click("#btn-login");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#list strong")).toHaveText("Example");

  // --- rotate the recovery code (guide is auto-confirmed)
  await page.click("#btn-settings");
  await expect(page.locator("#settings")).toBeVisible();
  await page.click("#btn-regen-recovery");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  const secondCode = (await page.locator("#code-text").textContent()).trim();
  expect(secondCode).not.toBe(firstCode);
  await page.click("#btn-code-done");
  await expect(page.locator("#settings")).toBeVisible();

  // --- lose the passkey, recover with username + new code on a fresh authenticator
  await page.click("#btn-lock");
  await expect(page.locator("#login")).toBeVisible();
  await auth.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: auth.authenticatorId });
  await addAuthenticator(page);
  await page.click("#btn-show-recover");
  await page.fill("#r-username", USERNAME);
  await page.fill("#r-code", secondCode);
  await page.click("#btn-recover");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#list strong")).toHaveText("Example");

  // --- the old code must be dead after rotation
  await page.click("#btn-lock");
  await page.click("#btn-show-recover");
  await page.fill("#r-username", USERNAME);
  await page.fill("#r-code", firstCode);
  await page.click("#btn-recover");
  await expect(page.locator("#error")).toContainText("recovery failed", { timeout: 15_000 });
  await expect(page.locator("#vault")).toBeHidden();
});

// TOTP step-up for synced passkeys: register with a backup-eligible (BE=1)
// virtual authenticator, opt into TOTP in settings, and verify the unlock
// gate, the trusted-device skip, and revocation.
test("TOTP step-up with a synced (backup-eligible) passkey", async ({ page }) => {
  test.setTimeout(120_000);
  page.on("dialog", (d) => d.accept());
  await autoGuide(page);
  await addAuthenticator(page, { defaultBackupEligibility: true, defaultBackupState: true });

  // Each TOTP step may be spent only once; the server accepts ±1 step of
  // skew, so borrow the next step when the current one is used up (worst
  // case: one short wait for the clock to move on).
  let lastStep = 0;
  async function freshCode(secret) {
    while (Math.floor(Date.now() / 30_000) + 1 <= lastStep) {
      await new Promise((r) => setTimeout(r, 500));
    }
    const step = Math.max(Math.floor(Date.now() / 30_000), lastStep + 1);
    lastStep = step;
    return totpCode(secret, step * 30_000 + 1);
  }

  const { stdout } = await run(bin, ["invite", "-db", db, "-origin", ORIGIN, "bob"]);
  await page.goto(`/?invite=${stdout.match(/invite=(\S+)/)[1]}`);
  await page.click("#btn-register");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  await page.click("#btn-code-done");
  await expect(page.locator("#vault")).toBeVisible();

  // --- no TOTP enrolled: the synced-passkey nag is up; enroll from settings
  await expect(page.locator("#synced-banner")).toBeVisible();
  await page.click("#btn-settings");
  await expect(page.locator("#cred-list small")).toContainText("synced");
  await page.click("#btn-totp-toggle");
  await expect(page.locator("#totp-setup")).toBeVisible();
  await expect(page.locator("#totp-setup-qr")).toBeVisible(); // QR rendered (drawQR sets the size)
  const secret = (await page.locator("#totp-setup-secret").textContent()).replace(/\s/g, "");
  await page.fill("#totp-setup-code", "000000");
  await page.click("#btn-totp-setup");
  await expect(page.locator("#totp-setup-error")).toContainText("wrong code");
  await page.fill("#totp-setup-code", await freshCode(secret));
  await page.click("#btn-totp-setup");
  await expect(page.locator("#totp-status")).toContainText("Enabled");

  // --- unlock now requires a code; wrong one is retryable, then trust the device
  await page.click("#btn-settings"); // back
  await page.click("#btn-lock");
  await page.click("#btn-login");
  await expect(page.locator("#totp-login")).toBeVisible({ timeout: 15_000 });
  await page.fill("#totp-login-code", "000000");
  await page.click("#btn-totp-login");
  await expect(page.locator("#totp-login-error")).toContainText("wrong code");
  await page.fill("#totp-login-code", await freshCode(secret));
  await page.check("#totp-login-trust");
  await page.click("#btn-totp-login");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });

  // --- trusted device: the next unlock skips the prompt entirely
  await page.click("#btn-lock");
  await page.click("#btn-login");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#totp-login")).toBeHidden();

  // --- revoke the trust: the prompt is back on the next unlock
  await page.click("#btn-settings");
  await expect(page.locator("#trust-list li")).toHaveCount(1);
  await page.click("#btn-trust-revoke-all");
  await expect(page.locator("#trust-list small")).toContainText("None");
  await page.click("#btn-settings"); // back
  await page.click("#btn-lock");
  await page.click("#btn-login");
  await expect(page.locator("#totp-login")).toBeVisible({ timeout: 15_000 });
  // Enter submits the code dialog (fill leaves the field focused).
  await page.fill("#totp-login-code", await freshCode(secret));
  await page.keyboard.press("Enter");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
});

async function invite(name) {
  const { stdout } = await run(bin, ["invite", "-db", db, "-origin", ORIGIN, name]);
  return stdout.match(/invite=(\S+)/)[1];
}

// Everyday vault usability: keyboard-first entry management, search with a
// no-matches state, generator/reveal, TOTP preview + copy, passkey
// rename/revoke, Bitwarden import, and the recover form submitting on Enter.
test("entry management, search, keyboard flows, passkeys and import", async ({ page }) => {
  test.setTimeout(120_000);
  page.on("dialog", (d) => d.accept(d.type() === "prompt" ? "renamed key" : undefined));
  await autoGuide(page);
  const auth = await addAuthenticator(page);
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin: ORIGIN });

  await page.goto(`/?invite=${await invite("carol")}`);
  await page.click("#btn-register");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  // The confirm button is focused, so Enter alone moves on.
  await expect(page.locator("#btn-code-done")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#vault")).toBeVisible();

  // --- create an entry with the keyboard only: focus lands on the name
  // field, Enter in any single-line field saves
  await page.click("#btn-add");
  await expect(page.locator("#f-name")).toBeFocused();
  await page.fill("#f-name", "Alpha");
  await page.fill("#f-username", "a@x.io");
  await page.locator("#f-username").press("Enter");
  await expect(page.locator("#editor")).toBeHidden();
  await expect(page.locator("#list strong")).toHaveText("Alpha");

  // --- generator fills and reveals the password; reveal toggles back
  await page.click("#btn-add");
  await page.fill("#f-name", "Beta");
  await page.click("#btn-generate");
  expect(await page.inputValue("#f-password")).toHaveLength(24);
  await expect(page.locator("#f-password")).toHaveAttribute("type", "text");
  await expect(page.locator("#btn-reveal")).toHaveAttribute("aria-pressed", "true");
  await page.click("#btn-reveal");
  await expect(page.locator("#f-password")).toHaveAttribute("type", "password");
  await expect(page.locator("#btn-reveal")).toHaveAttribute("aria-pressed", "false");

  // --- TOTP preview: a valid secret shows a ticking code, garbage says so
  await page.fill("#f-totp", "JBSWY3DPEHPK3PXP");
  await expect(page.locator("#totp-preview")).toHaveText(/^\d{6} · \d+s$/);
  await page.fill("#f-totp", "not a secret!");
  await expect(page.locator("#totp-preview")).toHaveText("invalid secret");
  await page.fill("#f-totp", "JBSWY3DPEHPK3PXP");
  await page.click("#btn-save");

  // --- the 2FA button copies a current code and confirms without losing its label
  const copy2fa = page.getByRole("button", { name: "Copy 2FA code for Beta" });
  await copy2fa.click();
  await expect(copy2fa).toHaveText(/2FA ✓/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toMatch(/^\d{6}$/);

  // --- search filters; zero matches say so instead of a bare empty list
  await page.fill("#search", "alp");
  await expect(page.locator("#list li")).toHaveCount(1);
  await page.fill("#search", "zzz");
  await expect(page.locator("#list li")).toHaveCount(0);
  await expect(page.locator("#empty")).toHaveText("No matches.");
  await page.fill("#search", "");
  await expect(page.locator("#list li")).toHaveCount(2);

  // --- Escape cancels an edit without saving; a saved edit sticks
  await page.locator(".entry-name", { hasText: "Alpha" }).click();
  await page.fill("#f-username", "changed@x.io");
  await page.keyboard.press("Escape");
  await expect(page.locator("#editor")).toBeHidden();
  await page.locator(".entry-name", { hasText: "Alpha" }).click();
  await expect(page.locator("#f-username")).toHaveValue("a@x.io");
  await page.fill("#f-username", "new@x.io");
  await page.click("#btn-save");
  await page.locator(".entry-name", { hasText: "Alpha" }).click();
  await expect(page.locator("#f-username")).toHaveValue("new@x.io");
  await page.click("#btn-cancel");

  // --- delete an entry (confirm dialog is auto-accepted)
  await page.locator(".entry-name", { hasText: "Beta" }).click();
  await page.click("#btn-delete");
  await expect(page.locator("#list li")).toHaveCount(1);

  // --- Escape backs out of settings
  await page.click("#btn-settings");
  await expect(page.locator("#settings")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#browser")).toBeVisible();

  // --- add a second passkey. It must land on a second authenticator (the
  // first already holds a credential and is excluded; Chrome allows only one
  // internal authenticator, so this one is a USB key). Chrome's virtual
  // environment stalls the create when the excluded authenticator is
  // present, so silence the first one's presence simulation during the
  // create and re-enable it for the vault-key assertion — stepping the
  // guides by hand to control the timing.
  const auth2 = await addAuthenticator(page, { transport: "usb" });
  const present = (a, enabled) => a.cdp.send("WebAuthn.setAutomaticPresenceSimulation",
    { authenticatorId: a.authenticatorId, enabled });
  const asserted = (a) => new Promise((r) => a.cdp.once("WebAuthn.credentialAsserted", r));
  await page.click("#btn-settings");
  await page.evaluate(() => { window.__noAutoGuide = true; });
  await present(auth, false);
  await page.click("#btn-add-passkey");
  await expect(page.locator("#guide-title")).toHaveText(/step 1 of 3/);
  await page.click("#btn-guide"); // → create on the USB authenticator
  await expect(page.locator("#guide-title")).toHaveText(/step 2 of 3/, { timeout: 15_000 });
  // Now the unlock passkey (internal) must answer alone.
  await present(auth2, false);
  await present(auth, true);
  const unlockAsserted = asserted(auth);
  await page.evaluate(() => { window.__noAutoGuide = false; }); // autoGuide steps the rest
  await unlockAsserted;
  // If the USB key still owes a PRF assertion, it must answer alone.
  await present(auth, false);
  await present(auth2, true);
  await expect(page.locator("#guide-input")).toBeVisible({ timeout: 30_000 });
  // Back to the internal authenticator for the rest of the test.
  await present(auth2, false);
  await present(auth, true);
  await page.fill("#guide-input", "spare key");
  await page.click("#btn-guide");
  await expect(page.locator("#cred-list li")).toHaveCount(2);
  await expect(page.locator("#cred-list")).toContainText("first key"); // named at registration
  await expect(page.locator("#cred-list")).toContainText("spare key");

  // --- rename (prompt auto-answers "renamed key"), then revoke it
  await page.getByRole("button", { name: "Rename spare key" }).click();
  await expect(page.locator("#cred-list")).toContainText("renamed key");
  await page.getByRole("button", { name: "Revoke renamed key" }).click();
  await expect(page.locator("#cred-list li")).toHaveCount(1);

  // --- Bitwarden import: preview with per-type skip counts, then run
  const bw = {
    items: [
      { type: 1, name: "GitHub", login: { username: "carol", password: "pw", uris: [{ uri: "https://github.com" }] } },
      { type: 2, name: "Note", notes: "hello" },
      { type: 3, name: "Visa" },
    ],
  };
  const [chooser] = await Promise.all([page.waitForEvent("filechooser"), page.click("#btn-import")]);
  await chooser.setFiles({ name: "bw.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(bw)) });
  await expect(page.locator("#import-summary")).toContainText("2 entries");
  await expect(page.locator("#import-summary")).toContainText("1 card");
  await expect(page.locator("#import-list li")).toHaveCount(2);
  await page.click("#btn-import-run");
  await expect(page.locator("#browser")).toBeVisible();
  await expect(page.locator("#list li")).toHaveCount(3);

  // --- lock clears the search box; focus lands on the unlock button
  await page.fill("#search", "alp");
  await page.click("#btn-lock");
  await expect(page.locator("#login")).toBeVisible();
  await expect(page.locator("#btn-login")).toBeFocused();

  // --- recover form: focus starts on the username, Enter submits; a
  // well-formed wrong code surfaces the server's message
  await page.click("#btn-show-recover");
  await expect(page.locator("#r-username")).toBeFocused();
  await page.fill("#r-username", "carol");
  await page.fill("#r-code", "aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aaaa");
  await page.locator("#r-code").press("Enter");
  await expect(page.locator("#error")).toContainText("recovery failed", { timeout: 15_000 });

  await page.click("#btn-recover-cancel");
  await page.click("#btn-login");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("#search")).toHaveValue("");
  await expect(page.locator("#list li")).toHaveCount(3);
});

// Failure paths: an authenticator without PRF gets the tailored error, and a
// 401 mid-session locks the vault with an explanation.
test("PRF-unsupported authenticator and session expiry", async ({ page }) => {
  page.on("dialog", (d) => d.accept());
  await autoGuide(page);
  const auth = await addAuthenticator(page, { hasPrf: false });

  await page.goto(`/?invite=${await invite("erin")}`);
  await page.click("#btn-register");
  await expect(page.locator("#error")).toContainText("PRF", { timeout: 15_000 });

  // Fresh PRF-capable authenticator, fresh user; then simulate an expired
  // session on the next API call.
  await auth.cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: auth.authenticatorId });
  await addAuthenticator(page);
  await page.goto(`/?invite=${await invite("frank")}`);
  await page.click("#btn-register");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  await page.click("#btn-code-done");
  await expect(page.locator("#vault")).toBeVisible();
  await page.waitForLoadState("networkidle"); // let the synced-banner check finish first
  await page.route("**/api/credentials", (r) => r.fulfill({ status: 401, body: "session expired" }));
  await page.click("#btn-settings");
  await expect(page.locator("#login")).toBeVisible();
  await expect(page.locator("#error")).toContainText("Session expired");
});

// Idle auto-lock: five minutes without input drops back to the login view.
// The clock is faked only after unlock so the register ceremony (and the
// autoGuide interval) run on real timers; the click re-arms the idle timer
// under the fake clock.
test("auto-lock after five idle minutes", async ({ page }) => {
  page.on("dialog", (d) => d.accept());
  await autoGuide(page);
  await addAuthenticator(page);

  await page.goto(`/?invite=${await invite("grace")}`);
  await page.click("#btn-register");
  await expect(page.locator("#recovery-code")).toBeVisible({ timeout: 15_000 });
  await page.click("#btn-code-done");
  await expect(page.locator("#vault")).toBeVisible();
  await expect(page.locator("#guide")).toBeHidden(); // second-passkey offer auto-declined

  await page.clock.install();
  await page.click("#search");
  await page.clock.fastForward("05:01");
  await expect(page.locator("#login")).toBeVisible();
});
