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
// through them; decline the optional "add a second passkey" offer.
function autoGuide(page) {
  return page.addInitScript(() => {
    setInterval(() => {
      const dlg = document.getElementById("guide");
      if (!dlg?.open) return;
      const title = document.getElementById("guide-title")?.textContent || "";
      if (title.includes("second passkey")) document.getElementById("btn-guide-cancel")?.click();
      else if (document.getElementById("guide-input")?.hidden) document.getElementById("btn-guide")?.click();
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
  await page.click("#btn-logout");
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
  await page.click("#btn-logout");
  await page.click("#btn-show-recover");
  await page.fill("#r-username", USERNAME);
  await page.fill("#r-code", firstCode);
  await page.click("#btn-recover");
  await expect(page.locator("#error")).not.toHaveText("", { timeout: 15_000 });
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
  await page.fill("#totp-login-code", await freshCode(secret));
  await page.click("#btn-totp-login");
  await expect(page.locator("#vault")).toBeVisible({ timeout: 15_000 });
});
