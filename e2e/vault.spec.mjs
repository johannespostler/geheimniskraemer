// End-to-end test of the passkey flows, using Chromium's virtual
// authenticator (CDP WebAuthn domain) with PRF support. Builds the gk binary,
// starts it against a throwaway database, and walks the whole journey:
// register → recovery code → entry → lock/login → new recovery code →
// lose the passkey → recover with the code.
import { test, expect } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const ORIGIN = "http://localhost:8199";
const USERNAME = "alice";

let dir, server, inviteToken;

test.beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "gk-e2e-"));
  const bin = join(dir, "gk");
  const db = join(dir, "gk.db");
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
async function addAuthenticator(page) {
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
