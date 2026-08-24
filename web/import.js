// @ts-check
// Bitwarden unencrypted-JSON export → vault entries. Pure mapping, no I/O.

const TYPE_LABELS = { 3: "card", 4: "identity", 5: "SSH key" };

// Returns {entries, skipped} where skipped is {label: count}. Nothing is
// silently dropped from imported items: extra URIs that don't fit our
// fields are appended to notes.
export function mapBitwarden(json) {
  if (json?.encrypted === true) {
    throw new Error("This is an encrypted export — create an unencrypted JSON export in Bitwarden.");
  }
  if (!Array.isArray(json?.items)) {
    throw new Error("This does not look like a Bitwarden export (no items array).");
  }
  const entries = [];
  const skipped = {};
  for (const it of json.items) {
    if (it.type === 1) { // login
      const uris = (it.login?.uris || []).map((u) => u?.uri).filter(Boolean);
      const extra = [];
      if (uris.length > 1) extra.push("Other URLs:\n" + uris.slice(1).join("\n"));
      entries.push({
        name: it.name || "",
        website: uris[0] || "",
        username: it.login?.username || "",
        password: it.login?.password || "",
        totp: it.login?.totp || "",
        notes: [it.notes, ...extra].filter(Boolean).join("\n\n"),
      });
    } else if (it.type === 2) { // secure note
      entries.push({ name: it.name || "", website: "", username: "", password: "", totp: "", notes: it.notes || "" });
    } else {
      const label = TYPE_LABELS[it.type] || `type ${it.type}`;
      skipped[label] = (skipped[label] || 0) + 1;
    }
  }
  return { entries, skipped };
}
