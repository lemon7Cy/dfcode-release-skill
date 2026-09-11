const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { createHash } = require("node:crypto")
const { verifyFullOtaEntries } = require("../scripts/archive.cjs")
const digest = (text, algo = "sha256", encoding = "hex") => createHash(algo).update(text).digest(encoding)

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-manifest-"))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const config = { version: "1.7.3", channel: "beta", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineRepository: "owner/engine", otaNotesFile: path.join(root, "notes.md") }
  fs.writeFileSync(config.otaNotesFile, "Release summary")
  const installer = "DFCode-1.7.3-x64.exe", blockmap = installer + ".blockmap", feedName = "beta.yml"
  const content = { [installer]: "fake unsigned fixture executable", [blockmap]: "fake blockmap fixture" }
  content[feedName] = JSON.stringify({ version: config.version, path: `1.7.3/win32/x64/${installer}`, sha512: digest(content[installer], "sha512", "base64"), releaseNotes: "Release summary", files: [{ url: `1.7.3/win32/x64/${installer}`, sha512: digest(content[installer], "sha512", "base64"), size: Buffer.byteLength(content[installer]) }] })
  const files = Object.entries(content).map(([name, text]) => ({ path: name, size: Buffer.byteLength(text), sha256: digest(text), role: name === installer ? "installer" : name === blockmap ? "blockmap" : "feed" }))
  const manifest = { schemaVersion: 3, kind: "dfcode-full-app-release", version: config.version, channel: config.channel, source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineRepository: "https://github.com/owner/engine.git" }, target: { platform: "win32", arch: "x64" }, signing: { status: "unsigned" }, files, feed: { path: feedName }, fileCount: files.length, totalSize: files.reduce((sum, entry) => sum + entry.size, 0), releaseHash: "sha256:" + digest(files.map((entry) => `${entry.path}:${entry.sha256}`).join("\n")), releaseNotes: "Release summary" }
  const entries = () => Object.entries({ ...content, "release.json": JSON.stringify(manifest) }).map(([name, text]) => ({ name, text, size: Buffer.byteLength(text), sha256: digest(text), sha512: digest(text, "sha512", "base64") }))
  return { config, manifest, content, entries, target: manifest.target }
}
test("valid endpoint pins, manifest, roles and feed hashes match at arbitrary version/channel", (t) => {
  const f = fixture(t)
  assert.equal(verifyFullOtaEntries(f.entries(), f.config, f.target, "unsigned", { load: JSON.parse }).files.length, 4)
})
test("changed executable bytes are rejected without trusting manifest alone", (t) => {
  const f = fixture(t)
  f.content["DFCode-1.7.3-x64.exe"] += "modified"
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "unsigned", { load: JSON.parse }), /hash mismatch/)
})
test("wrong source repo, wrong file role and stale notes cannot pass", (t) => {
  const f = fixture(t)
  f.manifest.source.engineRepository = "unrelated/engine"
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "unsigned", { load: JSON.parse }), /repository mismatch/)
  f.manifest.source.engineRepository = "owner/engine"
  f.manifest.files[0].role = "archive"
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "unsigned", { load: JSON.parse }))
  f.manifest.files[0].role = "installer"
  fs.writeFileSync(f.config.otaNotesFile, "Other release summary")
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "unsigned", { load: JSON.parse }))
})

test("signed Windows manifests require the configured publisher rather than a signed flag alone", (t) => {
  const f = fixture(t)
  f.manifest.signing = { status: "signed", publisherName: "Trusted Publisher" }
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "signed", { load: JSON.parse }), /configured publisher/)
  f.config.windows = { publisherName: "Trusted Publisher" }
  assert.equal(verifyFullOtaEntries(f.entries(), f.config, f.target, "signed", { load: JSON.parse }).signing.publisherName, "Trusted Publisher")
  f.manifest.signing.publisherName = "Another Publisher"
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "signed", { load: JSON.parse }), /publisher mismatch/)
  f.manifest.signing = { status: "unsigned" }
  assert.throws(() => verifyFullOtaEntries(f.entries(), f.config, f.target, "signed", { load: JSON.parse }))
})
