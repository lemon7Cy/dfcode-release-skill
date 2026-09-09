const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { spawnSync } = require("node:child_process")
const { parse, chooseVersion, routeHost, macPublicationInputs, assertExistingRelease } = require("../scripts/release.cjs")
const { normalizeConfig } = require("../scripts/config.cjs")
const { hashFile } = require("../scripts/io.cjs")

test("version selection uses stable releases, not draft or prerelease labels", () => {
  const releases = [{ tagName: "studio-v0.2.26", isDraft: false, isPrerelease: false }, { tagName: "studio-v0.2.28", isDraft: true }, { tagName: "studio-v0.2.99", isPrerelease: true }]
  assert.equal(chooseVersion("0.2.25", releases), "0.2.27")
  assert.equal(chooseVersion("0.3.0", releases), "0.3.0")
  assert.throws(() => chooseVersion("0.1.0", []))
})
test("native routing never attempts Mac signing on Windows or unsupported hosts", () => {
  assert.equal(routeHost("darwin", "arm64"), "mac-release.cjs")
  assert.equal(routeHost("win32", "x64"), "windows-release.cjs")
  assert.equal(routeHost("darwin", "x64"), null)
  assert.equal(routeHost("linux", "x64"), null)
})
test("flags cannot silently accept typos or missing values", () => {
  assert.throws(() => parse(["prepare", "--config"]))
  assert.throws(() => parse(["publish", "--force"]))
  assert(parse(["sign", "--config", "config.json", "--execute", "--resume"]).flags.has("--resume"))
})
test("prepare without execute produces a plan and creates no workspace/output", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-plan-test-"))
  try {
    const config = { version: "0.9.3", studioCommit: "1".repeat(40), engineCommit: "2".repeat(40), engineVersion: "3.9.1", workspace: "workspace", outputDir: "output", releaseNotesFile: "notes.md", otaNotesFile: "ota.md" }
    fs.writeFileSync(path.join(temp, "config.json"), JSON.stringify(config))
    const result = spawnSync(process.execPath, [path.resolve(__dirname, "../scripts/release.cjs"), "prepare", "--config", path.join(temp, "config.json")], { encoding: "utf8", env: { ...process.env, PATH: "/nonexistent" } })
    assert.equal(result.status, 0, result.stderr)
    assert.equal(JSON.parse(result.stdout).mode, "plan-only")
    assert.deepEqual(fs.readdirSync(temp), ["config.json"])
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
})

test("publication consumes nested Mac delivery with explicit signed aliases and rejects altered bytes", () => {
  const temp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-native-publish-")))
  try {
    const config = normalizeConfig({ version: "1.8.2", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineVersion: "3.8.1", workspace: path.join(temp, "workspace"), outputDir: path.join(temp, "output"), releaseNotesFile: path.join(temp, "full.md"), otaNotesFile: path.join(temp, "ota.md") })
    fs.writeFileSync(config.otaNotesFile, "Actual notes")
    assert.throws(() => macPublicationInputs(config), /signing has not produced/)
    const native = path.join(config.outputDir, "delivery", "mac"), reports = path.join(config.outputDir, "reports")
    fs.mkdirSync(native, { recursive: true }); fs.mkdirSync(reports, { recursive: true })
    const names = ["DFCode-1.8.2-arm64.dmg", "DFCode-1.8.2-darwin-arm64-full-ota-signed-notarized.zip"]
    const files = names.map((name) => {
      const file = path.join(native, name); fs.writeFileSync(file, name)
      return { path: file, size: fs.statSync(file).size, sha256: hashFile(file) }
    })
    fs.writeFileSync(path.join(reports, "mac-final.json"), JSON.stringify({ status: "finalized", configBinding: require("../scripts/mac-utils.cjs").configBinding(config), notaryIds: { app: "test-app-id", dmg: "test-dmg-id" }, files }))
    const selected = macPublicationInputs(config)
    assert.equal(selected.files[0].name, "DFCode-1.8.2-arm64-signed-notarized.dmg")
    assert.equal(selected.files[1].path, files[1].path)
    fs.appendFileSync(files[0].path, "changed")
    assert.throws(() => macPublicationInputs(config))
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
})
test("existing public Release cannot be changed through draft-only authorization", () => {
  const config = { version: "1.0.0", studioRepository: "owner/studio", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40) }
  assert.throws(() => assertExistingRelease(config, { isDraft: false }, { flags: new Set() }, () => { throw Error("must not reach network") }), /already published/)
  assertExistingRelease(config, { isDraft: false, targetCommitish: "main" }, { flags: new Set(["--publish-release"]) }, () => ({ object: { type: "commit", sha: config.studioCommit } }))
  assert.throws(() => assertExistingRelease(config, { isDraft: false, targetCommitish: config.studioCommit }, { flags: new Set(["--publish-release"]) }, () => ({ object: { type: "commit", sha: "c".repeat(40) } })), /another source/)
})
