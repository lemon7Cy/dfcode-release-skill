const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { spawnSync } = require("node:child_process")
const { parse, chooseVersion, routeHost, nativeSigningArguments, macPublicationInputs, windowsPublicationInputs, assertExistingRelease } = require("../scripts/release.cjs")
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

test("Windows native signing explicitly requests signing and passes resume without changing the handoff command", () => {
  const file = path.resolve("release.json")
  const windows = nativeSigningArguments(file, true, "win32", "x64")
  assert.equal(path.basename(windows[0]), "windows-release.cjs")
  assert.deepEqual(windows.slice(1), ["--config", file, "--sign", "--execute", "--resume"])
  const mac = nativeSigningArguments(file, false, "darwin", "arm64")
  assert.equal(path.basename(mac[0]), "mac-release.cjs")
  assert.deepEqual(mac.slice(1), ["--config", file, "--execute"])
  assert.throws(() => nativeSigningArguments(file, false, "win32", "arm64"), /Windows x64/)
})
test("flags cannot silently accept typos or missing values", () => {
  assert.throws(() => parse(["prepare", "--config"]))
  assert.throws(() => parse(["publish", "--force"]))
  assert(parse(["sign", "--config", "config.json", "--execute", "--resume"]).flags.has("--resume"))
})
test("prepare and sign without execute produce plans and create no workspace/output", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-plan-test-"))
  try {
    const config = { version: "0.9.3", studioCommit: "1".repeat(40), engineCommit: "2".repeat(40), engineVersion: "3.9.1", workspace: "workspace", outputDir: "output", releaseNotesFile: "notes.md", otaNotesFile: "ota.md" }
    fs.writeFileSync(path.join(temp, "config.json"), JSON.stringify(config))
    for (const command of ["prepare", "sign"]) {
      const result = spawnSync(process.execPath, [path.resolve(__dirname, "../scripts/release.cjs"), command, "--config", path.join(temp, "config.json")], { encoding: "utf8", env: { ...process.env, PATH: "/nonexistent" } })
      assert.equal(result.status, 0, result.stderr)
      assert.equal(JSON.parse(result.stdout).mode, "plan-only")
    }
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

test("Windows publication binds source, certificate, notes and exact native delivery bytes", (t) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-windows-publish-")))
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  const config = normalizeConfig({ version: "1.8.2", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineVersion: "3.8.1", workspace: path.join(root, "workspace"), outputDir: path.join(root, "output"), releaseNotesFile: path.join(root, "full.md"), otaNotesFile: path.join(root, "ota.md"), windows: { publisherName: "Fixture Publisher", certificateSha1: "c".repeat(40), keypairAlias: "fixture_key" } })
  fs.writeFileSync(config.releaseNotesFile, "Full notes")
  fs.writeFileSync(config.otaNotesFile, "OTA notes")
  assert.throws(() => windowsPublicationInputs(config), /signing has not produced/)
  const native = path.join(config.outputDir, "delivery", "windows"), reports = path.join(config.outputDir, "reports")
  fs.mkdirSync(native, { recursive: true }); fs.mkdirSync(reports, { recursive: true })
  const files = ["DFCode-1.8.2-x64.exe", "DFCode-1.8.2-win32-x64-full-ota-signed.zip"].map((name) => {
    const file = path.join(native, name); fs.writeFileSync(file, `fixture ${name}`)
    return { path: file, size: fs.statSync(file).size, sha256: hashFile(file) }
  })
  const report = { schemaVersion: 1, status: "finalized", version: config.version, configBinding: require("../scripts/windows-release.cjs").configBinding(config), source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, build: { repository: config.buildRepository }, signing: { status: "signed", publisherName: config.windows.publisherName, certificateSha1: config.windows.certificateSha1 }, files, acceptance: { installed: false, actualOta: false } }
  const reportFile = path.join(reports, "windows-final.json")
  const save = () => fs.writeFileSync(reportFile, JSON.stringify(report))
  save()
  const selected = windowsPublicationInputs(config)
  assert.equal(selected.files[0].name, "DFCode-1.8.2-x64-signed.exe")
  assert.equal(selected.files[1].path, files[1].path)
  report.signing.publisherName = "Wrong Publisher"; save()
  assert.throws(() => windowsPublicationInputs(config), /publisher mismatch/)
  report.signing.publisherName = config.windows.publisherName
  report.signing.certificateSha1 = "e".repeat(40); save()
  assert.throws(() => windowsPublicationInputs(config), /certificate mismatch/)
  report.signing.certificateSha1 = config.windows.certificateSha1
  report.source.studioCommit = "d".repeat(40); save()
  assert.throws(() => windowsPublicationInputs(config), /studioCommit mismatch/)
  report.source.studioCommit = config.studioCommit
  const outsideFile = path.join(root, path.basename(files[0].path))
  fs.copyFileSync(files[0].path, outsideFile)
  const expectedPath = files[0].path
  files[0].path = outsideFile; save()
  assert.throws(() => windowsPublicationInputs(config), /outside this release/)
  files[0].path = expectedPath
  report.status = "signing"; save()
  assert.throws(() => windowsPublicationInputs(config))
  report.status = "finalized"; save()
  fs.appendFileSync(config.otaNotesFile, " changed")
  assert.throws(() => windowsPublicationInputs(config), /different source\/config\/notes/)
  fs.writeFileSync(config.otaNotesFile, "OTA notes")
  fs.appendFileSync(files[0].path, " changed")
  assert.throws(() => windowsPublicationInputs(config))
})
