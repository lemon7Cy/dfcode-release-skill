"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const U = require("../scripts/mac-utils.cjs")
const S = require("../scripts/sign-macos.cjs")
const F = require("../scripts/finalize-macos.cjs")
const M = require("../scripts/mac-release.cjs")

function directory(t) { const result = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "mac-helper-test-"))); t.after(() => fs.rmSync(result, { recursive: true, force: true })); return result }

test("single ignore callback preserves Engine skip; libraries receive empty entitlements", (t) => {
  const root = directory(t), app = path.join(root, "Test.app"), library = path.join(app, "test.dylib"), engine = path.join(app, "engine"), main = path.join(app, "main"), resource = path.join(app, "image.png")
  fs.mkdirSync(app)
  for (const file of [library, engine, main]) fs.writeFileSync(file, Buffer.from("cffaedfe00000000", "hex"))
  fs.writeFileSync(resource, "not native")
  const opts = S.signingOptions(app, engine, { apps: [app], entrypoints: new Set([main, engine]) }, () => ({ stdout: "Mach-O 64-bit executable arm64" }))
  assert.equal(typeof opts.ignore, "function"); assert(!Array.isArray(opts.ignore))
  assert(opts.ignore(engine)); assert(opts.ignore(resource)); assert(!opts.ignore(library)); assert(!opts.ignore(app))
  assert.deepEqual(opts.optionsForFile(library).entitlements, [])
  assert.deepEqual(opts.optionsForFile(main).entitlements, U.ENTITLEMENTS)
  assert.deepEqual(opts.optionsForFile(app).entitlements, U.ENTITLEMENTS)
})

test("identity selection requires a unique valid Team match", () => {
  const team = "TESTTEAM01", identity = "A".repeat(40), other = "B".repeat(40)
  const config = { mac: { teamId: team, identity: "" } }
  const line = (hash) => `  1) ${hash} "Developer ID Application: Fixture (${team})"`
  assert.equal(S.selectIdentity(config, () => ({ stdout: line(identity) })).fingerprint, identity)
  assert.throws(() => S.selectIdentity(config, () => ({ stdout: `${line(identity)}\n${line(other)}` })), /Expected one/)
  assert.equal(S.selectIdentity({ mac: { ...config.mac, identity: other } }, () => ({ stdout: `${line(identity)}\n${line(other)}` })).fingerprint, other)
})

test("Gatekeeper disabled or override does not become full verification", () => {
  const accepted = () => ({ exitCode: 0, stdout: "", stderr: "accepted\nsource=Notarized Developer ID" })
  assert.equal(F.assess("fixture.app", "execute", "disabled", accepted).fullyVerified, false)
  assert.equal(F.assess("fixture.app", "execute", "enabled", accepted).fullyVerified, true)
  assert.equal(F.assess("fixture.app", "execute", "enabled", () => ({ exitCode: 0, stdout: "", stderr: "accepted (override)\nsource=Notarized Developer ID" })).fullyVerified, false)
})

test("tree digest does not follow framework symlink loops and rejects escaping links", (t) => {
  const root = directory(t), source = path.join(root, "source"), copy = path.join(root, "copy")
  fs.mkdirSync(source); fs.writeFileSync(path.join(source, "file"), "body"); fs.symlinkSync(".", path.join(source, "Current"))
  fs.cpSync(source, copy, { recursive: true, verbatimSymlinks: true })
  assert.deepEqual(U.treeDigest(source), U.treeDigest(copy))
  fs.symlinkSync("../", path.join(source, "escape"))
  assert.throws(() => U.treeDigest(source), /escapes application/)
})

test("output protection refuses nonempty directories and symlink ancestors", (t) => {
  const root = directory(t), nonempty = path.join(root, "nonempty"), linked = path.join(root, "linked")
  fs.mkdirSync(nonempty); fs.writeFileSync(path.join(nonempty, "preserve"), "user bytes"); fs.symlinkSync(nonempty, linked)
  assert.throws(() => U.ensureEmpty(nonempty), /non-empty/)
  assert.throws(() => U.ensureEmpty(path.join(linked, "new"), true), /Symlink/)
  assert.equal(fs.readFileSync(path.join(nonempty, "preserve"), "utf8"), "user bytes")
})

test("trash is restricted to owned work; unregister happens before trash", (t) => {
  const root = directory(t), config = { outputDir: root }, work = path.join(root, ".work.noindex/mac/run"), app = path.join(work, "app/Test.app")
  fs.mkdirSync(app, { recursive: true })
  U.markOwnedWork(config, work)
  const calls = []
  assert.throws(() => U.trashWork(config, root, () => {}), /must be beneath/)
  const result = U.trashWork(config, work, (command, args) => { calls.push([command, args]); if (command === "/usr/bin/trash") fs.renameSync(args[0], path.join(root, "mock-trash")); return { exitCode: 0, stdout: "", stderr: "" } })
  assert.equal(result.appsUnregistered, 1); assert.equal(calls[0][0], "/usr/sbin/lsof"); assert(calls[1][0].endsWith("lsregister")); assert.equal(calls[2][0], "/usr/bin/trash")
  assert(fs.existsSync(work))
})

test("cleanup refuses unowned or open work files", (t) => {
  const root = directory(t), config = { outputDir: root }, work = path.join(root, ".work.noindex/mac/run")
  fs.mkdirSync(work, { recursive: true })
  assert.throws(() => U.trashWork(config, work, () => {}), /ENOENT/)
  U.markOwnedWork(config, work)
  assert.throws(() => U.trashWork(config, work, () => ({ exitCode: 0, stdout: `p123\nn${work}/open-file\n`, stderr: "" })), /in use/)
})

test("noindex App already absent from LaunchServices can still be moved to Trash", (t) => {
  const root = directory(t), config = { outputDir: root }, work = path.join(root, ".work.noindex/mac/run"), app = path.join(work, "Test.app")
  fs.mkdirSync(app, { recursive: true }); U.markOwnedWork(config, work)
  const result = U.trashWork(config, work, (command, args) => {
    if (command.endsWith("lsregister")) return { exitCode: 1, stdout: `failed to scan ${app}: -10814\n from spotlight`, stderr: "" }
    if (command === "/usr/bin/trash") fs.renameSync(args[0], path.join(root, "mock-trash"))
    return { exitCode: 0, stdout: "", stderr: "" }
  })
  assert.equal(result.unregister[0].status, "already-unregistered")
})

test("help works without config and without side-effecting programs", () => {
  for (const script of ["sign-macos", "finalize-macos", "mac-release"]) {
    const result = spawnSync(process.execPath, [path.join(__dirname, `../scripts/${script}.cjs`), "--help"], { encoding: "utf8", env: { PATH: "", HOME: os.homedir() } })
    assert.equal(result.status, 0, result.stderr); assert.match(result.stdout, /Usage:/)
  }
})

test("generated filenames and feed checks use configured versions and channels", (t) => {
  const root = directory(t), config = { version: "9.8.7-rc.4", channel: "beta" }, names = U.names(config)
  assert.equal(names.feed, "beta-mac.yml"); assert.match(names.dmg, /9\.8\.7-rc\.4/)
  const feed = { version: config.version, releaseNotes: "fixture", path: names.zip, sha512: "zip", files: [{ url: names.zip, sha512: "zip", size: 1 }, { url: names.dmg, sha512: "dmg", size: 2 }] }
  const file = path.join(root, "feed"); fs.writeFileSync(file, JSON.stringify(feed))
  const expected = { [names.zip]: { size: 1, sha512: "zip" }, [names.dmg]: { size: 2, sha512: "dmg" } }
  F.verifyFeed(config, file, expected, "fixture", { load: JSON.parse })
  feed.files[0].size = 3; fs.writeFileSync(file, JSON.stringify(feed))
  assert.throws(() => F.verifyFeed(config, file, expected, "fixture", { load: JSON.parse }))
})

test("default driver mode stops after read-only preflight without writing or running commands", async (t) => {
  const root = directory(t), config = { outputDir: path.join(root, "not-created") }
  const report = await M.macRelease(config, { check: () => ({ plan: { version: "9.8.7" } }), run() { throw Error("unexpected execution") } })
  assert.equal(report.status, "planned"); assert.equal(report.execute, false); assert(!fs.existsSync(config.outputDir))
})

test("input binding rejects modified expanded App bytes before normalization", (t) => {
  const root = directory(t), app = path.join(root, ".work.noindex/mac/run/DFCode.app"), archive = path.join(root, "unsigned-ci/input.zip"), notes = path.join(root, "notes.md")
  fs.mkdirSync(app, { recursive: true }); fs.mkdirSync(path.dirname(archive)); fs.mkdirSync(path.join(root, "reports"))
  fs.writeFileSync(path.join(app, "file"), "original"); fs.writeFileSync(archive, "archive fixture"); fs.writeFileSync(notes, "fixture notes")
  const config = { version: "9.8.7", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineVersion: "1.2.3", outputDir: root, otaNotesFile: notes, mac: {} }
  const reportFile = path.join(root, "reports/verify-ci.json")
  fs.writeFileSync(reportFile, JSON.stringify({ status: "verified", version: config.version, source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, artifacts: [{ path: archive, sha256: U.hash(archive), kind: "full-ota", target: { platform: "darwin", arch: "arm64" } }] }))
  const binding = { status: "ci-input-bound", configBinding: U.configBinding(config), archive, archiveSha256: U.hash(archive), verifyCiSha256: U.hash(reportFile), appTree: U.treeDigest(app) }
  S.validateInputBinding(config, app, binding)
  fs.writeFileSync(path.join(app, "file"), "modified")
  assert.throws(() => S.validateInputBinding(config, app, binding), /Expanded App differs/)
})
