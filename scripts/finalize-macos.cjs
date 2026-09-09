#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { createHash } = require("node:crypto")
const { gunzipSync } = require("node:zlib")
const U = require("./mac-utils.cjs")

function verifyFeed(config, file, expected, notes, yaml, prefix = "") {
  const names = U.names(config), feed = yaml.load(fs.readFileSync(file, "utf8"))
  assert.equal(feed.version, config.version); assert.equal(feed.releaseNotes, notes)
  assert.equal(feed.path, prefix + names.zip); assert.equal(feed.sha512, expected[names.zip].sha512)
  assert.equal(feed.files.length, 2)
  for (const name of [names.zip, names.dmg]) {
    const item = feed.files.find((entry) => entry.url === prefix + name)
    assert(item, `Missing feed entry: ${name}`); assert.equal(item.size, expected[name].size); assert.equal(item.sha512, expected[name].sha512)
  }
}

function verifyManifest(config, directory, expected, notes) {
  const names = U.names(config), manifest = U.readJson(path.join(directory, "release.json"))
  assert.equal(manifest.schemaVersion, 3); assert.equal(manifest.kind, "dfcode-full-app-release")
  assert.equal(manifest.version, config.version); assert.equal(manifest.channel, config.channel)
  assert.deepEqual(manifest.target, { platform: "darwin", arch: "arm64" })
  assert.deepEqual(manifest.source, { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineRepository: `https://github.com/${config.engineRepository}.git` })
  assert.deepEqual(manifest.signing, { status: "signed", teamId: config.mac.teamId, notarized: true })
  assert.equal(manifest.releaseNotes, notes); assert.equal(manifest.feed.path, names.feed)
  assert.deepEqual(manifest.files.map((entry) => entry.path).sort(), [names.dmg, names.zip, names.blockmap, names.feed].sort())
  const roles = { [names.dmg]: "installer", [names.zip]: "archive", [names.blockmap]: "blockmap", [names.feed]: "feed" }
  for (const item of manifest.files) {
    const file = path.join(directory, item.path)
    assert.equal(item.role, roles[item.path]); assert.equal(item.size, fs.statSync(file).size); assert.equal(item.sha256, U.hash(file))
    if (expected[item.path]) assert.equal(item.sha256, expected[item.path].sha256)
  }
  assert.equal(manifest.fileCount, 4); assert.equal(manifest.totalSize, manifest.files.reduce((sum, item) => sum + item.size, 0))
  assert.equal(manifest.releaseHash, `sha256:${createHash("sha256").update(manifest.files.map((item) => `${item.path}:${item.sha256}`).join("\n")).digest("hex")}`)
  return manifest
}

function assess(file, type, policyStatus, command = U.run) {
  const args = ["--assess", "--verbose=4", "--type", type, ...(type === "open" ? ["--context", "context:primary-signature"] : []), file]
  const result = command("/usr/sbin/spctl", args, { allowFailure: true })
  const output = `${result.stdout}\n${result.stderr}`.trim()
  return { policyStatus, exitCode: result.exitCode, output, fullyVerified: policyStatus === "enabled" && result.exitCode === 0 && /\baccepted\b/i.test(output) && /source=Notarized Developer ID/.test(output) && !/override/i.test(output) }
}

function verifyStapled(file, config, command = U.run) {
  if (file.endsWith(".app")) command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", file])
  U.signature(file, config.mac.teamId, command)
  command("/usr/bin/xcrun", ["stapler", "validate", file])
}

async function finalizeMac(config, input, options = {}) {
  const command = options.run || U.run, deps = options.dependencies || U.dependencies(config), names = U.names(config)
  const destination = path.join(config.outputDir, "delivery/mac"), reportFile = path.join(config.outputDir, "reports/mac-final.json")
  const notes = U.normalizeNotes(config.otaNotesFile), binding = U.configBinding(config)
  const signReport = U.readJson(input.signReport), journal = U.readJson(input.stateFile)
  assert.equal(signReport.status, "signed-and-verified"); assert.equal(signReport.configBinding, binding)
  assert.equal(journal.configBinding, binding); assert.equal(journal.notary.app.status, "Accepted"); assert.equal(journal.notary.dmg.status, "Accepted")
  const app = fs.realpathSync(signReport.app), dmg = fs.realpathSync(input.dmg), zip = fs.realpathSync(input.zip)
  U.assertWorkPath(config, app)
  assert.equal(U.hash(dmg), journal.notary.dmg.stapledSha256, "DMG differs from accepted/stapled state")
  assert.deepEqual(U.treeDigest(app), journal.notary.app.stapledAppTree, "App differs from accepted/stapled state")
  const engine = path.join(app, "Contents/Resources/engine/dfcode"), manifestPath = path.join(app, "Contents/Resources/engine/manifest.json")
  assert.equal(U.hash(engine), signReport.signedEngineSha256); assert.equal(U.hash(manifestPath), signReport.manifestSha256)
  verifyStapled(app, config, command); verifyStapled(dmg, config, command)
  if (fs.existsSync(reportFile)) {
    const previous = U.readJson(reportFile)
    if ((previous.status === "delivery-ready" || (previous.status === "failed" && previous.atomicCommitStarted)) && previous.configBinding === binding && fs.existsSync(destination)) {
      assert(previous.files?.length, "Incomplete delivery commit receipt")
      for (const file of previous.files) { assert.equal(fs.statSync(file.path).size, file.size); assert.equal(U.hash(file.path), file.sha256, "Interrupted delivery changed after atomic commit") }
      if (!options.execute) return { status: "preflight-passed", execute: false, recovery: "finish-atomic-delivery-receipt", destination }
      previous.status = "finalized"; previous.recoveredAtomicCommit = true
      U.writeJson(reportFile, previous)
      if (previous.workDirectory && !previous.cleanup) { previous.cleanup = U.trashWork(config, previous.workDirectory, command); U.writeJson(reportFile, previous) }
      return previous
    }
  }
  U.ensureEmpty(destination)
  const plan = { status: "preflight-passed", execute: Boolean(options.execute), destination, artifacts: names, version: config.version, appLaunchTest: "not-performed", realOtaTest: "not-performed" }
  if (!options.execute) return plan
  const workRoot = path.join(config.outputDir, ".work.noindex/mac")
  fs.mkdirSync(workRoot, { recursive: true })
  const temporary = fs.mkdtempSync(path.join(workRoot, "finalize-"))
  U.markOwnedWork(config, temporary)
  let mounted, report = { ...plan, status: "verifying", workDirectory: temporary, configBinding: binding, notaryIds: { app: journal.notary.app.id, dmg: journal.notary.dmg.id }, inputs: { dmg: U.fileInfo(dmg), zip: U.fileInfo(zip) } }
  U.writeJson(reportFile, report)
  try {
    const policy = command("/usr/sbin/spctl", ["--status"], { allowFailure: true })
    const text = `${policy.stdout}\n${policy.stderr}`, status = /assessments enabled/.test(text) ? "enabled" : /assessments disabled/.test(text) ? "disabled" : "unknown"
    report.gatekeeper = { policy: { status, ...policy }, app: assess(app, "execute", status, command), dmg: assess(dmg, "open", status, command) }
    report.gatekeeper.fullyVerified = report.gatekeeper.app.fullyVerified && report.gatekeeper.dmg.fullyVerified
    if (status === "enabled") assert(report.gatekeeper.fullyVerified, "Enabled Gatekeeper did not accept both notarized inputs without overrides")
    const entries = U.zipEntries(zip, config.workspace, command)
    for (const entry of entries) assert(entry.name === "DFCode.app" || entry.name.startsWith("DFCode.app/") || entry.name.startsWith("__MACOSX/"), `Unexpected app ZIP path: ${entry.name}`)
    const extracted = path.join(temporary, "zip"); fs.mkdirSync(extracted)
    command("/usr/bin/ditto", ["-x", "-k", zip, extracted])
    const zipApp = path.join(extracted, "DFCode.app"), tree = U.treeDigest(app)
    verifyStapled(zipApp, config, command); assert.deepEqual(U.treeDigest(zipApp), tree, "ZIP App differs from source App")
    mounted = path.join(temporary, "dmg"); fs.mkdirSync(mounted)
    const attach = command("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mounted, "-plist", dmg])
    assert(deps.plist.parse(attach.stdout)["system-entities"]?.some((item) => item["mount-point"] && fs.realpathSync(item["mount-point"]) === fs.realpathSync(mounted)), "DMG attached at an unexpected mountpoint")
    const link = path.join(mounted, "Applications")
    assert(fs.lstatSync(link).isSymbolicLink()); assert.equal(fs.readlinkSync(link), "/Applications")
    const dmgApp = path.join(mounted, "DFCode.app")
    verifyStapled(dmgApp, config, command); assert.deepEqual(U.treeDigest(dmgApp), tree, "DMG App differs from source App")
    command("/usr/bin/hdiutil", ["detach", mounted]); mounted = undefined
    report.contents = { appTree: tree, zipMatches: true, dmgMatches: true, applicationsLink: "/Applications", detached: true }
    const artifacts = path.join(temporary, "assets"); fs.mkdirSync(artifacts)
    fs.copyFileSync(dmg, path.join(artifacts, names.dmg), fs.constants.COPYFILE_EXCL)
    fs.copyFileSync(zip, path.join(artifacts, names.zip), fs.constants.COPYFILE_EXCL)
    const zipInfo = await deps.buildBlockMap(path.join(artifacts, names.zip), "gzip", path.join(artifacts, names.blockmap))
    const expected = Object.fromEntries([names.dmg, names.zip, names.blockmap].map((name) => [name, U.fileInfo(path.join(artifacts, name))]))
    assert.equal(expected[names.dmg].sha256, report.inputs.dmg.sha256); assert.equal(expected[names.zip].sha256, report.inputs.zip.sha256)
    assert.equal(zipInfo.size, expected[names.zip].size); assert.equal(zipInfo.sha512, expected[names.zip].sha512)
    const blockmap = JSON.parse(gunzipSync(fs.readFileSync(path.join(artifacts, names.blockmap))))
    assert.equal(blockmap.version, "2"); assert.equal(blockmap.files.length, 1); assert.equal(blockmap.files[0].offset, 0)
    assert.equal(blockmap.files[0].sizes.length, blockmap.files[0].checksums.length)
    assert.equal(blockmap.files[0].sizes.reduce((sum, size) => sum + size, 0), expected[names.zip].size)
    const feed = { version: config.version, files: [names.zip, names.dmg].map((name) => ({ url: name, size: expected[name].size, sha512: expected[name].sha512 })), path: names.zip, sha512: expected[names.zip].sha512, releaseDate: new Date().toISOString(), releaseNotes: notes }
    fs.writeFileSync(path.join(artifacts, names.feed), deps.yaml.dump(feed, { lineWidth: -1, noRefs: true }), { flag: "wx" })
    verifyFeed(config, path.join(artifacts, names.feed), expected, notes, deps.yaml)
    const admin = path.join(temporary, "admin")
    command(process.execPath, [path.join(config.workspace, "scripts/prepare-admin-full-ota-release.mjs"), "--artifact-dir", artifacts, "--output-dir", admin, "--channel", config.channel, "--version", config.version, "--platform", "darwin", "--arch", "arm64", "--studio-commit", config.studioCommit, "--engine-commit", config.engineCommit, "--engine-repository", `https://github.com/${config.engineRepository}.git`, "--signing-status", "signed", "--team-id", config.mac.teamId, "--notarized", "true", "--release-notes", config.otaNotesFile])
    verifyFeed(config, path.join(admin, names.feed), expected, notes, deps.yaml, `${config.version}/darwin/arm64/`)
    const manifest = verifyManifest(config, admin, expected, notes)
    const fullOta = path.join(temporary, names.fullOta)
    command("/usr/bin/zip", ["-q", "-0", fullOta, names.dmg, names.zip, names.blockmap, names.feed, "release.json"], { cwd: admin, timeout: 300_000 })
    command("/usr/bin/unzip", ["-tq", fullOta], { timeout: 300_000 })
    assert.deepEqual(U.zipEntries(fullOta, config.workspace, command).map((item) => item.name).sort(), [names.dmg, names.zip, names.blockmap, names.feed, "release.json"].sort())
    const transaction = path.join(temporary, "delivery-transaction"); fs.mkdirSync(transaction)
    for (const name of [names.dmg, names.zip, names.blockmap, names.feed, "release.json"]) fs.copyFileSync(path.join(admin, name), path.join(transaction, name), fs.constants.COPYFILE_EXCL)
    fs.copyFileSync(fullOta, path.join(transaction, names.fullOta), fs.constants.COPYFILE_EXCL)
    verifyFeed(config, path.join(transaction, names.feed), expected, notes, deps.yaml, `${config.version}/darwin/arm64/`)
    verifyManifest(config, transaction, expected, notes)
    report.releaseHash = manifest.releaseHash
    const verification = [
      `# macOS ${config.version} Verification`, "",
      `- Studio source: ${config.studioRepository}@${config.studioCommit}`,
      `- Engine source: ${config.engineRepository}@${config.engineCommit} (${config.engineVersion})`,
      `- Developer ID Team: ${config.mac.teamId}`,
      `- App notarization: Accepted (${report.notaryIds.app})`,
      `- DMG notarization: Accepted (${report.notaryIds.dmg})`,
      "- App and DMG signatures, timestamps and stapled tickets: verified.",
      "- DMG and ZIP contain the same final App; DMG Applications symlink: /Applications.",
      "- Final ZIP/blockmap/feed/Full OTA hashes and source metadata: verified.",
      `- Local Gatekeeper policy: ${status}; full default-policy assessment: ${report.gatekeeper.fullyVerified ? "verified" : "not established"}.`,
      "- App GUI launch and real OTA upgrade: not performed by this automated release flow.",
      "- Expanded App copies use .work.noindex/mac and are unregistered then moved to Trash after open-file checks.",
      "- Original CI archives, notarization upload archives and reports are retained for recovery.", "",
    ].join("\n")
    fs.writeFileSync(path.join(transaction, "MACOS-VERIFICATION.md"), verification, { flag: "wx" })
    report.source = { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }
    report.files = fs.readdirSync(transaction).map((name) => ({ ...U.fileInfo(path.join(transaction, name)), path: path.join(destination, name) }))
    report.status = "delivery-ready"; report.atomicCommitStarted = true; report.transactionDirectory = transaction; U.writeJson(reportFile, report)
    U.ensureEmpty(destination); fs.mkdirSync(path.dirname(destination), { recursive: true })
    fs.renameSync(transaction, destination)
    report.status = "finalized"; report.finishedAt = new Date().toISOString(); U.writeJson(reportFile, report)
    return report
  } catch (error) { report.status = "failed"; report.error = error.message; U.writeJson(reportFile, report); throw error }
  finally {
    if (mounted) command("/usr/bin/hdiutil", ["detach", mounted])
    report.cleanup = U.trashWork(config, temporary, command)
    U.writeJson(reportFile, report)
  }
}

async function cli() {
  const args = U.parseArgs(process.argv.slice(2), ["config", "dmg", "zip", "sign-report", "state"])
  if (args.help) return console.log("Usage: node finalize-macos.cjs --config release.json --dmg final.dmg --zip final.zip --sign-report reports/mac-sign.json --state reports/mac-state.json [--execute]\nWithout --execute: validates existing signing and notarization evidence read-only. Does not mount or write.")
  assert(args.config && args.dmg && args.zip && args["sign-report"] && args.state, "All paths shown by --help are required")
  const config = require("./config.cjs").loadConfig(args.config)
  console.log(JSON.stringify(await finalizeMac(config, { dmg: args.dmg, zip: args.zip, signReport: args["sign-report"], stateFile: args.state }, { execute: args.execute }), null, 2))
}

module.exports = { verifyFeed, verifyManifest, assess, verifyStapled, finalizeMac }
if (require.main === module) cli().catch((error) => { console.error(error.message); process.exitCode = 1 })
