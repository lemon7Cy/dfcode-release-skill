#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const U = require("./mac-utils.cjs")
const S = require("./sign-macos.cjs")
const F = require("./finalize-macos.cjs")

function ciArtifact(config) {
  const reportFile = path.join(config.outputDir, "reports/verify-ci.json"), report = U.readJson(reportFile)
  assert.equal(report.schemaVersion, 1); assert.equal(report.status, "verified"); assert.equal(report.version, config.version)
  assert.equal(report.source.studioCommit, config.studioCommit); assert.equal(report.source.engineCommit, config.engineCommit); assert.equal(report.source.engineVersion, config.engineVersion)
  assert.equal(report.build.repository, config.buildRepository)
  const matches = report.artifacts.filter((item) => item.kind === "full-ota" && item.target?.platform === "darwin" && item.target?.arch === "arm64")
  assert.equal(matches.length, 1, "Expected exactly one verified macOS Full OTA input")
  const artifact = matches[0]
  assert.equal(path.basename(artifact.path), `DFCode-${config.version}-darwin-arm64-full-ota-unsigned.zip`)
  assert(U.within(path.join(config.outputDir, "unsigned-ci"), fs.realpathSync(artifact.path)), "Input archive is outside unsigned-ci")
  assert.equal(fs.statSync(artifact.path).size, artifact.size); assert.equal(U.hash(artifact.path), artifact.sha256, "CI input bytes no longer match their verification report")
  return { artifact, reportFile, reportSha256: U.hash(reportFile), build: report.build }
}

function validateFullOta(config, archive, command = U.run) {
  const entries = U.zipEntries(archive, config.workspace, command)
  for (const item of entries) assert(!item.symlink && !item.name.includes("/"), `Full OTA must contain only root-level ordinary files: ${item.name}`)
  const manifest = JSON.parse(command("/usr/bin/unzip", ["-p", archive, "release.json"]).stdout)
  assert.equal(manifest.kind, "dfcode-full-app-release"); assert.equal(manifest.schemaVersion, 3)
  assert.equal(manifest.version, config.version); assert.equal(manifest.channel, config.channel)
  assert.deepEqual(manifest.target, { platform: "darwin", arch: "arm64" })
  assert.equal(manifest.source.studioCommit, config.studioCommit); assert.equal(manifest.source.engineCommit, config.engineCommit)
  if (manifest.source.engineRepository !== undefined) assert.equal(manifest.source.engineRepository, `https://github.com/${config.engineRepository}.git`)
  assert.equal(manifest.signing.status, "unsigned")
  assert(Array.isArray(manifest.files) && manifest.files.length >= 3)
  for (const item of manifest.files) {
    assert(item.path === path.basename(item.path) && /^[a-f0-9]{64}$/.test(item.sha256), "Invalid manifest asset")
    assert(entries.some((entry) => entry.name === item.path && entry.size === item.size), `Missing or incorrectly sized input asset: ${item.path}`)
  }
  assert.equal(manifest.files.filter((item) => item.role === "archive").length, 1)
  return manifest
}

function check(config, options = {}) {
  assert.equal(process.platform, "darwin", "Mac release commands require macOS")
  assert.equal(process.arch, "arm64", "Mac signing currently supports an Apple Silicon host only")
  const command = options.run || U.run
  U.noSymlinkAncestors(config.outputDir)
  assert.equal(command("git", ["-C", config.workspace, "rev-parse", "HEAD"]).stdout.trim(), config.studioCommit, "Workspace is not the pinned Studio commit")
  const modified = command("git", ["-C", config.workspace, "diff", "HEAD", "--name-only", "--", "bun.lock", "packages/desktop/package.json", "scripts/engine-contract.mjs", "scripts/prepare-admin-full-ota-release.mjs"]).stdout.trim()
  assert.equal(modified, "", "Tracked signing dependencies or packaging helpers differ from the pinned source")
  const deps = U.dependencies(config), identity = S.selectIdentity(config, command)
  const input = ciArtifact(config), manifest = validateFullOta(config, input.artifact.path, command)
  U.normalizeNotes(config.otaNotesFile)
  for (const file of ["/usr/bin/codesign", "/usr/bin/hdiutil", "/usr/bin/trash", "/usr/bin/ditto", "/usr/bin/zip"]) assert(fs.existsSync(file), `Missing macOS tool: ${file}`)
  command("/usr/bin/xcrun", ["--find", "notarytool"])
  return { deps, identity, input, manifest, plan: { version: config.version, source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, input: input.artifact, identity, profile: config.mac.notaryProfile, workDirectory: path.join(config.outputDir, ".work.noindex/mac"), deliveryDirectory: path.join(config.outputDir, "delivery/mac"), actions: ["Verify CI bytes and complete ad-hoc signatures", "Sign Engine and application; verify all native code", "Submit App once, persist submission ID, staple on acceptance", "Create Applications-link DMG; sign, notarize once and staple", "Recreate final ZIP, blockmap, feed and Full OTA", "Verify final contents without launching an application", "Unregister and move only this run's expanded copies to Trash"] } }
}

function archiveApp(app, zip, command = U.run) {
  if (!fs.existsSync(zip)) {
    const temporary = `${zip}.${process.pid}.partial`
    command("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "--keepParent", app, temporary], { timeout: 300_000 })
    fs.renameSync(temporary, zip)
  }
  command("/usr/bin/unzip", ["-tq", zip], { timeout: 300_000 })
}

function submissionResult(output) {
  const value = JSON.parse(output)
  assert(typeof value.id === "string" && /^[0-9a-f-]{36}$/i.test(value.id), "notarytool did not return a valid submission ID")
  return value
}

function ensureNotarized(config, state, key, file, save, options = {}) {
  const command = options.run || U.run, nowHash = U.hash(file)
  let entry = state.notary[key]
  if (entry) {
    if (entry.status === "Accepted" && entry.sha256 !== nowHash && entry.stapledSha256 !== nowHash && key === "dmg" && options.recoverAcceptedDmg) {
      options.recoverAcceptedDmg(file, state)
      entry.stapledSha256 = nowHash; entry.recoveredStapleReceipt = true; save()
    }
    assert(entry.sha256 === nowHash || (entry.status === "Accepted" && entry.stapledSha256 === nowHash), "Notary input bytes changed; refusing to reuse or resubmit the ID")
    assert.equal(entry.path, file, "Notary input path changed")
    if (entry.status === "Accepted") return entry
    assert(entry.id, `Previous ${key} submission has an unknown result. Recover its ID from Apple history and use --recover-${key}-id; do not submit again.`)
    assert(entry.status !== "Invalid" && entry.status !== "Rejected", `Apple rejected ${key} submission ${entry.id}; inspect its saved log before preparing a new release`)
  } else {
    entry = state.notary[key] = { path: file, sha256: nowHash, status: "submission-unknown", submittedAt: new Date().toISOString() }
    save()
    // Persist the intent before the external call. An ambiguous timeout must never auto-resubmit.
    const submitted = command("/usr/bin/xcrun", ["notarytool", "submit", file, "--keychain-profile", config.mac.notaryProfile, "--output-format", "json"], { timeout: 300_000 })
    const result = submissionResult(submitted.stdout)
    entry.id = result.id; entry.status = result.status || "In Progress"; save()
  }
  const info = submissionResult(command("/usr/bin/xcrun", ["notarytool", "info", entry.id, "--keychain-profile", config.mac.notaryProfile, "--output-format", "json"]).stdout)
  assert.equal(info.id, entry.id); entry.status = info.status; entry.checkedAt = new Date().toISOString(); save()
  if (entry.status === "In Progress") {
    const wait = command("/usr/bin/xcrun", ["notarytool", "wait", entry.id, "--keychain-profile", config.mac.notaryProfile, "--timeout", "60s", "--output-format", "json"], { timeout: 75_000, allowFailure: true })
    if (wait.exitCode === 0) { const result = submissionResult(wait.stdout); assert.equal(result.id, entry.id); entry.status = result.status; save() }
    else { entry.lastWait = { exitCode: wait.exitCode, stderr: wait.stderr.slice(0, 1000) }; save() }
  }
  if (entry.status === "Invalid" || entry.status === "Rejected") {
    const log = command("/usr/bin/xcrun", ["notarytool", "log", entry.id, "--keychain-profile", config.mac.notaryProfile, "--output-format", "json"], { allowFailure: true })
    entry.rejectionLog = log.stdout || log.stderr; save()
    throw new Error(`Apple ${entry.status}: ${entry.id}. Rejection log recorded; no automatic resubmission.`)
  }
  assert.equal(entry.status, "Accepted", `Apple submission ${entry.id} is pending. Resume with --execute --resume; its ID will be reused.`)
  return entry
}

function recoverAcceptedDmg(config, file, state, command = U.run) {
  assert(state.notary.app.stapledAppTree, "App staple evidence is required for DMG recovery")
  F.verifyStapled(file, config, command)
  const root = path.join(config.outputDir, ".work.noindex/mac")
  const temporary = fs.mkdtempSync(path.join(root, "recover-staple-")); U.markOwnedWork(config, temporary)
  const mount = path.join(temporary, "mount"); fs.mkdirSync(mount)
  let attempted = false
  try {
    attempted = true
    const output = command("/usr/bin/hdiutil", ["attach", "-readonly", "-nobrowse", "-noautoopen", "-mountpoint", mount, "-plist", file])
    const info = U.dependencies(config).plist.parse(output.stdout)
    assert(info["system-entities"]?.some((entry) => entry["mount-point"] && fs.realpathSync(entry["mount-point"]) === fs.realpathSync(mount)), "Recovered DMG mounted unexpectedly")
    const link = path.join(mount, "Applications")
    assert(fs.lstatSync(link).isSymbolicLink()); assert.equal(fs.readlinkSync(link), "/Applications")
    const app = path.join(mount, "DFCode.app")
    F.verifyStapled(app, config, command)
    assert.deepEqual(U.treeDigest(app), state.notary.app.stapledAppTree, "Recovered DMG App differs from the accepted/stapled source")
  } finally {
    if (attempted) command("/usr/bin/hdiutil", ["detach", mount])
    U.trashWork(config, temporary, command)
  }
}

function verifyDelivery(report) {
  assert.equal(report.status, "finalized")
  for (const file of report.files) { assert.equal(fs.statSync(file.path).size, file.size); assert.equal(U.hash(file.path), file.sha256, `Final delivery changed: ${file.path}`) }
}

async function macRelease(config, options = {}) {
  const command = options.run || U.run, checked = (options.check || check)(config, { run: command })
  if (!options.execute) return { status: "planned", execute: false, ...checked.plan }
  const stateFile = path.join(config.outputDir, "reports/mac-state.json"), workRoot = path.join(config.outputDir, ".work.noindex/mac")
  const binding = U.configBinding(config)
  let state
  if (fs.existsSync(stateFile)) {
    assert(options.resume, "A Mac release state already exists. Use --resume to reuse it; old output is never overwritten")
    state = U.readJson(stateFile); assert.equal(state.configBinding, binding, "Release config or notes changed; use a new outputDir")
    assert.equal(state.input.sha256, checked.input.artifact.sha256)
  } else {
    assert(!options.resume, "No prior Mac release state exists")
    U.ensureEmpty(path.join(config.outputDir, "delivery/mac"))
    fs.mkdirSync(workRoot, { recursive: true })
    state = { schemaVersion: 1, configBinding: binding, version: config.version, input: checked.input.artifact, build: checked.input.build, phase: "prepared", notary: {}, createdAt: new Date().toISOString() }
  }
  const save = () => U.writeJson(stateFile, state)
  const processLock = `${stateFile}.lock`
  U.noSymlinkAncestors(processLock)
  fs.mkdirSync(path.dirname(processLock), { recursive: true })
  if (fs.existsSync(processLock)) {
    const lock = U.readJson(processLock)
    let alive = true; try { process.kill(lock.pid, 0) } catch (error) { if (error.code === "ESRCH") alive = false }
    assert(!alive && options.resume, "Another Mac release process may be active")
    fs.unlinkSync(processLock)
  }
  fs.writeFileSync(processLock, JSON.stringify({ pid: process.pid }), { flag: "wx", mode: 0o600 })
  try {
    save()
    if (options.recoverAppId || options.recoverDmgId) {
      for (const [key, id] of [["app", options.recoverAppId], ["dmg", options.recoverDmgId]]) {
        if (!id) continue
        assert(/^[0-9a-f-]{36}$/i.test(id) && state.notary[key]?.status === "submission-unknown" && !state.notary[key].id, "ID recovery is only allowed for an ambiguous recorded submission")
        state.notary[key].id = id; state.notary[key].status = "In Progress"; save()
      }
    }
    if (state.phase === "complete") { verifyDelivery(U.readJson(path.join(config.outputDir, "reports/mac-final.json"))); return { status: "complete", state: stateFile, reused: true } }
    if (state.phase === "delivered") {
      verifyDelivery(U.readJson(path.join(config.outputDir, "reports/mac-final.json")))
      state.cleanup = U.trashWork(config, state.stage, command); state.phase = "complete"; save()
      return { status: "complete", state: stateFile, cleanupResumed: true }
    }
    if (!state.signReport) {
      if (state.stage) { assert(!state.notary.app, "Cannot restage an already submitted App"); U.trashWork(config, state.stage, command) }
      state.stage = fs.mkdtempSync(path.join(workRoot, "release-")); U.markOwnedWork(config, state.stage); state.phase = "extracting"; save()
      const unpacked = path.join(state.stage, "ci"); fs.mkdirSync(unpacked)
      command("/usr/bin/unzip", ["-tq", checked.input.artifact.path], { timeout: 300_000 })
      command("/usr/bin/ditto", ["-x", "-k", checked.input.artifact.path, unpacked])
      for (const file of checked.manifest.files) assert.equal(U.hash(path.join(unpacked, file.path)), file.sha256, `Input asset hash failed: ${file.path}`)
      const archive = path.join(unpacked, checked.manifest.files.find((file) => file.role === "archive").path)
      for (const item of U.zipEntries(archive, config.workspace, command)) assert(item.name === "DFCode.app" || item.name.startsWith("DFCode.app/") || item.name.startsWith("__MACOSX/"), `Unexpected App ZIP root: ${item.name}`)
      const appDir = path.join(state.stage, "app"); fs.mkdirSync(appDir)
      command("/usr/bin/ditto", ["-x", "-k", archive, appDir])
      state.app = path.join(appDir, "DFCode.app")
      const yaml = checked.deps.yaml, update = yaml.load(fs.readFileSync(path.join(state.app, "Contents/Resources/app-update.yml"), "utf8"))
      assert.equal(update.provider, "generic"); assert.equal(update.url.replace(/\/$/, ""), config.updateBaseUrl.replace(/\/$/, "")); assert.equal(update.channel || "latest", config.channel)
      const inputBinding = { status: "ci-input-bound", configBinding: binding, verifyCiSha256: checked.input.reportSha256, archive: checked.input.artifact.path, archiveSha256: checked.input.artifact.sha256, appTree: U.treeDigest(state.app) }
      U.writeJson(path.join(config.outputDir, "reports/mac-input.json"), inputBinding)
      state.phase = "signing"; save()
      await S.signMac(config, state.app, { execute: true, binding: inputBinding, reportFile: path.join(config.outputDir, "reports/mac-sign.json"), run: command })
      state.signReport = path.join(config.outputDir, "reports/mac-sign.json"); state.identity = checked.identity; state.phase = "signed"; save()
    }
    const sign = U.readJson(state.signReport)
    assert.equal(sign.status, "signed-and-verified"); assert.equal(U.hash(path.join(state.app, "Contents/Resources/engine/dfcode")), sign.signedEngineSha256)
    if (!state.appNotaryZip) {
      state.appNotaryZip = path.join(state.stage, "app-notary.zip"); archiveApp(state.app, state.appNotaryZip, command); save()
    }
    ensureNotarized(config, state, "app", state.appNotaryZip, save, { run: command })
    if (!state.notary.app.stapledAppTree) {
      command("/usr/bin/xcrun", ["stapler", "staple", state.app]); command("/usr/bin/xcrun", ["stapler", "validate", state.app])
      state.notary.app.stapledAppTree = U.treeDigest(state.app); state.phase = "app-notarized"; save()
    }
    if (!state.dmg) {
      const layout = fs.mkdtempSync(path.join(state.stage, "dmg-layout-"))
      command("/usr/bin/ditto", [state.app, path.join(layout, "DFCode.app")]); fs.symlinkSync("/Applications", path.join(layout, "Applications"))
      const dmg = path.join(state.stage, `dmg-${Date.now()}-${U.names(config).dmg}`)
      command("/usr/bin/hdiutil", ["create", "-volname", `DFCode ${config.version}`, "-srcfolder", layout, "-format", "UDZO", dmg], { timeout: 300_000 })
      command("/usr/bin/codesign", ["--force", "--sign", state.identity.fingerprint, "--timestamp", dmg])
      U.signature(dmg, config.mac.teamId, command); state.dmg = dmg; state.phase = "dmg-signed"; save()
    }
    ensureNotarized(config, state, "dmg", state.dmg, save, { run: command, recoverAcceptedDmg: (file, current) => recoverAcceptedDmg(config, file, current, command) })
    if (!state.notary.dmg.stapledSha256) {
      command("/usr/bin/xcrun", ["stapler", "staple", state.dmg]); command("/usr/bin/xcrun", ["stapler", "validate", state.dmg])
      state.notary.dmg.stapledSha256 = U.hash(state.dmg); state.phase = "dmg-notarized"; save()
    }
    if (!state.finalZip) { state.finalZip = path.join(state.stage, U.names(config).zip); archiveApp(state.app, state.finalZip, command); save() }
    const finalReportFile = path.join(config.outputDir, "reports/mac-final.json")
    if (fs.existsSync(finalReportFile) && U.readJson(finalReportFile).status === "finalized") {
      const finalReport = U.readJson(finalReportFile)
      verifyDelivery(finalReport)
      if (finalReport.workDirectory && !finalReport.cleanup) {
        finalReport.cleanup = U.trashWork(config, finalReport.workDirectory, command)
        U.writeJson(finalReportFile, finalReport)
      }
    }
    else await F.finalizeMac(config, { dmg: state.dmg, zip: state.finalZip, signReport: state.signReport, stateFile }, { execute: true, run: command })
    state.phase = "delivered"; save()
    state.cleanup = U.trashWork(config, state.stage, command); state.phase = "complete"; state.completedAt = new Date().toISOString(); save()
    return { status: "complete", state: stateFile, delivery: path.join(config.outputDir, "delivery/mac"), reports: path.join(config.outputDir, "reports"), appNotaryId: state.notary.app.id, dmgNotaryId: state.notary.dmg.id, appLaunchTest: "not-performed", realOtaTest: "not-performed" }
  } catch (error) { state.lastError = { message: error.message, at: new Date().toISOString() }; save(); throw error }
  finally { fs.unlinkSync(processLock) }
}

async function cli() {
  const args = U.parseArgs(process.argv.slice(2), ["config", "recover-app-id", "recover-dmg-id"])
  if (args.help) return console.log("Usage: node mac-release.cjs --config release.json [--execute] [--resume]\nDefault: read-only plan and local CI/certificate/tool preflight. No writes, submissions, downloads or application launches.\nResume reuses pending/Accepted Apple IDs. Ambiguous prior submission: --resume --recover-app-id ID or --recover-dmg-id ID.\nOutput: outputDir/delivery/mac and outputDir/reports. Expanded copies use .work.noindex/mac and are moved to Trash after verification.")
  assert(args.config, "--config is required")
  const config = require("./config.cjs").loadConfig(args.config)
  console.log(JSON.stringify(await macRelease(config, { execute: args.execute, resume: args.resume, recoverAppId: args["recover-app-id"], recoverDmgId: args["recover-dmg-id"] }), null, 2))
}

module.exports = { ciArtifact, validateFullOta, check, submissionResult, ensureNotarized, recoverAcceptedDmg, verifyDelivery, macRelease }
if (require.main === module) cli().catch((error) => { console.error(error.message); process.exitCode = 1 })
