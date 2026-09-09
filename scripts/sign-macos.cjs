#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { pathToFileURL } = require("node:url")
const U = require("./mac-utils.cjs")

function selectIdentity(config, command = U.run) {
  const text = command("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning"]).stdout
  const matches = text.split("\n").flatMap((line) => {
    const match = line.match(/\b([A-Fa-f0-9]{40})\s+"(Developer ID Application:[^"]+)"/)
    return match && match[2].endsWith(`(${config.mac.teamId})`) ? [{ fingerprint: match[1].toUpperCase(), name: match[2] }] : []
  })
  const requested = config.mac.identity?.toUpperCase()
  const selected = requested ? matches.filter((entry) => entry.fingerprint === requested) : matches
  assert.equal(selected.length, 1, requested ? "Requested valid Developer ID identity is unavailable" : "Expected one Developer ID identity for this Team; set mac.identity explicitly")
  return selected[0]
}

function signingOptions(app, engine, entries, command = U.run) {
  engine = fs.realpathSync(engine)
  const apps = new Set(entries.apps.map((file) => fs.realpathSync(file)))
  const entrypoints = new Set([...entries.entrypoints].map((file) => fs.realpathSync(file)))
  return {
    // osx-sign 1.3.3 drops an array-form ignore during option normalization.
    ignore: (file) => {
      const real = fs.realpathSync(file)
      if (real === engine) return true
      return fs.statSync(file).isDirectory() ? !(file.endsWith(".app") || file.endsWith(".framework")) : !U.isMachO(file, command)
    },
    optionsForFile: (file) => ({ entitlements: apps.has(fs.realpathSync(file)) || entrypoints.has(fs.realpathSync(file)) ? [...U.ENTITLEMENTS] : [], hardenedRuntime: true }),
  }
}

function validateInputBinding(config, app, binding) {
  assert(binding?.status === "ci-input-bound" && binding.configBinding === U.configBinding(config), "Missing matching CI input binding")
  const reportPath = path.join(config.outputDir, "reports/verify-ci.json")
  assert.equal(U.hash(reportPath), binding.verifyCiSha256, "CI verification report changed")
  const report = U.readJson(reportPath)
  assert.equal(report.status, "verified")
  assert.equal(report.version, config.version)
  assert.equal(report.source.studioCommit, config.studioCommit)
  assert.equal(report.source.engineCommit, config.engineCommit)
  assert.equal(report.source.engineVersion, config.engineVersion)
  const artifact = report.artifacts.find((entry) => entry.path === binding.archive && entry.sha256 === binding.archiveSha256 && entry.kind === "full-ota" && entry.target?.platform === "darwin" && entry.target?.arch === "arm64")
  assert(artifact, "Input binding is not backed by the verified Mac CI artifact")
  assert(U.within(path.join(config.outputDir, "unsigned-ci"), fs.realpathSync(artifact.path)), "CI artifact escaped unsigned-ci")
  assert.equal(U.hash(artifact.path), artifact.sha256, "CI archive changed after verification")
  assert.deepEqual(U.treeDigest(app), binding.appTree, "Expanded App differs from the CI-bound input")
}

async function preflight(config, app, options = {}) {
  const command = options.run || U.run, deps = options.dependencies || U.dependencies(config)
  app = fs.realpathSync(app)
  U.assertWorkPath(config, app)
  const identity = selectIdentity(config, command)
  const info = U.plistFile(path.join(app, "Contents/Info.plist"), deps.plist, command)
  assert.equal(info.CFBundleShortVersionString, config.version, "Incorrect App version")
  assert.equal(info.CFBundleIdentifier, deps.appId, "Incorrect App identifier")
  const framework = U.plistFile(path.join(app, "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"), deps.plist, command)
  assert.equal(framework.CFBundleVersion, deps.electronVersion, "App Electron does not match frozen workspace dependencies")
  const contract = await import(pathToFileURL(path.join(config.workspace, "scripts/engine-contract.mjs")).href)
  const lock = { repository: `https://github.com/${config.engineRepository}.git`, commit: config.engineCommit, platform: "darwin", arch: "arm64", executable: "dfcode" }
  const directory = path.join(app, "Contents/Resources/engine"), engine = fs.realpathSync(path.join(directory, "dfcode")), manifestFile = path.join(directory, "manifest.json")
  const original = U.readJson(manifestFile), expected = contract.createManifest(lock, lock.repository, engine, path.join(directory, "skill"))
  for (const key of Object.keys(expected).filter((key) => key !== "binarySha256")) assert.equal(original[key], expected[key], `Engine manifest mismatch: ${key}`)
  if (original.engineVersion !== undefined) assert.equal(original.engineVersion, config.engineVersion)
  assert.deepEqual(Object.keys(original).filter((key) => key !== "engineVersion").sort(), Object.keys(expected).sort(), "Unexpected Engine manifest fields")
  const entries = U.inventory(app, deps.plist, command)
  assert(entries.native.includes(engine), "Engine is not a physical enclosed Mach-O")
  entries.entrypoints.add(engine)
  command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", app])
  const inputSignatures = []
  for (const file of [...entries.native, ...entries.frameworks, ...entries.apps]) {
    const details = U.signature(file, undefined, command)
    assert(details.adhoc, `Input must retain its verified complete ad-hoc CI signature: ${file}`)
    inputSignatures.push({ path: path.relative(app, file) || ".", ...details })
  }
  for (const file of [path.join(app, "Contents/MacOS", info.CFBundleExecutable), path.join(app, "Contents/Frameworks/Electron Framework.framework/Electron Framework"), engine]) {
    assert(command("/usr/bin/lipo", ["-archs", file]).stdout.trim().split(/\s+/).includes("arm64"), `Missing arm64: ${file}`)
  }
  validateInputBinding(config, app, options.binding)
  return { app, identity, deps, contract, lock, engine, directory, manifestFile, original, expected, entries, inputSignatures, normalization: original.binarySha256 !== expected.binarySha256 ? { old: original.binarySha256, actualCiBinarySha256: expected.binarySha256, reason: "CI packaging ad-hoc signature changed Engine bytes after its source manifest was produced; verified archive, complete ad-hoc signatures, source fields and skill tree remain bound" } : null }
}

async function signMac(config, app, options = {}) {
  const checked = await preflight(config, app, options)
  const plan = { status: "preflight-passed", execute: Boolean(options.execute), app: checked.app, version: config.version, engineVersion: config.engineVersion, identity: checked.identity, normalization: checked.normalization, counts: { native: checked.entries.native.length, apps: checked.entries.apps.length, frameworks: checked.entries.frameworks.length } }
  if (!options.execute) return plan
  const command = options.run || U.run, reportFile = options.reportFile || path.join(config.outputDir, "reports/mac-sign.json")
  const report = { ...plan, status: "signing", configBinding: U.configBinding(config), source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit }, tools: checked.deps.versions, inputSignatures: checked.inputSignatures, startedAt: new Date().toISOString(), appLaunchTest: "not-performed", notarized: false }
  U.writeJson(reportFile, report)
  try {
    if (checked.normalization) {
      U.writeJson(path.join(config.outputDir, "reports/mac-engine-manifest-normalization.json"), { ...checked.normalization, originalManifest: checked.original, boundArchive: options.binding.archive, archiveSha256: options.binding.archiveSha256 })
      U.writeJson(checked.manifestFile, { ...checked.original, binarySha256: checked.expected.binarySha256 })
    }
    const entitlementsFile = path.join(path.dirname(checked.app), "entrypoint-entitlements.plist")
    fs.writeFileSync(entitlementsFile, checked.deps.plist.build(Object.fromEntries(U.ENTITLEMENTS.map((key) => [key, true]))), { mode: 0o600, flag: "wx" })
    command("/usr/bin/codesign", ["--force", "--sign", checked.identity.fingerprint, "--timestamp", "--options", "runtime", "--entitlements", entitlementsFile, checked.engine])
    const engineHash = U.hash(checked.engine)
    U.writeJson(checked.manifestFile, { ...checked.original, binarySha256: engineHash })
    report.phase = "sign-bundle"; U.writeJson(reportFile, report)
    await checked.deps.signAsync({ app: checked.app, identity: checked.identity.fingerprint, platform: "darwin", type: "distribution", version: checked.deps.electronVersion, preAutoEntitlements: false, preEmbedProvisioningProfile: false, strictVerify: true, ...signingOptions(checked.app, checked.engine, checked.entries, command) })
    command("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", checked.app])
    const verified = []
    for (const file of [...checked.entries.native, ...checked.entries.frameworks, ...checked.entries.apps]) {
      const details = U.signature(file, config.mac.teamId, command), entitlementValues = U.entitlements(file, checked.deps.plist, command)
      if (checked.entries.apps.includes(file) || checked.entries.entrypoints.has(file)) {
        assert(details.runtime, `Hardened runtime missing: ${file}`)
        for (const key of U.ENTITLEMENTS) assert.equal(entitlementValues[key], true, `Missing entitlement ${key}: ${file}`)
      } else assert.equal(Object.keys(entitlementValues).length, 0, `Library has unexpected entitlements: ${file}`)
      verified.push({ path: path.relative(checked.app, file) || ".", ...details, entitlements: entitlementValues })
    }
    assert.equal(U.hash(checked.engine), engineHash, "Engine changed during bundle signing")
    checked.contract.validateStage(checked.lock, checked.directory)
    const environment = { ...process.env, NO_PROXY: "127.0.0.1,localhost,::1" }
    for (const key of Object.keys(environment)) if (/^(https?|all)_proxy$/i.test(key)) delete environment[key]
    const probe = path.join(path.dirname(checked.app), "version-probe")
    fs.mkdirSync(probe)
    environment.HOME = probe; environment.DFCODE_TEST_HOME = probe
    environment.DFCODE_CONFIG_DIR = path.join(probe, "dfcode-config")
    fs.mkdirSync(environment.DFCODE_CONFIG_DIR)
    for (const name of ["CONFIG", "DATA", "CACHE", "STATE"]) { const directory = path.join(probe, name.toLowerCase()); fs.mkdirSync(directory); environment[`XDG_${name}_HOME`] = directory }
    const engineVersion = command(checked.engine, ["--version"], { cwd: probe, env: environment, timeout: 30_000 }).stdout.trim()
    assert.equal(engineVersion, config.engineVersion, "Signed Engine reports an unexpected version")
    Object.assign(report, { status: "signed-and-verified", phase: "complete", signatureVerified: true, engineVersion, signedEngineSha256: engineHash, manifestSha256: U.hash(checked.manifestFile), appTree: U.treeDigest(checked.app), verified, finishedAt: new Date().toISOString() })
    U.writeJson(reportFile, report)
    return report
  } catch (error) { report.status = "failed"; report.error = error.message; U.writeJson(reportFile, report); throw error }
}

async function cli() {
  const args = U.parseArgs(process.argv.slice(2), ["config", "app", "binding", "report"])
  if (args.help) return console.log("Usage: node sign-macos.cjs --config release.json --app .work.noindex/mac/.../DFCode.app --binding reports/mac-input.json [--report path] [--execute]\nWithout --execute: read-only CI-bound signature preflight. No App or Engine is launched.")
  assert(args.config && args.app && args.binding, "--config, --app and --binding are required")
  const config = require("./config.cjs").loadConfig(args.config)
  console.log(JSON.stringify(await signMac(config, args.app, { execute: args.execute, binding: U.readJson(args.binding), reportFile: args.report }), null, 2))
}

module.exports = { selectIdentity, signingOptions, validateInputBinding, preflight, signMac }
if (require.main === module) cli().catch((error) => { console.error(error.message); process.exitCode = 1 })
