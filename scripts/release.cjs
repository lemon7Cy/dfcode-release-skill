#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const { loadConfig, normalizeConfig, releaseNames, fingerprint, inside, canonical, SHA, VERSION } = require("./config.cjs")
const { run, gh, hashFile, writeJson } = require("./io.cjs")
const { inspectFlatZip, verifyFullOtaEntries } = require("./archive.cjs")

function parse(argv) {
  const command = argv[0]
  const values = {}, flags = new Set()
  for (let i = 1; i < argv.length; i++) {
    const option = argv[i]
    if (["--execute", "--resume", "--publish-release", "--unsigned-only"].includes(option)) { assert(!flags.has(option), `Duplicate ${option}`); flags.add(option); continue }
    assert(["--config", "--studio-commit", "--engine-commit", "--version", "--directory"].includes(option), `Unknown option: ${option}`)
    assert(!values[option] && argv[i + 1] && !argv[i + 1].startsWith("--"), `Missing or duplicate ${option}`)
    values[option] = argv[++i]
  }
  return { command, values, flags }
}

function sourceJson(repository, relative, commit) {
  const result = gh(["api", `repos/${repository}/contents/${relative}?ref=${commit}`])
  assert.equal(result.encoding, "base64")
  return JSON.parse(Buffer.from(result.content, "base64").toString("utf8"))
}

function compareStable(a, b) {
  const av = a.split(".").map(Number), bv = b.split(".").map(Number)
  return av[0] - bv[0] || av[1] - bv[1] || av[2] - bv[2]
}

function chooseVersion(sourceVersion, releases) {
  const versions = releases.filter((item) => !item.isDraft && !item.isPrerelease && /^studio-v\d+\.\d+\.\d+$/.test(item.tagName)).map((item) => item.tagName.slice(8))
  assert(versions.length, "No stable prior release found; supply --version explicitly")
  const latest = versions.sort(compareStable).at(-1)
  if (/^\d+\.\d+\.\d+$/.test(sourceVersion) && compareStable(sourceVersion, latest) > 0) return sourceVersion
  const parts = latest.split(".").map(Number)
  parts[2]++
  return parts.join(".")
}

function initialize(options) {
  const studioCommit = options.values["--studio-commit"], engineCommit = options.values["--engine-commit"]
  assert(SHA.test(studioCommit) && SHA.test(engineCommit), "init requires two full lowercase commits")
  const directory = path.resolve(options.values["--directory"] || `dfcode-release-${studioCommit.slice(0, 8)}-${engineCommit.slice(0, 8)}`)
  const studio = sourceJson("wbz0429/dfcode-studio", "packages/desktop/package.json", studioCommit)
  const engine = sourceJson("wbz0429/xingyuanshusuan-dfcode", "packages/dfcode/package.json", engineCommit)
  const releases = gh(["release", "list", "--repo", "wbz0429/dfcode-studio", "--limit", "100", "--json", "tagName,isDraft,isPrerelease"])
  const version = options.values["--version"] || chooseVersion(studio.version, releases)
  assert(VERSION.test(version))
  const config = normalizeConfig({ version, studioCommit, engineCommit, engineVersion: engine.version, workspace: path.join(directory, "studio-workspace"), outputDir: path.join(directory, "output"), releaseNotesFile: path.join(directory, "release-notes.md"), otaNotesFile: path.join(directory, "ota-notes.md") }, directory)
  console.log(JSON.stringify({ config, configFile: path.join(directory, "release.config.json"), versionInferred: !options.values["--version"], next: "Author release-notes.md and ota-notes.md from the actual previous release manifest before prepare" }, null, 2))
  if (!options.flags.has("--execute")) return
  fs.mkdirSync(directory, { recursive: true })
  const configFile = path.join(directory, "release.config.json")
  assert(!fs.existsSync(configFile), "Config already exists; review and reuse it instead of overwriting")
  writeJson(configFile, config)
}

function stateFile(config) { return path.join(config.outputDir, "state", "ci.json") }
function readState(config) {
  assert(fs.existsSync(stateFile(config)), "Run prepare first")
  const state = JSON.parse(fs.readFileSync(stateFile(config), "utf8"))
  assert.equal(state.configHash, fingerprint(config), "Config changed after preparation; use a new release directory")
  return state
}

function notesCheck(config) {
  for (const file of [config.releaseNotesFile, config.otaNotesFile]) {
    const text = fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n").trim()
    assert(text.length && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\uFFFD]/.test(text), "Notes must be non-empty safe UTF-8 text")
    if (file === config.otaNotesFile) assert(text.length <= 4000, "OTA notes exceed the Admin 4000-character limit")
  }
}

function assertRepoCommit(repository, commit) {
  const result = gh(["api", `repos/${repository}/commits/${commit}`])
  assert.equal(result.sha, commit, `Commit mismatch in ${repository}`)
}

function prepare(config) {
  notesCheck(config)
  assert(!fs.existsSync(stateFile(config)), "This release already has CI state; resume existing stages instead of rebuilding")
  const build = gh(["repo", "view", config.buildRepository, "--json", "visibility,defaultBranchRef"])
  assert.equal(build.visibility, "PRIVATE", "The staging build repository must remain private")
  assertRepoCommit(config.studioRepository, config.studioCommit)
  assertRepoCommit(config.engineRepository, config.engineCommit)
  assert.equal(sourceJson(config.engineRepository, "packages/dfcode/package.json", config.engineCommit).version, config.engineVersion)
  const names = releaseNames(config)
  const workflows = gh(["api", `repos/${config.buildRepository}/actions/workflows?per_page=100`]).workflows
  assert(workflows.some((workflow) => workflow.path === `.github/workflows/${names.workflowFile}` && workflow.state === "active"), "The staging default branch needs an active desktop-installers.yml workflow_dispatch entry first; do not modify its default branch silently")
  assert(!fs.existsSync(config.workspace), "workspace must be a new isolated checkout, not a user's existing worktree")
  fs.mkdirSync(config.outputDir, { recursive: true })
  const ownership = path.join(config.outputDir, "state", "ownership.json")
  assert(!fs.existsSync(ownership), "Preparation started previously; inspect partial checkout before retrying in a new directory")
  writeJson(ownership, { configHash: fingerprint(config), workspace: config.workspace, createdAt: new Date().toISOString() })
  run("git", ["clone", "--filter=blob:none", "--no-checkout", `https://github.com/${config.studioRepository}.git`, config.workspace])
  run("git", ["fetch", "--no-tags", "origin", config.studioCommit], { cwd: config.workspace })
  run("git", ["checkout", "--detach", config.studioCommit], { cwd: config.workspace })
  const required = ["scripts/set-desktop-version.mjs", "scripts/engine-contract.mjs", "scripts/build-engine-binary.sh", "scripts/pack-desktop.sh", "scripts/pack-desktop-win.mjs", "scripts/prepare-admin-full-ota-release.mjs", "packages/desktop/package.json", "bun.lock"]
  for (const name of required) assert(fs.existsSync(path.join(config.workspace, name)), `Selected Studio source lacks expected build contract: ${name}`)
  assert.equal(run("bun", ["--version"]), "1.3.14", "Use Bun 1.3.14 to match the CI toolchain before installing dependencies")
  run("bun", ["install", "--frozen-lockfile"], { cwd: config.workspace })
  const ciWorkspace = path.join(config.outputDir, ".work.noindex", "ci-checkout")
  assert(!fs.existsSync(ciWorkspace), "CI staging path is not empty")
  run("git", ["clone", "--no-hardlinks", config.workspace, ciWorkspace])
  run("git", ["remote", "set-url", "origin", `https://github.com/${config.buildRepository}.git`], { cwd: ciWorkspace })
  run("git", ["switch", "-c", names.branch, config.studioCommit], { cwd: ciWorkspace })
  const { renderWorkflow } = require("./render-workflow.cjs")
  const workflowPath = path.join(ciWorkspace, ".github", "workflows", names.workflowFile)
  fs.mkdirSync(path.dirname(workflowPath), { recursive: true })
  fs.writeFileSync(workflowPath, renderWorkflow(config))
  const fullNotes = `docs/releases/studio-v${config.version}.md`, otaNotes = `docs/releases/studio-v${config.version}-ota.md`
  fs.mkdirSync(path.join(ciWorkspace, "docs", "releases"), { recursive: true })
  fs.copyFileSync(config.releaseNotesFile, path.join(ciWorkspace, fullNotes))
  fs.copyFileSync(config.otaNotesFile, path.join(ciWorkspace, otaNotes))
  run("git", ["add", `.github/workflows/${names.workflowFile}`, fullNotes, otaNotes], { cwd: ciWorkspace })
  run("git", ["diff", "--cached", "--check"], { cwd: ciWorkspace })
  run("git", ["commit", "-m", `ci: unsigned Studio ${config.version} handoff from pinned sources`], { cwd: ciWorkspace })
  const workflowCommit = run("git", ["rev-parse", "HEAD"], { cwd: ciWorkspace })
  const state = { schemaVersion: 1, configHash: fingerprint(config), version: config.version, names, ciWorkspace, workflowCommit, preparedAt: new Date().toISOString(), phase: "prepared", noteHashes: { full: hashFile(config.releaseNotesFile), ota: hashFile(config.otaNotesFile) } }
  writeJson(stateFile(config), state)
  console.log(JSON.stringify({ phase: state.phase, workflowCommit, next: "dispatch --execute" }))
}

function assertNotesUnchanged(config, state) {
  assert.equal(hashFile(config.releaseNotesFile), state.noteHashes.full, "Full notes changed after prepare; regenerate the workflow branch instead of mixing notes")
  assert.equal(hashFile(config.otaNotesFile), state.noteHashes.ota, "OTA notes changed after prepare")
}

async function dispatch(config) {
  const state = readState(config)
  assertNotesUnchanged(config, state)
  if (state.runId) { console.log(JSON.stringify({ runId: state.runId, next: "wait" })); return }
  assert(!state.dispatchPending, "A prior dispatch may have succeeded. Resolve its run ID using gh run list and the exact workflowCommit before attempting another paid build")
  assert.equal(gh(["repo", "view", config.buildRepository, "--json", "visibility"]).visibility, "PRIVATE", "The build repository must remain private")
  assert.equal(run("git", ["rev-parse", "HEAD"], { cwd: state.ciWorkspace }), state.workflowCommit, "CI branch HEAD changed after review")
  assert.equal(run("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: state.ciWorkspace }), "", "CI checkout changed after preparation")
  assert.equal(run("git", ["remote", "get-url", "origin"], { cwd: state.ciWorkspace }), `https://github.com/${config.buildRepository}.git`, "CI remote changed")
  run("git", ["push", "origin", `HEAD:refs/heads/${state.names.branch}`], { cwd: state.ciWorkspace })
  const remoteBranch = gh(["api", `repos/${config.buildRepository}/git/ref/heads/${state.names.branch}`])
  assert.equal(remoteBranch.object.sha, state.workflowCommit, "Remote workflow branch no longer matches reviewed commit")
  const queried = spawnSync("gh", ["release", "view", state.names.draftTag, "--repo", config.buildRepository, "--json", "isDraft,targetCommitish,assets"], { encoding: "utf8" })
  if (queried.status === 0) {
    const existing = JSON.parse(queried.stdout)
    assert(existing.isDraft && existing.targetCommitish === state.workflowCommit && existing.assets.length === 0, "Staging Release exists with different source or assets; refuse to overwrite")
  } else {
    assert(/release not found|Not Found|HTTP 404/i.test(queried.stderr || ""), "Cannot inspect draft Release; check GitHub authentication/network")
    run("gh", ["release", "create", state.names.draftTag, "--repo", config.buildRepository, "--target", state.workflowCommit, "--draft", "--title", `DFCode ${config.version} unsigned staging`, "--notes-file", config.releaseNotesFile])
  }
  const before = new Set(gh(["run", "list", "--repo", config.buildRepository, "--branch", state.names.branch, "--limit", "50", "--json", "databaseId"]).map((item) => item.databaseId))
  state.dispatchPending = true
  state.dispatchStartedAt = new Date().toISOString()
  writeJson(stateFile(config), state)
  run("gh", ["workflow", "run", state.names.workflowFile, "--repo", config.buildRepository, "--ref", state.names.branch, "-f", `draft_release_tag=${state.names.draftTag}`])
  for (let attempt = 0; attempt < 12; attempt++) {
    const runs = gh(["run", "list", "--repo", config.buildRepository, "--branch", state.names.branch, "--limit", "50", "--json", "databaseId,headSha,event,createdAt,url"])
    const candidates = runs.filter((item) => !before.has(item.databaseId) && item.headSha === state.workflowCommit && item.event === "workflow_dispatch")
    assert(candidates.length <= 1, "Multiple matching builds appeared; select the intended run explicitly")
    if (candidates.length) {
      Object.assign(state, { phase: "dispatched", runId: candidates[0].databaseId, runUrl: candidates[0].url, dispatchPending: false })
      writeJson(stateFile(config), state)
      console.log(JSON.stringify({ runId: state.runId, runUrl: state.runUrl })); return
    }
    await new Promise((resolve) => setTimeout(resolve, 2500))
  }
  throw new Error("Dispatch sent but run not visible yet; resume by inspecting the recorded workflow commit, do not dispatch again")
}

function buildStatus(config, state) {
  assert(state.runId, "No recorded run ID")
  const result = gh(["run", "view", String(state.runId), "--repo", config.buildRepository, "--json", "status,conclusion,headSha,event,url,jobs"])
  assert.equal(result.headSha, state.workflowCommit)
  assert.equal(result.event, "workflow_dispatch")
  return result
}

async function collect(config) {
  const state = readState(config)
  assertNotesUnchanged(config, state)
  const status = buildStatus(config, state)
  assert.equal(status.conclusion, "success", "The selected build has not succeeded")
  for (const name of ["prepare", "build-macos", "build-windows"]) assert(status.jobs.some((job) => job.name === name && job.conclusion === "success"), `Required job did not succeed: ${name}`)
  const release = gh(["release", "view", state.names.draftTag, "--repo", config.buildRepository, "--json", "isDraft,targetCommitish,assets"])
  assert(release.isDraft && release.targetCommitish === state.workflowCommit, "Staging Release source changed")
  const directory = path.join(config.outputDir, "unsigned-ci")
  fs.mkdirSync(directory, { recursive: true })
  const artifacts = []
  for (const asset of release.assets) {
    assert(path.basename(asset.name) === asset.name && /^[A-Za-z0-9_.-]+$/.test(asset.name), "Unexpected asset filename")
    assert(/^sha256:[a-f0-9]{64}$/.test(asset.digest || ""), "GitHub asset digest missing; do not skip provenance verification")
    const file = path.join(directory, asset.name)
    if (!fs.existsSync(file)) run("gh", ["release", "download", state.names.draftTag, "--repo", config.buildRepository, "--pattern", asset.name, "--dir", directory])
    assert.equal(fs.statSync(file).size, asset.size)
    assert.equal(`sha256:${hashFile(file)}`, asset.digest, `Downloaded asset mismatch: ${asset.name}; preserve partial file separately before retrying`)
    artifacts.push({ name: asset.name, path: file, size: asset.size, sha256: asset.digest.slice(7), kind: "asset" })
  }
  for (const [platform, arch] of [["darwin", "arm64"], ["win32", "x64"]]) {
    const buildInfoFile = path.join(directory, `BUILD-INFO-${platform}-${arch}.json`)
    const info = JSON.parse(fs.readFileSync(buildInfoFile, "utf8"))
    for (const key of ["version", "studioCommit", "engineCommit", "engineVersion"]) assert.equal(info[key], config[key], `BUILD-INFO ${key} mismatch`)
    assert.equal(info.platform, platform); assert.equal(info.arch, arch)
    assert.equal(String(info.runId), String(state.runId))
    assert.equal(info.workflowCommit, state.workflowCommit)
    const name = `DFCode-${config.version}-${platform}-${arch}-full-ota-unsigned.zip`
    const artifact = artifacts.find((entry) => entry.name === name)
    assert(artifact, `Missing Full OTA archive ${name}`)
    const entries = await inspectFlatZip(artifact.path, config.workspace)
    verifyFullOtaEntries(entries, config, { platform, arch })
    Object.assign(artifact, { kind: "full-ota", target: { platform, arch } })
  }
  const handoff = artifacts.find((entry) => entry.name === `DFCode-${config.version}-win32-x64-signing-input-unsigned.zip`)
  assert(handoff, "Complete Windows signing input is required, not just the installer")
  Object.assign(handoff, { kind: "signing-input", target: { platform: "win32", arch: "x64" } })
  const report = { schemaVersion: 1, status: "verified", version: config.version, source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, build: { repository: config.buildRepository, runId: state.runId, workflowCommit: state.workflowCommit, releaseTag: state.names.draftTag }, artifacts, verifiedAt: new Date().toISOString() }
  writeJson(path.join(config.outputDir, "reports", "verify-ci.json"), report)
  const delivery = path.join(config.outputDir, "delivery")
  fs.mkdirSync(delivery, { recursive: true })
  for (const artifact of artifacts.filter((entry) => entry.kind !== "asset" || entry.name.startsWith("BUILD-INFO-") || entry.name.endsWith("signing-input-unsigned.zip.sha256"))) {
    const destination = path.join(delivery, artifact.name)
    if (fs.existsSync(destination)) assert.equal(hashFile(destination), artifact.sha256)
    else fs.copyFileSync(artifact.path, destination, fs.constants.COPYFILE_EXCL)
  }
  state.phase = "collected"
  writeJson(stateFile(config), state)
  console.log(JSON.stringify({ status: "verified", assets: artifacts.length, delivery }))
}

function routeHost(platform = process.platform, arch = process.arch) {
  if (platform === "darwin" && arch === "arm64") return "mac-release.cjs"
  if (platform === "win32" && arch === "x64") return "windows-release.cjs"
  return null
}

function macPublicationInputs(config) {
  const reportFile = path.join(config.outputDir, "reports", "mac-final.json")
  assert(fs.existsSync(reportFile), "Mac signing has not produced its final report; sign first or explicitly publish --unsigned-only")
  const report = JSON.parse(fs.readFileSync(reportFile, "utf8"))
  const U = require("./mac-utils.cjs")
  assert.equal(report.status, "finalized")
  assert.equal(report.configBinding, U.configBinding(config), "Mac report is bound to different source/config/notes")
  assert(report.notaryIds?.app && report.notaryIds?.dmg, "Mac notarization evidence is missing")
  for (const file of report.files) {
    assert(inside(canonical(path.join(config.outputDir, "delivery", "mac")), canonical(file.path)), "Mac report references a file outside this release's native delivery")
    assert.equal(fs.statSync(file.path).size, file.size)
    assert.equal(hashFile(file.path), file.sha256, "Native Mac delivery changed after verification")
  }
  const names = [
    [`DFCode-${config.version}-arm64.dmg`, `DFCode-${config.version}-arm64-signed-notarized.dmg`],
    [`DFCode-${config.version}-darwin-arm64-full-ota-signed-notarized.zip`, `DFCode-${config.version}-darwin-arm64-full-ota-signed-notarized.zip`],
  ]
  return { report, files: names.map(([inputName, name]) => {
    const matches = report.files.filter((entry) => path.basename(entry.path) === inputName)
    assert.equal(matches.length, 1, `Missing native delivery: ${inputName}`)
    return { ...matches[0], name }
  }) }
}

function assertExistingRelease(config, release, options, query = gh) {
  if (release.isDraft) {
    assert.equal(release.targetCommitish, config.studioCommit, "Draft Release has a different source target")
    return
  }
  assert(options.flags.has("--publish-release"), "Release is already published; updating its assets/notes requires explicit --publish-release authorization")
  let object = query(["api", `repos/${config.studioRepository}/git/ref/tags/${releaseNames(config).upstreamTag}`]).object
  for (let i = 0; object.type === "tag" && i < 5; i++) object = query(["api", `repos/${config.studioRepository}/git/tags/${object.sha}`]).object
  assert.equal(object.type, "commit", "Release tag did not resolve to a commit")
  assert.equal(object.sha, config.studioCommit, "Published Release tag points to another source; never move it")
}

async function publish(config, options) {
  const state = readState(config)
  assert.equal(state.phase, "collected", "Collect and verify unsigned artifacts before publication")
  const proof = JSON.parse(fs.readFileSync(path.join(config.outputDir, "reports", "verify-ci.json"), "utf8"))
  assert.equal(proof.status, "verified")
  const directory = path.join(config.outputDir, "delivery")
  const targets = proof.artifacts.filter((entry) => entry.kind !== "asset" || entry.name.startsWith("BUILD-INFO-") || entry.name.endsWith("signing-input-unsigned.zip.sha256"))
  for (const entry of targets) assert.equal(hashFile(path.join(directory, entry.name)), entry.sha256, "Unsigned delivery changed since CI verification")
  const signedZip = `DFCode-${config.version}-darwin-arm64-full-ota-signed-notarized.zip`
  const signedDmg = `DFCode-${config.version}-arm64-signed-notarized.dmg`
  if (!options.flags.has("--unsigned-only")) {
    assert.equal(routeHost(), "mac-release.cjs", "Windows native signing is not implemented yet; publish its handoff with --unsigned-only")
    const native = macPublicationInputs(config)
    for (const entry of native.files) {
      const destination = path.join(directory, entry.name)
      if (fs.existsSync(destination)) assert.equal(hashFile(destination), entry.sha256, "Existing delivery alias has other bytes")
      else fs.copyFileSync(entry.path, destination, fs.constants.COPYFILE_EXCL)
    }
    const verified = verifyFullOtaEntries(await inspectFlatZip(path.join(directory, signedZip), config.workspace), config, { platform: "darwin", arch: "arm64" }, "signed")
    const insideDmg = verified.files.find((entry) => entry.name === `DFCode-${config.version}-arm64.dmg`)
    assert.equal(hashFile(path.join(directory, signedDmg)), insideDmg.sha256)
    run("xcrun", ["stapler", "validate", path.join(directory, signedDmg)])
    targets.push({ name: signedZip }, { name: signedDmg })
    const evidence = [
      `# DFCode ${config.version} macOS Verification`, "",
      `Studio: ${config.studioRepository}@${config.studioCommit}`,
      `Engine: ${config.engineRepository}@${config.engineCommit} (${config.engineVersion})`,
      `App notarization: ${native.report.notaryIds.app} (Accepted)`,
      `DMG notarization: ${native.report.notaryIds.dmg} (Accepted)`,
      `Default-policy Gatekeeper verified: ${native.report.gatekeeper?.fullyVerified === true}`,
      "App and DMG signatures and staples verified; App trees match in the DMG and OTA ZIP.",
      "Runtime startup and live OTA were not performed by this skill. Installed application and Admin were not modified.", "",
    ].join("\n")
    fs.writeFileSync(path.join(directory, "MACOS-VERIFICATION.md"), evidence)
  }
  const extra = [
    [config.releaseNotesFile, `studio-v${config.version}-release-notes.md`],
    [config.otaNotesFile, `studio-v${config.version}-ota.md`],
  ]
  for (const [source, name] of extra) { fs.copyFileSync(source, path.join(directory, name)); targets.push({ name }) }
  const winNotes = `Windows-${config.version}-signing-handoff.md`
  if (fs.existsSync(path.join(directory, winNotes))) targets.push({ name: winNotes })
  const evidence = "MACOS-VERIFICATION.md"
  if (fs.existsSync(path.join(directory, evidence))) targets.push({ name: evidence })
  const unique = [...new Set(targets.map((entry) => entry.name))]
  assert(unique.length < 1000, "Too many Release assets")
  for (const name of unique) assert(fs.statSync(path.join(directory, name)).size < 2 * 1024 ** 3, `Release asset exceeds GitHub's per-file limit: ${name}`)
  const checksums = unique.map((name) => `${hashFile(path.join(directory, name))}  ${name}`).join("\n") + "\n"
  const checksumName = options.flags.has("--unsigned-only") ? "UNSIGNED-SHA256SUMS.txt" : "SHA256SUMS.txt"
  fs.writeFileSync(path.join(directory, checksumName), checksums)
  unique.push(checksumName)
  assertRepoCommit(config.studioRepository, config.studioCommit)
  const tag = state.names.upstreamTag
  const existing = spawnSync("gh", ["release", "view", tag, "--repo", config.studioRepository, "--json", "isDraft,targetCommitish,assets"], { encoding: "utf8" })
  if (existing.status !== 0) {
    assert(/release not found|Not Found|HTTP 404/i.test(existing.stderr || ""), "Cannot inspect upstream Release")
    run("gh", ["release", "create", tag, "--repo", config.studioRepository, "--target", config.studioCommit, "--draft", "--title", `DFCode Studio v${config.version}`, "--notes-file", config.releaseNotesFile])
  } else {
    const release = JSON.parse(existing.stdout)
    assertExistingRelease(config, release, options)
    for (const name of unique) {
      const asset = release.assets.find((entry) => entry.name === name)
      if (asset) assert.equal(asset.digest, `sha256:${hashFile(path.join(directory, name))}`, `Existing upstream asset differs: ${name}; explicit replacement review required`)
    }
  }
  let remote = gh(["release", "view", tag, "--repo", config.studioRepository, "--json", "assets,isDraft,url"])
  for (const name of unique) {
    if (!remote.assets.some((asset) => asset.name === name)) run("gh", ["release", "upload", tag, "--repo", config.studioRepository, path.join(directory, name)])
  }
  run("gh", ["release", "edit", tag, "--repo", config.studioRepository, "--notes-file", config.releaseNotesFile])
  remote = gh(["release", "view", tag, "--repo", config.studioRepository, "--json", "assets,isDraft,url"])
  for (const name of unique) {
    const asset = remote.assets.find((entry) => entry.name === name)
    assert(asset && asset.state === "uploaded")
    assert.equal(asset.digest, `sha256:${hashFile(path.join(directory, name))}`)
  }
  if (remote.isDraft && options.flags.has("--publish-release")) run("gh", ["release", "edit", tag, "--repo", config.studioRepository, "--draft=false"])
  writeJson(path.join(config.outputDir, "reports", "upstream.json"), { status: "verified", repository: config.studioRepository, tag, sourceCommit: config.studioCommit, assetCount: unique.length, githubReleasePublishedByThisRun: options.flags.has("--publish-release"), adminPublished: false, assets: unique.map((name) => ({ name, sha256: hashFile(path.join(directory, name)) })) })
  console.log(JSON.stringify({ status: "verified", releaseUrl: remote.url, assets: unique.length, adminPublished: false }))
}

async function main(argv = process.argv.slice(2)) {
  if (!argv.length || argv.includes("--help")) {
    console.log("Usage: release.cjs <init|plan|prepare|dispatch|wait|status|collect|sign|publish> --config release.config.json [--execute] [--resume]\ninit: --studio-commit SHA --engine-commit SHA --directory DIR [--version VERSION] [--execute]\nNo --execute: plan only (init resolves source versions with read-only GitHub calls). wait/status are read-only. publish defaults to an upstream draft; --publish-release requires explicit GitHub publication authorization.")
    return
  }
  const options = parse(argv)
  if (options.command === "init") return initialize(options)
  assert(options.values["--config"], "--config is required")
  const config = loadConfig(options.values["--config"])
  assert(["plan", "prepare", "dispatch", "wait", "status", "collect", "sign", "publish"].includes(options.command), "Unknown command")
  if (options.command === "plan" || (!options.flags.has("--execute") && !["wait", "status"].includes(options.command))) {
    console.log(JSON.stringify({ command: options.command, mode: "plan-only", version: config.version, studio: `${config.studioRepository}@${config.studioCommit}`, engine: `${config.engineRepository}@${config.engineCommit}`, names: releaseNames(config), signingDriver: routeHost(), windowsSigningImplemented: false, workspace: config.workspace, outputDir: config.outputDir, adminPublish: false }, null, 2)); return
  }
  if (options.command === "prepare") return prepare(config)
  if (options.command === "dispatch") return dispatch(config)
  if (options.command === "wait" || options.command === "status") {
    const state = readState(config)
    if (options.command === "wait") run("gh", ["run", "watch", String(state.runId), "--repo", config.buildRepository, "--interval", "30", "--exit-status"], { timeout: 75 * 60_000, stdio: "inherit" })
    const current = buildStatus(config, state)
    console.log(JSON.stringify({ runUrl: current.url, status: current.status, conclusion: current.conclusion })); return
  }
  if (options.command === "collect") return collect(config)
  if (options.command === "sign") {
    const driver = routeHost()
    assert(driver, "Only macOS arm64 signing is implemented; Windows x64 currently routes to a handoff, other hosts stop here")
    const args = [path.join(__dirname, driver), "--config", path.resolve(options.values["--config"]), "--execute"]
    if (options.flags.has("--resume") && process.platform === "darwin") args.push("--resume")
    run(process.execPath, args, { stdio: "inherit", timeout: 90 * 60_000 }); return
  }
  if (options.command === "publish") return publish(config, options)
}

module.exports = { parse, chooseVersion, routeHost, macPublicationInputs, assertExistingRelease, main }
if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1 })
