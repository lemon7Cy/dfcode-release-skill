"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { createHash } = require("node:crypto")

const SHA = /^[a-f0-9]{40}$/
const REPO = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/
const VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/
const FIELDS = new Set(["schemaVersion", "attempt", "version", "studioRepository", "studioCommit", "engineRepository", "engineCommit", "engineVersion", "buildRepository", "channel", "updateBaseUrl", "workspace", "outputDir", "releaseNotesFile", "otaNotesFile", "mac", "windows"])
const WINDOWS_FIELDS = new Set(["publisherName", "certificateSha1", "keypairAlias", "smctlPath", "signtoolPath", "powershellPath", "timestampUrl", "preserveMicrosoftSignatures"])

function normalizeWindowsConfig(raw, base) {
  assert(raw && typeof raw === "object" && !Array.isArray(raw), "windows config must be an object")
  for (const key of Object.keys(raw)) assert(WINDOWS_FIELDS.has(key), `Unknown windows config key: ${key}; credentials do not belong in config`)
  const result = { timestampUrl: "http://timestamp.digicert.com", preserveMicrosoftSignatures: true, ...raw }
  for (const key of ["publisherName", "certificateSha1", "keypairAlias", "smctlPath", "signtoolPath", "powershellPath", "timestampUrl"]) {
    if (result[key] === undefined) continue
    assert(typeof result[key] === "string" && result[key].trim() && !/[\u0000-\u001f\u007f]/.test(result[key]), `Invalid windows.${key}`)
    assert(result[key] === result[key].trim(), `windows.${key} must not contain surrounding whitespace`)
  }
  if (result.certificateSha1 !== undefined) {
    assert(/^[a-fA-F0-9]{40}$/.test(result.certificateSha1), "windows.certificateSha1 must be a certificate SHA-1 fingerprint")
    result.certificateSha1 = result.certificateSha1.toUpperCase()
  }
  if (result.publisherName !== undefined) assert(result.publisherName.length <= 512, "windows.publisherName is too long")
  if (result.keypairAlias !== undefined) assert(result.keypairAlias.length <= 200, "windows.keypairAlias is too long")
  const timestamp = new URL(result.timestampUrl)
  assert(["http:", "https:"].includes(timestamp.protocol) && !timestamp.username && !timestamp.password && !timestamp.search && !timestamp.hash, "windows.timestampUrl must be a credential-free HTTP(S) URL")
  assert(typeof result.preserveMicrosoftSignatures === "boolean", "windows.preserveMicrosoftSignatures must be boolean")
  for (const key of ["smctlPath", "signtoolPath", "powershellPath"]) {
    if (result[key] !== undefined) result[key] = path.resolve(base, result[key])
  }
  return result
}

function inside(root, target) {
  const relative = path.relative(root, target)
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
}

function canonical(file) {
  if (fs.existsSync(file)) return fs.realpathSync(file)
  const parent = path.dirname(file)
  return parent === file ? file : path.join(canonical(parent), path.basename(file))
}

function normalizeConfig(raw, base = process.cwd()) {
  assert(raw && typeof raw === "object" && !Array.isArray(raw), "Config must be an object")
  for (const key of Object.keys(raw)) assert(FIELDS.has(key), `Unknown config key: ${key}; credentials do not belong in config`)
  assert(raw.schemaVersion === undefined || raw.schemaVersion === 1, "Unsupported schemaVersion")
  assert(VERSION.test(raw.version), "version must be a desktop semver without a v prefix")
  assert(SHA.test(raw.studioCommit), "studioCommit must be a full lowercase 40-character commit")
  assert(SHA.test(raw.engineCommit), "engineCommit must be a full lowercase 40-character commit")
  assert(VERSION.test(raw.engineVersion), "engineVersion must be resolved from the selected Engine source")
  const result = {
    schemaVersion: 1,
    attempt: 1,
    studioRepository: "wbz0429/dfcode-studio",
    engineRepository: "wbz0429/xingyuanshusuan-dfcode",
    buildRepository: "lemon7Cy/dfcode-studio",
    channel: "latest",
    updateBaseUrl: "https://www.xingyuanshusuan.com/ota/latest",
    ...raw,
    mac: { teamId: "XN5ZRPT7L5", notaryProfile: "DFCodeNotary", identity: "", ...raw.mac },
  }
  assert(Number.isSafeInteger(result.attempt) && result.attempt >= 1 && result.attempt <= 100, "attempt must be an integer from 1 to 100")
  for (const key of ["studioRepository", "engineRepository", "buildRepository"]) {
    assert(REPO.test(result[key]) && !result[key].split("/").some((part) => part === "." || part === ".."), `Invalid ${key}`)
  }
  assert(result.buildRepository.toLowerCase() !== result.studioRepository.toLowerCase(), "Build in the personal staging repository, not the source repository")
  assert(/^[a-z0-9][a-z0-9._-]*$/.test(result.channel) && !result.channel.startsWith("pack."), "Invalid channel")
  const url = new URL(result.updateBaseUrl)
  assert(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash, "updateBaseUrl must be a credential-free HTTPS URL")
  assert(!/[\r\n\0]/.test(result.updateBaseUrl), "Invalid URL characters")
  for (const key of ["workspace", "outputDir", "releaseNotesFile", "otaNotesFile"]) {
    assert(typeof result[key] === "string" && result[key].trim() && !/[\r\n\0]/.test(result[key]), `${key} is required`)
    result[key] = path.resolve(base, result[key])
  }
  const workspace = canonical(result.workspace)
  const output = canonical(result.outputDir)
  const skill = canonical(path.resolve(__dirname, ".."))
  for (const target of [workspace, output]) {
    assert(target !== path.parse(target).root && target !== canonical(os.homedir()), "Do not use a filesystem root or HOME as workspace/output")
    assert(!inside(skill, target) && !inside(target, skill), "Keep build artifacts and application worktrees outside the skill")
    if (process.platform === "darwin") assert(!["/Applications", "/System", "/Library"].some((root) => inside(root, target)), "System/application locations are not release workspaces")
  }
  assert(!inside(workspace, output) && !inside(output, workspace), "workspace and outputDir must be separate non-overlapping directories")
  for (const [key, value] of Object.entries(result.mac)) {
    assert(["teamId", "identity", "notaryProfile"].includes(key), "Only keychain profile names and public signing identifiers belong in mac config")
    assert(typeof value === "string" && !/[\r\n\0]/.test(value), `Invalid mac.${key}`)
  }
  assert(/^[A-Z0-9]{10}$/.test(result.mac.teamId), "mac.teamId must be an Apple Team ID")
  assert(result.mac.identity === "" || /^[A-Fa-f0-9]{40}$/.test(result.mac.identity), "mac.identity must be empty or an identity SHA-1 fingerprint")
  assert(result.mac.notaryProfile && result.mac.notaryProfile.length <= 120, "mac.notaryProfile is required")
  if (raw.windows !== undefined) result.windows = normalizeWindowsConfig(raw.windows, base)
  return result
}

function loadConfig(file) {
  return normalizeConfig(JSON.parse(fs.readFileSync(file, "utf8")), path.dirname(path.resolve(file)))
}

function releaseNames(config) {
  const suffix = `${config.version}-${config.studioCommit.slice(0, 8)}-${config.engineCommit.slice(0, 8)}${config.attempt > 1 ? `-attempt${config.attempt}` : ""}`
  return { branch: `release/unsigned-v${suffix}`, draftTag: `internal-studio-v${suffix}`, upstreamTag: `studio-v${config.version}`, workflowFile: "desktop-installers.yml" }
}

function fingerprint(config) {
  return createHash("sha256").update(JSON.stringify(config)).digest("hex")
}

module.exports = { loadConfig, normalizeConfig, normalizeWindowsConfig, releaseNames, fingerprint, inside, canonical, SHA, REPO, VERSION }
