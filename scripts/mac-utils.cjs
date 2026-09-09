#!/usr/bin/env node
"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { createHash } = require("node:crypto")
const { createRequire } = require("node:module")
const { spawnSync } = require("node:child_process")

const ENTITLEMENTS = ["com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.disable-library-validation"]
const MAGICS = new Set(["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"])

function run(command, args, options = {}) {
  const { allowFailure = false, ...spawnOptions } = options
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 120_000, maxBuffer: 16 * 1024 * 1024, ...spawnOptions })
  const record = { exitCode: result.status, stdout: result.stdout || "", stderr: result.stderr || "", ...(result.error ? { error: result.error.message } : {}) }
  if (!allowFailure && (result.error || result.status !== 0)) throw new Error(`${path.basename(command)} failed (${result.status ?? "spawn"}): ${(record.error || record.stderr || record.stdout).slice(0, 3000)}`)
  return record
}

function hash(file, algorithm = "sha256", encoding = "hex") {
  const digest = createHash(algorithm)
  const fd = fs.openSync(file, "r")
  try {
    const buffer = Buffer.alloc(1024 * 1024)
    let size
    while ((size = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) digest.update(buffer.subarray(0, size))
  } finally { fs.closeSync(fd) }
  return digest.digest(encoding)
}

function fileInfo(file) { return { path: file, size: fs.statSync(file).size, sha256: hash(file), sha512: hash(file, "sha512", "base64") } }
function readJson(file) { return JSON.parse(fs.readFileSync(file, "utf8")) }
function within(root, file) { const relative = path.relative(root, file); return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) }

function noSymlinkAncestors(file) {
  for (let current = path.resolve(file); ; current = path.dirname(current)) {
    if (fs.existsSync(current)) assert(!fs.lstatSync(current).isSymbolicLink(), `Symlink path is not allowed: ${current}`)
    if (path.dirname(current) === current) break
  }
}

function writeJson(file, value) {
  noSymlinkAncestors(file)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const temporary = `${file}.${process.pid}.tmp`
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" })
  fs.renameSync(temporary, file)
}

function ensureEmpty(directory, create = false) {
  noSymlinkAncestors(directory)
  if (fs.existsSync(directory)) assert(fs.statSync(directory).isDirectory() && fs.readdirSync(directory).length === 0, `Refusing non-empty output: ${directory}`)
  else if (create) fs.mkdirSync(directory, { recursive: true })
}

function dependencies(config) {
  const desktopRequire = createRequire(path.join(config.workspace, "packages/desktop/package.json"))
  const builderRequire = createRequire(desktopRequire.resolve("electron-builder/package.json"))
  const libraryRequire = createRequire(builderRequire.resolve("app-builder-lib/package.json"))
  return {
    plist: libraryRequire("plist"), yaml: libraryRequire("js-yaml"), signAsync: libraryRequire("@electron/osx-sign").signAsync,
    buildBlockMap: libraryRequire("app-builder-lib/out/targets/blockmap/blockmap.js").buildBlockMap,
    electronVersion: desktopRequire("electron/package.json").version,
    appId: desktopRequire("./package.json").build.appId,
    versions: { electron: desktopRequire("electron/package.json").version, osxSign: libraryRequire("@electron/osx-sign/package.json").version, builder: builderRequire("app-builder-lib/package.json").version },
  }
}

function plistFile(file, plist, command = run) { return plist.parse(command("/usr/bin/plutil", ["-convert", "xml1", "-o", "-", file]).stdout) }
function isMachO(file, command = run) {
  if (!fs.statSync(file).isFile()) return false
  const fd = fs.openSync(file, "r")
  let magic
  try { const bytes = Buffer.alloc(4); magic = fs.readSync(fd, bytes, 0, 4, 0) === 4 && MAGICS.has(bytes.toString("hex")) } finally { fs.closeSync(fd) }
  return Boolean(magic && /^Mach-O\b/.test(command("/usr/bin/file", ["-b", file]).stdout))
}

function treeDigest(directory) {
  directory = fs.realpathSync(directory)
  const entries = []
  function walk(current) {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, "en"))) {
      const file = path.join(current, entry.name), name = path.relative(directory, file).split(path.sep).join("/")
      if (entry.isSymbolicLink()) {
        assert(within(directory, fs.realpathSync(file)), `Symlink escapes application: ${file}`)
        entries.push([name, "link", fs.readlinkSync(file)])
      } else if (entry.isDirectory()) { entries.push([name, "directory"]); walk(file) }
      else { assert(entry.isFile(), `Unsupported file: ${file}`); entries.push([name, "file", fs.statSync(file).mode & 0o111, hash(file)]) }
    }
  }
  walk(directory)
  return { sha256: createHash("sha256").update(JSON.stringify(entries)).digest("hex"), entries: entries.length }
}

function inventory(app, plist, command = run) {
  app = fs.realpathSync(app)
  const apps = [app], frameworks = [], native = [], entrypoints = new Set()
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name)
      if (entry.isSymbolicLink()) { assert(within(app, fs.realpathSync(file)), `Symlink escapes App: ${file}`); continue }
      if (entry.isDirectory()) { if (file.endsWith(".app")) apps.push(file); if (file.endsWith(".framework")) frameworks.push(file); walk(file) }
      else if (entry.isFile() && isMachO(file, command)) native.push(file)
    }
  }
  walk(path.join(app, "Contents"))
  for (const bundle of apps) {
    const info = plistFile(path.join(bundle, "Contents/Info.plist"), plist, command)
    assert(typeof info.CFBundleExecutable === "string" && path.basename(info.CFBundleExecutable) === info.CFBundleExecutable, `Invalid bundle executable: ${bundle}`)
    const binary = fs.realpathSync(path.join(bundle, "Contents/MacOS", info.CFBundleExecutable))
    assert(within(app, binary) && isMachO(binary, command), `Missing bundle Mach-O: ${binary}`)
    entrypoints.add(binary)
  }
  return { apps, frameworks, native, entrypoints }
}

function signature(file, teamId, command = run) {
  command("/usr/bin/codesign", ["--verify", "--strict", "--verbose=2", file])
  const result = command("/usr/bin/codesign", ["--display", "--verbose=4", file])
  const text = `${result.stdout}\n${result.stderr}`
  if (teamId) {
    assert.equal(/^TeamIdentifier=(.+)$/m.exec(text)?.[1]?.trim(), teamId, `Wrong signing Team ID: ${file}`)
    assert(/^Authority=Developer ID Application:/m.test(text) && !/^Signature=adhoc$/m.test(text), `Missing Developer ID signature: ${file}`)
    assert(/^Timestamp=.+$/m.test(text), `Missing secure timestamp: ${file}`)
  }
  return { teamId: /^TeamIdentifier=(.+)$/m.exec(text)?.[1]?.trim(), adhoc: /^Signature=adhoc$/m.test(text), timestamp: /^Timestamp=(.+)$/m.exec(text)?.[1]?.trim(), runtime: /flags=0x[0-9a-f]+\([^\n)]*runtime/i.test(text) }
}

function entitlements(file, plist, command = run) {
  const result = command("/usr/bin/codesign", ["--display", "--entitlements", ":-", file])
  const text = `${result.stdout}\n${result.stderr}`, start = text.indexOf("<?xml"), end = text.indexOf("</plist>", start)
  if (start < 0) return {}
  assert(end >= start, `Malformed entitlements: ${file}`)
  return plist.parse(text.slice(start, end + 8))
}

function normalizeNotes(file) {
  const notes = fs.readFileSync(file, "utf8").replaceAll("\r\n", "\n").replaceAll("\r", "\n").trim()
  assert(notes.length > 0 && notes.length <= 4000 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(notes), "OTA release notes must be safe text of 1-4000 characters")
  return notes
}

function names(config) {
  return { dmg: `DFCode-${config.version}-arm64.dmg`, zip: `DFCode-${config.version}-arm64.zip`, blockmap: `DFCode-${config.version}-arm64.zip.blockmap`, feed: `${config.channel}-mac.yml`, fullOta: `DFCode-${config.version}-darwin-arm64-full-ota-signed-notarized.zip` }
}

function configBinding(config) {
  const fields = ["version", "studioRepository", "studioCommit", "engineRepository", "engineCommit", "engineVersion", "buildRepository", "channel", "updateBaseUrl", "workspace", "outputDir"]
  return createHash("sha256").update(JSON.stringify({ ...Object.fromEntries(fields.map((field) => [field, config[field]])), mac: config.mac, otaNotesSha256: hash(config.otaNotesFile) })).digest("hex")
}

function parseArgs(args, values = []) {
  const result = {}
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]
    assert(arg.startsWith("--") && !Object.hasOwn(result, arg.slice(2)), `Invalid or duplicate argument: ${arg}`)
    const key = arg.slice(2)
    if (["help", "execute", "resume"].includes(key)) result[key] = true
    else { assert(values.includes(key) && args[i + 1] && !args[i + 1].startsWith("--"), `Unknown or missing value: ${arg}`); result[key] = args[++i] }
  }
  return result
}

function assertWorkPath(config, file) {
  const root = path.join(config.outputDir, ".work.noindex", "mac")
  noSymlinkAncestors(file)
  assert(within(root, path.resolve(file)) && path.resolve(file) !== root, `Mac work item must be beneath ${root}`)
  return root
}

function markOwnedWork(config, directory) {
  const root = assertWorkPath(config, directory)
  writeJson(path.join(directory, ".dfcode-mac-work.json"), { schemaVersion: 1, kind: "dfcode-release-mac-work", root: fs.realpathSync(root), directory: fs.realpathSync(directory) })
}

function trashWork(config, directory, command = run) {
  const root = assertWorkPath(config, directory)
  if (!fs.existsSync(directory)) return { status: "absent" }
  const marker = readJson(path.join(directory, ".dfcode-mac-work.json"))
  assert(marker.schemaVersion === 1 && marker.kind === "dfcode-release-mac-work" && marker.root === fs.realpathSync(root) && marker.directory === fs.realpathSync(directory), "Work directory is not marked as owned by this release")
  const open = command("/usr/sbin/lsof", ["-nP", "-Fpn", "+D", directory], { allowFailure: true })
  assert(!open.error && (open.exitCode === 0 || (open.exitCode === 1 && !open.stderr.trim())), `Cannot determine whether work files are in use: ${open.stderr || open.error}`)
  const used = open.stdout.split("\n").filter((line) => line.startsWith("n") && within(fs.realpathSync(directory), path.resolve(line.slice(1))))
  assert.equal(used.length, 0, `Work files are in use; refusing cleanup: ${used.join(", ")}`)
  const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  const apps = []
  function walk(dir) { for (const item of fs.readdirSync(dir, { withFileTypes: true })) { if (!item.isDirectory()) continue; const file = path.join(dir, item.name); if (file.endsWith(".app")) apps.push(file); else walk(file) } }
  walk(directory)
  const unregister = []
  for (const app of apps) {
    const result = command(lsregister, ["-u", app], { allowFailure: true })
    const text = `${result.stdout}\n${result.stderr}`
    const absent = result.exitCode === 1 && text.includes(app) && /failed to scan/.test(text) && /-10814\b/.test(text)
    assert(result.exitCode === 0 || absent, `LaunchServices unregister failed: ${text}`)
    unregister.push({ path: app, status: absent ? "already-unregistered" : "unregistered" })
    command("/usr/bin/trash", [app])
    assert(!fs.existsSync(app), `Expanded App was not moved to Trash: ${app}`)
  }
  return { status: "apps-trashed", appsUnregistered: apps.length, unregister, paths: apps, retainedWorkDirectory: directory }
}

function validateZipName(name) {
  assert(name && !name.startsWith("/") && !name.includes("\\") && !/^[A-Za-z]:/.test(name) && !name.split("/").includes("..") && !name.includes("\0"), `Unsafe ZIP path: ${name}`)
}

function validateZipLink(name, target) {
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), target))
  assert(target && !target.includes("\\") && !target.includes("\0") && !path.posix.isAbsolute(target) && !/^[A-Za-z]:/.test(target) && !resolved.startsWith("../") && resolved.split("/")[0] === name.split("/")[0], `Unsafe ZIP symlink: ${name}`)
}

async function inspectZip(workspace, file, options = {}) {
  let yauzl = options.yauzl
  if (!yauzl) {
    const desktopRequire = createRequire(path.join(workspace, "packages/desktop/package.json"))
    const electronRequire = createRequire(desktopRequire.resolve("electron/package.json"))
    const extractRequire = createRequire(electronRequire.resolve("extract-zip/package.json"))
    yauzl = extractRequire("yauzl")
  }
  const fd = fs.openSync(file, "r")
  try {
    return await new Promise((resolve, reject) => {
      yauzl.open(file, { lazyEntries: true, decodeStrings: false, validateEntrySizes: true }, (error, zip) => {
        if (error) return reject(error)
        const entries = [], seen = new Set()
        const fail = (failure) => { zip.close(); reject(failure) }
        zip.on("error", fail)
        zip.on("end", () => resolve(entries))
        zip.on("entry", async (entry) => {
          try {
            assert(entries.length < 100_000, "Too many ZIP entries")
            const raw = entry.fileName, name = new TextDecoder("utf-8", { fatal: true }).decode(raw)
            validateZipName(name)
            assert(!seen.has(name), `Duplicate ZIP path: ${name}`); seen.add(name)
            assert(!(entry.generalPurposeBitFlag & 1), "Encrypted ZIP unsupported")
            // Ensure ditto's local-header path is exactly the path that yauzl validated centrally.
            const header = Buffer.alloc(30)
            assert.equal(fs.readSync(fd, header, 0, 30, entry.relativeOffsetOfLocalHeader), 30)
            assert.equal(header.readUInt32LE(0), 0x04034b50, "Invalid ZIP local header")
            const localName = Buffer.alloc(header.readUInt16LE(26))
            assert.equal(fs.readSync(fd, localName, 0, localName.length, entry.relativeOffsetOfLocalHeader + 30), localName.length)
            assert(raw.equals(localName), "ZIP local and central filenames disagree")
            const symlink = ((entry.externalFileAttributes >>> 16) & 0o170000) === 0o120000
            if (symlink) {
              assert(entry.uncompressedSize <= 4096, "Oversized ZIP symlink")
              const bytes = await new Promise((done, no) => zip.openReadStream(entry, (failure, stream) => {
                if (failure) return no(failure)
                const chunks = []
                stream.on("data", (chunk) => chunks.push(chunk)); stream.on("error", no); stream.on("end", () => done(Buffer.concat(chunks)))
              }))
              validateZipLink(name, new TextDecoder("utf-8", { fatal: true }).decode(bytes))
            }
            entries.push({ name, symlink, size: entry.uncompressedSize })
            zip.readEntry()
          } catch (failure) { fail(failure) }
        })
        zip.readEntry()
      })
    })
  } finally { fs.closeSync(fd) }
}

function zipEntries(file, workspace, command = run) {
  return JSON.parse(command(process.execPath, [__filename, "--inspect-zip", workspace, file]).stdout)
}

module.exports = { ENTITLEMENTS, run, hash, fileInfo, readJson, within, writeJson, ensureEmpty, dependencies, plistFile, isMachO, treeDigest, inventory, signature, entitlements, normalizeNotes, names, configBinding, parseArgs, markOwnedWork, assertWorkPath, trashWork, zipEntries, inspectZip, validateZipName, validateZipLink, noSymlinkAncestors }
if (require.main === module) {
  if (process.argv[2] === "--inspect-zip" && process.argv.length === 5) inspectZip(process.argv[3], process.argv[4]).then((entries) => console.log(JSON.stringify(entries))).catch((error) => { console.error(error.message); process.exitCode = 1 })
  else { console.error("Internal usage: mac-utils.cjs --inspect-zip WORKSPACE ZIP"); process.exitCode = 2 }
}
