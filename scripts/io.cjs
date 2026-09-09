"use strict"
const fs = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const { createHash } = require("node:crypto")
const { createRequire } = require("node:module")

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 15 * 60_000, maxBuffer: 32 * 1024 * 1024, ...options })
  if (result.error || result.status !== 0) throw new Error(`${command} failed (${result.status}): ${(result.error?.message || result.stderr || result.stdout || "").slice(-3000)}`)
  return (result.stdout || "").trim()
}
const gh = (args) => JSON.parse(run("gh", args))
function hashFile(file, algorithm = "sha256", encoding = "hex") {
  const hash = createHash(algorithm)
  const fd = fs.openSync(file, "r")
  try {
    const buffer = Buffer.alloc(1024 * 1024)
    let length
    while ((length = fs.readSync(fd, buffer, 0, buffer.length, null))) hash.update(buffer.subarray(0, length))
  } finally { fs.closeSync(fd) }
  return hash.digest(encoding)
}
function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true })
  const temporary = `${file}.${process.pid}.tmp`
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { flag: "wx", mode: 0o600 })
  fs.renameSync(temporary, file)
}
function requireFromStudio(workspace) {
  const desktop = createRequire(path.join(workspace, "packages/desktop/package.json"))
  const builder = createRequire(desktop.resolve("electron-builder/package.json"))
  return createRequire(builder.resolve("app-builder-lib/package.json"))
}
module.exports = { run, gh, hashFile, writeJson, requireFromStudio }
