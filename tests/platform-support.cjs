"use strict"
const fs = require("node:fs")
const path = require("node:path")
const { spawnSync } = require("node:child_process")

function symlinkOrSkip(t, target, link, type) {
  try { fs.symlinkSync(target, link, type); return true }
  catch (error) {
    if (process.platform === "win32" && ["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.skip(`Windows symlink privilege unavailable (${error.code}); this symlink-specific test requires a capable host`)
      return false
    }
    throw error
  }
}

function testBash() {
  if (process.platform !== "win32") {
    const probe = spawnSync("bash", ["--version"], { encoding: "utf8", timeout: 5000 })
    return probe.status === 0 ? "bash" : null
  }
  // Windows' system32/bash.exe can be an unconfigured WSL launcher. Prefer
  // Git Bash, already supplied with the Git dependency, without changing WSL.
  const searchPath = process.env.PATH || process.env.Path || ""
  const candidates = []
  for (const item of searchPath.split(path.delimiter)) {
    const directory = item.replace(/^"|"$/g, "")
    if (!directory || !fs.existsSync(path.join(directory, "git.exe"))) continue
    candidates.push(path.resolve(directory, "../bin/bash.exe"), path.resolve(directory, "../usr/bin/bash.exe"))
  }
  for (const base of [process.env.ProgramFiles, process.env["ProgramFiles(x86)"], process.env.LOCALAPPDATA]) {
    if (base) candidates.push(path.join(base, "Git/bin/bash.exe"), path.join(base, "Programs/Git/bin/bash.exe"))
  }
  for (const candidate of new Set(candidates)) {
    if (!fs.existsSync(candidate)) continue
    const probe = spawnSync(candidate, ["--version"], { encoding: "utf8", timeout: 5000, windowsHide: true })
    if (probe.status === 0) return candidate
  }
  return null
}

module.exports = { symlinkOrSkip, testBash }
