"use strict"

const assert = require("node:assert/strict")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const { spawnSync } = require("node:child_process")
const { test } = require("node:test")
const { renderWorkflow, writeWorkflow } = require("../scripts/render-workflow.cjs")

function fixture(overrides = {}) {
  return {
    version: "0.2.27", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineVersion: "3.3.20",
    studioRepository: "example/studio", engineRepository: "example/engine", buildRepository: "builder/studio",
    channel: "latest", updateBaseUrl: "https://downloads.example.com/ota/latest",
    workspace: path.join(os.tmpdir(), "dfcode-workflow-source"), outputDir: path.join(os.tmpdir(), "dfcode-workflow-output"),
    releaseNotesFile: path.join(os.tmpdir(), "release-notes.md"), otaNotesFile: path.join(os.tmpdir(), "ota-notes.md"),
    ...overrides,
  }
}

function renderedEnvironment(workflow) {
  const section = workflow.slice(workflow.indexOf("\nenv:\n") + 6, workflow.indexOf("\njobs:\n"))
  return Object.fromEntries(section.trimEnd().split("\n").map((line) => {
    const [, key, value] = /^  ([A-Z_]+): (.+)$/.exec(line)
    return [key, value.startsWith('"') ? JSON.parse(value) : value]
  }))
}

test("renders multiple releases without retaining historical pins or local paths", () => {
  for (const values of [{}, { version: "1.4.0-rc.2", studioCommit: "c".repeat(40), engineCommit: "d".repeat(40), engineVersion: "4.0.1", channel: "beta" }]) {
    const config = fixture(values)
    const text = renderWorkflow(config)
    const env = renderedEnvironment(text)
    assert.equal(env.DFCODE_INSTALLER_VERSION, config.version)
    assert.equal(env.DFCODE_STUDIO_COMMIT, config.studioCommit)
    assert.equal(env.DFCODE_ENGINE_COMMIT, config.engineCommit)
    assert.equal(env.DFCODE_ENGINE_VERSION, config.engineVersion)
    assert.equal(env.DFCODE_STUDIO_REPOSITORY, config.studioRepository)
    assert.equal(env.DFCODE_BUILD_REPOSITORY, config.buildRepository)
    assert.equal(env.DFCODE_RELEASE_NOTES, `.release-handoff/docs/releases/studio-v${config.version}.md`)
    assert.equal(env.DFCODE_OTA_NOTES, `.release-handoff/docs/releases/studio-v${config.version}-ota.md`)
    assert(!text.includes(config.workspace) && !text.includes(config.outputDir))
    assert(!text.includes("@@"))
    assert(!text.includes("0.2.26") && !text.includes("3.3.18"))
  }
})

test("uses exact source checkouts and records workflow provenance separately", () => {
  const text = renderWorkflow(fixture())
  assert.equal((text.match(/ref: \$\{\{ env\.DFCODE_STUDIO_COMMIT \}\}/g) || []).length, 2)
  assert.equal((text.match(/ref: \$\{\{ env\.DFCODE_ENGINE_COMMIT \}\}/g) || []).length, 2)
  assert.equal((text.match(/ref: \$\{\{ github\.sha \}\}/g) || []).length, 2)
  assert.match(text, /studioCommit: env\.DFCODE_STUDIO_COMMIT/)
  assert.match(text, /workflowCommit: env\.GITHUB_SHA/)
  assert.match(text, /studioCommit = \$env:DFCODE_STUDIO_COMMIT/)
  assert.match(text, /workflowCommit = \$env:GITHUB_SHA/)
  assert.match(text, /STUDIO_ENGINE_SOURCE_PATH=.*RUNNER_TEMP/)
  assert.match(text, /printf 'STUDIO_ENGINE_SOURCE_PATH=.*GITHUB_ENV/)
  assert.doesNotMatch(text, /ref:\s*(?:main|feature\/dev)/)
})

test("has only draft input, no artifact storage or signing credentials, and preserves full handoff", () => {
  const text = renderWorkflow(fixture())
  const dispatch = text.slice(text.indexOf("  workflow_dispatch:"), text.indexOf("\npermissions:"))
  assert.deepEqual([...dispatch.matchAll(/^      ([a-z_]+):$/gm)].map((match) => match[1]), ["draft_release_tag"])
  assert.match(dispatch, /required: true/)
  assert.doesNotMatch(text, /actions\/(?:upload|download)-artifact|actions\/cache|notarytool|signtool|KEYLOCKER|WINDOWS_PFX|MACOS_CSC|APPLE_API|DFCODE_ADMIN/)
  assert.deepEqual([...new Set([...text.matchAll(/secrets\.([A-Z_]+)/g)].map((match) => match[1]))], ["DFCODE_ENGINE_READ_TOKEN"])
  assert.match(text, /DFCODE_REQUIRE_CODE_SIGNING: "0"/)
  assert.match(text, /DFCODE_WINDOWS_SIGNING_MODE: none/)
  assert.equal((text.match(/gh release upload/g) || []).length, 2)
  assert.doesNotMatch(text, /--clobber|gh release create|gh release edit|--draft=false/)
  assert.match(text, /git archive --format=zip --output=\$sourceZip \$env:DFCODE_STUDIO_COMMIT/)
  assert.match(text, /Copy-Item "release\\win32-x64\\win-unpacked"/)
  assert.match(text, /darwin-arm64-full-ota-unsigned\.zip/)
  assert.match(text, /win32-x64-full-ota-unsigned\.zip/)
  assert.match(text, /SHA256SUMS-darwin-arm64\.txt/)
  assert.match(text, /SHA256SUMS-win32-x64\.txt/)
})

test("draft validation rejects empty, formal, invalid and missing tags before building", () => {
  const text = renderWorkflow(fixture())
  const body = text.slice(text.indexOf("      - name: Verify build repository and existing draft"), text.indexOf("\n  build-macos:"))
  const shell = body.slice(body.indexOf("        run: |\n") + 15).split("\n").map((line) => line.replace(/^          /, "")).join("\n")
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-workflow-gate-"))
  const calls = path.join(temp, "calls")
  fs.writeFileSync(path.join(temp, "gh"), '#!/bin/sh\necho called >> "$CALLS"\n[ "$DRAFT_EXISTS" = yes ] && echo true\n', { mode: 0o700 })
  try {
    for (const [tag, exists, repository, pass, called] of [
      ["internal-studio-v0.2.27", "yes", "builder/studio", true, true],
      ["", "yes", "builder/studio", false, false],
      ["studio-v0.2.27", "yes", "builder/studio", false, false],
      ["a..b", "yes", "builder/studio", false, false],
      ["internal-studio-v0.2.27", "no", "builder/studio", false, true],
      ["internal-studio-v0.2.27", "yes", "example/studio", false, false],
    ]) {
      if (fs.existsSync(calls)) fs.unlinkSync(calls)
      const result = spawnSync("bash", ["-c", shell], { encoding: "utf8", env: { ...process.env, PATH: `${temp}:${process.env.PATH}`, CALLS: calls, DRAFT_TAG: tag, DRAFT_EXISTS: exists, GITHUB_REPOSITORY: repository, DFCODE_BUILD_REPOSITORY: "builder/studio" } })
      assert.equal(result.status === 0, pass, `${tag}: ${result.stderr}`)
      assert.equal(fs.existsSync(calls), called, tag)
    }
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
})

test("escapes config as YAML values and rejects GitHub expression injection", () => {
  const config = fixture({ updateBaseUrl: 'https://downloads.example.com/a/quote"/literal$(text)' })
  assert.equal(renderedEnvironment(renderWorkflow(config)).DFCODE_FULL_OTA_BASE_URL, config.updateBaseUrl)
  assert.throws(() => renderWorkflow(fixture({ updateBaseUrl: "https://example.com/${{secrets.VALUE}}" })), /Workflow expression/)
  assert.throws(() => renderWorkflow(fixture({ studioCommit: "main" })), /studioCommit/)
})

test("writes a new dedicated workflow and never replaces an existing file or symlink", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-render-workflow-"))
  try {
    const output = path.join(temp, ".github/workflows/desktop-installers.yml")
    assert.equal(writeWorkflow(fixture(), output), output)
    const original = fs.readFileSync(output, "utf8")
    assert.throws(() => writeWorkflow(fixture({ version: "9.9.9" }), output), /EEXIST/)
    assert.equal(fs.readFileSync(output, "utf8"), original)
    const link = path.join(temp, "workflow-link.yml")
    fs.symlinkSync(output, link)
    assert.throws(() => writeWorkflow(fixture(), link), /EEXIST/)
    assert.equal(fs.readFileSync(output, "utf8"), original)
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
})

test("CLI loads config from disk, writes only the requested output and refuses a second write", () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "dfcode-workflow-cli-"))
  try {
    const configFile = path.join(temp, "release config.json")
    const output = path.join(temp, "generated workflow.yml")
    const config = fixture({ workspace: path.join(temp, "source"), outputDir: path.join(temp, "delivery") })
    fs.writeFileSync(configFile, JSON.stringify(config))
    const script = path.resolve(__dirname, "../scripts/render-workflow.cjs")
    const args = [script, "--config", configFile, "--output", output]
    const first = spawnSync(process.execPath, args, { encoding: "utf8" })
    assert.equal(first.status, 0, first.stderr)
    assert.equal(first.stdout.trim(), output)
    assert.equal(fs.readFileSync(output, "utf8"), renderWorkflow(config))
    const second = spawnSync(process.execPath, args, { encoding: "utf8" })
    assert.notEqual(second.status, 0)
    assert.match(second.stderr, /EEXIST/)
    assert.equal(fs.readFileSync(output, "utf8"), renderWorkflow(config))
    assert(!fs.existsSync(config.workspace) && !fs.existsSync(config.outputDir))
  } finally { fs.rmSync(temp, { recursive: true, force: true }) }
})
