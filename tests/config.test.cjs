const test = require("node:test")
const assert = require("node:assert/strict")
const os = require("node:os")
const path = require("node:path")
const { normalizeConfig, releaseNames } = require("../scripts/config.cjs")
function sample() {
  return { version: "0.9.1", studioCommit: "a".repeat(40), engineCommit: "b".repeat(40), engineVersion: "3.5.1", workspace: path.join(os.tmpdir(), "dfcode-test-workspace"), outputDir: path.join(os.tmpdir(), "dfcode-test-output"), releaseNotesFile: "full.md", otaNotesFile: "ota.md" }
}
test("config resolves portable paths and generates internal non-release tags", () => {
  const config = normalizeConfig(sample(), os.tmpdir())
  assert.equal(config.otaNotesFile, path.join(os.tmpdir(), "ota.md"))
  assert.equal(releaseNames(config).draftTag, "internal-studio-v0.9.1-aaaaaaaa-bbbbbbbb")
  assert.equal(config.mac.identity, "")
})
test("ambiguous refs, credentials and overlapping directories are rejected", () => {
  for (const patch of [{ studioCommit: "main" }, { engineCommit: "b".repeat(39) }, { version: "v1.0.0" }, { updateBaseUrl: "https://u:p@example.com/ota" }, { mac: { p8: "secret" } }, { apiKey: "secret" }, { buildRepository: "wbz0429/dfcode-studio" }, { outputDir: sample().workspace }, { workspace: os.homedir() }]) {
    assert.throws(() => normalizeConfig({ ...sample(), ...patch }))
  }
})
test("explicit attempt separates CI recovery without changing source or release tag", () => {
  const first = normalizeConfig(sample()), second = normalizeConfig({ ...sample(), attempt: 2 })
  assert.notEqual(releaseNames(first).branch, releaseNames(second).branch)
  assert.notEqual(releaseNames(first).draftTag, releaseNames(second).draftTag)
  assert.equal(releaseNames(first).upstreamTag, releaseNames(second).upstreamTag)
  assert.equal(first.studioCommit, second.studioCommit)
  assert.throws(() => normalizeConfig({ ...sample(), attempt: -1 }))
})
