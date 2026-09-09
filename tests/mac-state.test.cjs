"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")
const U = require("../scripts/mac-utils.cjs")
const { ensureNotarized, submissionResult } = require("../scripts/mac-release.cjs")
const ID = "11111111-2222-3333-4444-555555555555"

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mac-state-test-")), file = path.join(directory, "app.zip")
  fs.writeFileSync(file, "fixture bytes; never submitted")
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  return { file, config: { mac: { notaryProfile: "TEST-ONLY" } }, state: { notary: {} } }
}

test("Accepted submission is reused without any external command", (t) => {
  const f = fixture(t)
  f.state.notary.app = { id: ID, status: "Accepted", path: f.file, sha256: U.hash(f.file) }
  assert.equal(ensureNotarized(f.config, f.state, "app", f.file, () => {}, { run() { throw Error("must not run") } }).id, ID)
})

test("submission intent and ID are durable before pending wait; resume never submits again", (t) => {
  const f = fixture(t), snapshots = [], calls = []
  const save = () => snapshots.push(JSON.parse(JSON.stringify(f.state)))
  const run = (_command, args) => {
    calls.push(args[1])
    if (args[1] === "submit") { assert.equal(snapshots.at(-1).notary.app.status, "submission-unknown"); return { stdout: JSON.stringify({ id: ID, status: "In Progress" }), exitCode: 0 } }
    assert.equal(snapshots.at(-1).notary.app.id, ID)
    if (args[1] === "wait") return { exitCode: 1, stdout: "", stderr: "Timed out" }
    return { stdout: JSON.stringify({ id: ID, status: "In Progress" }), exitCode: 0 }
  }
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, save, { run }), /pending/)
  assert.deepEqual(calls, ["submit", "info", "wait"])
  calls.length = 0
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, save, { run }), /pending/)
  assert.deepEqual(calls, ["info", "wait"])
})

test("an ambiguous submit result blocks duplicate submissions", (t) => {
  const f = fixture(t)
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, () => {}, { run() { throw Error("network lost") } }), /network lost/)
  assert.equal(f.state.notary.app.status, "submission-unknown")
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, () => {}, { run() { throw Error("must not resubmit") } }), /unknown result/)
})

test("changed notarization input bytes fail before any API request", (t) => {
  const f = fixture(t)
  f.state.notary.app = { id: ID, status: "In Progress", path: f.file, sha256: "0".repeat(64) }
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, () => {}, { run() { throw Error("must not run") } }), /bytes changed/)
})

test("rejected submissions save the log and do not retry", (t) => {
  const f = fixture(t), calls = []
  f.state.notary.app = { id: ID, status: "In Progress", path: f.file, sha256: U.hash(f.file) }
  const run = (_command, args) => { calls.push(args[1]); return { exitCode: 0, stdout: JSON.stringify(args[1] === "info" ? { id: ID, status: "Invalid" } : { issues: ["fixture rejection"] }), stderr: "" } }
  assert.throws(() => ensureNotarized(f.config, f.state, "app", f.file, () => {}, { run }), /Apple Invalid/)
  assert.deepEqual(calls, ["info", "log"])
  assert.match(f.state.notary.app.rejectionLog, /fixture rejection/)
})

test("submission parser refuses missing IDs", () => { assert.throws(() => submissionResult('{"status":"Accepted"}'), /valid submission ID/) })

test("Accepted DMG byte changes require content and ticket recovery before new hash is trusted", (t) => {
  const f = fixture(t)
  f.state.notary.dmg = { id: ID, status: "Accepted", path: f.file, sha256: "0".repeat(64) }
  let checked = false
  assert.throws(() => ensureNotarized(f.config, f.state, "dmg", f.file, () => {}, { recoverAcceptedDmg() { throw Error("ticket invalid") }, run() { throw Error("must not submit") } }), /ticket invalid/)
  assert.equal(f.state.notary.dmg.stapledSha256, undefined)
  ensureNotarized(f.config, f.state, "dmg", f.file, () => assert(checked), { recoverAcceptedDmg(file) { assert.equal(file, f.file); checked = true }, run() { throw Error("must not submit") } })
  assert.equal(f.state.notary.dmg.stapledSha256, U.hash(f.file)); assert.equal(f.state.notary.dmg.recoveredStapleReceipt, true)
})
