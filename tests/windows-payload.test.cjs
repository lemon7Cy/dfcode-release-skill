"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { createHash } = require("node:crypto")
const P = require("../scripts/windows-payload.cjs")

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex")
const json = (value) => Buffer.from(JSON.stringify(value))
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "windows-payload-test-"))
  t.after(() => {
    const absolute = path.resolve(directory), base = path.resolve(os.tmpdir())
    assert.equal(path.dirname(absolute), base)
    assert(path.basename(absolute).startsWith("windows-payload-test-"))
    fs.rmSync(absolute, { recursive: true, force: true })
  })
  return directory
}
function write(root, relative, bytes) {
  const target = path.join(root, relative)
  fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, bytes)
  return target
}
function makeAsar(values, modify) {
  const tree = { files: {} }, bodies = []; let offset = 0
  for (const [name, value] of Object.entries(values)) {
    const content = Buffer.isBuffer(value) ? value : Buffer.from(value), parts = name.split("/")
    let current = tree
    for (const part of parts.slice(0, -1)) current = current.files[part] ||= { files: {} }
    const blocks = [], blockSize = 16
    for (let start = 0; start <= content.length; start += blockSize) blocks.push(hash(content.subarray(start, start + blockSize)))
    current.files[parts.at(-1)] = { size: content.length, offset: String(offset), integrity: { algorithm: "SHA256", hash: hash(content), blockSize, blocks } }
    offset += content.length; bodies.push(content)
  }
  if (modify) modify(tree)
  const header = json(tree), headerSize = 8 + Math.ceil(header.length / 4) * 4, prefix = Buffer.alloc(8 + headerSize)
  prefix.writeUInt32LE(4, 0); prefix.writeUInt32LE(headerSize, 4); prefix.writeUInt32LE(headerSize - 4, 8); prefix.writeUInt32LE(header.length, 12)
  header.copy(prefix, 16)
  return { bytes: Buffer.concat([prefix, ...bodies]), headerHash: hash(header) }
}
function makePe({ machine = 0x8664, signed = false, headerHash, fuseValues = [49, 48, 49, 49, 48, 48, 48, 49], overlay = Buffer.alloc(0) } = {}) {
  const optionalSize = machine === 0x8664 ? 240 : 224, optionalOffset = 152, directories = machine === 0x8664 ? 112 : 96
  const program = Buffer.alloc(1536)
  program.write("MZ"); program.writeUInt32LE(128, 60); program.write("PE\0\0", 128)
  program.writeUInt16LE(machine, 132); program.writeUInt16LE(1, 134); program.writeUInt16LE(optionalSize, 148)
  program.writeUInt16LE(machine === 0x8664 ? 0x20b : 0x10b, optionalOffset)
  program.writeUInt32LE(16, optionalOffset + directories - 4)
  program.writeUInt32LE(123, optionalOffset + 64)
  const section = optionalOffset + optionalSize
  program.write(".rsrc", section); program.writeUInt32LE(1024, section + 8); program.writeUInt32LE(0x1000, section + 12)
  program.writeUInt32LE(1024, section + 16); program.writeUInt32LE(512, section + 20)
  if (headerHash) {
    program.writeUInt32LE(0x1000, optionalOffset + directories + 16); program.writeUInt32LE(1024, optionalOffset + directories + 20)
    const resource = program.subarray(512)
    resource.writeUInt16LE(1, 12); resource.writeUInt32LE(0x80000080, 16); resource.writeUInt32LE(0x80000020, 20)
    resource.writeUInt16LE(1, 44); resource.writeUInt32LE(0x800000a0, 48); resource.writeUInt32LE(0x80000040, 52)
    resource.writeUInt16LE(1, 78); resource.writeUInt32LE(1033, 80); resource.writeUInt32LE(96, 84)
    for (const [name, at] of [["INTEGRITY", 128], ["ELECTRONASAR", 160]]) { resource.writeUInt16LE(name.length, at); resource.write(name, at + 2, "utf16le") }
    const record = json([{ file: "resources\\app.asar", alg: "SHA256", value: headerHash }])
    resource.writeUInt32LE(0x1100, 96); resource.writeUInt32LE(record.length, 100); record.copy(resource, 256)
    Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX").copy(resource, 768)
    Buffer.from([1, 8, ...fuseValues]).copy(resource, 800)
  }
  let bytes = Buffer.concat([program, overlay])
  if (signed) {
    bytes = Buffer.concat([bytes, Buffer.alloc((8 - bytes.length % 8) % 8)])
    bytes.writeUInt32LE(bytes.length, optionalOffset + directories + 32); bytes.writeUInt32LE(24, optionalOffset + directories + 36)
    const certificate = Buffer.alloc(24, 0x61)
    certificate.writeUInt32LE(24); certificate.writeUInt16LE(0x200, 4); certificate.writeUInt16LE(2, 6)
    bytes = Buffer.concat([bytes, certificate])
  }
  return bytes
}
function fixture(t, { signed = false } = {}) {
  const root = temporary(t)
  const config = { version: "0.2.99", workspace: root, engineRepository: "example/engine", engineCommit: "a".repeat(40), engineVersion: "3.3.18", channel: "latest", updateBaseUrl: "https://example.com/ota/latest", windows: { publisherName: "Example Publisher" } }
  const pkg = { name: "@studio/desktop", version: config.version, type: "module", main: "./main.mjs" }
  const asar = makeAsar({ "package.json": json(pkg), "main.mjs": "export {}", "empty.txt": "" })
  write(root, "resources/app.asar", asar.bytes)
  write(root, "DFCode.exe", makePe({ signed, headerHash: asar.headerHash }))
  const engineBytes = makePe({ signed }); write(root, "resources/engine/dfcode.exe", engineBytes)
  write(root, "resources/elevate.exe", makePe({ machine: 0x14c, signed }))
  write(root, "resources/engine/skill/example/SKILL.md", "# Example")
  const skill = P.skillTreeHash(path.join(root, "resources/engine/skill"))
  const manifest = { repository: config.engineRepository, commit: config.engineCommit, engineVersion: config.engineVersion, platform: "win32", arch: "x64", executable: "dfcode.exe", binarySha256: hash(engineBytes), skillTreeSha256: skill.sha256, signing: signed ? { mode: "keylocker", signed: true, publisherName: config.windows.publisherName } : { mode: "none", signed: false } }
  write(root, "resources/engine/manifest.json", json(manifest))
  const update = { provider: "generic", url: config.updateBaseUrl, channel: "latest", updaterCacheDirName: "@studiodesktop-updater", ...(signed ? { publisherName: [config.windows.publisherName] } : {}) }
  write(root, "resources/app-update.yml", json(update))
  const options = { signed, packagingConfig: { packageJson: pkg }, requireFromStudio: () => (name) => { assert.equal(name, "js-yaml"); return { load: JSON.parse } } }
  return { root, config, options, asar, manifest, update }
}

test("Windows path rules reject traversal, streams, device names and ambiguous components", () => {
  for (const name of ["../escape", "/absolute", "C:/escape", "file:stream", "a\\b", "a/../b", "a//b", "NUL.txt", "com1", "LPT¹.txt", "file.", "dir /file", "a\0b"]) assert.throws(() => P.safeName(name), /path|device/i)
  assert.equal(P.safeName("resources/Engine-data.txt"), "resources/Engine-data.txt")
})
test("Path registry rejects case-only ancestors, file-directory aliases and duplicate entries", () => {
  for (const [first, second] of [["A/a.txt", "a/b.txt"], ["root", "root/file"], ["file", "file"], ["é/a", "e\u0301/b"]]) {
    const register = P.nameRegistry(); register(first, false); assert.throws(() => register(second, false), /collision|Duplicate/)
  }
  const register = P.nameRegistry(); register("same/a", false); register("same/b", false)
})
test("Inventory recursively records files and refuses junction/symlink roots", (t) => {
  const root = temporary(t); write(root, "z.txt", "z"); write(root, "a/file", "a")
  assert.deepEqual(P.inventoryTree(root).map((entry) => entry.file), ["a/file", "z.txt"])
  const hardLink = path.join(root, "hard-link")
  fs.linkSync(path.join(root, "z.txt"), hardLink)
  assert.throws(() => P.inventoryTree(root), /Hard-linked/)
  fs.unlinkSync(hardLink)
  const alias = path.join(root, "alias")
  try { fs.symlinkSync(path.join(root, "a"), alias, process.platform === "win32" ? "junction" : "dir") }
  catch (error) { if (error.code === "EPERM") { t.diagnostic("Symlink creation unavailable"); return } throw error }
  assert.throws(() => P.inventoryTree(root), /ordinary|Link/)
})
test("PE inspector detects AMD64 and keeps content digest invariant only across signature fields", (t) => {
  const root = temporary(t), overlay = Buffer.from("payload-end")
  const unsigned = write(root, "unsigned.exe", makePe({ overlay })), signed = write(root, "signed.exe", makePe({ overlay, signed: true }))
  assert.equal(P.inspectPe(unsigned).machine, 0x8664); assert.equal(P.inspectPe(unsigned).signed, false)
  assert.equal(P.inspectPe(signed).signed, true); assert.equal(P.peContentDigest(unsigned), P.peContentDigest(signed))
  const changed = fs.readFileSync(signed); changed[600] ^= 1; fs.writeFileSync(signed, changed)
  assert.notEqual(P.peContentDigest(unsigned), P.peContentDigest(signed))
})
test("PE certificate overlay, malformed MZ and fake executable files fail closed", (t) => {
  const root = temporary(t), file = write(root, "test.exe", Buffer.concat([makePe({ signed: true }), Buffer.from("overlay")]))
  assert.throws(() => P.inspectPe(file), /terminal/)
  fs.writeFileSync(file, Buffer.from("MZbroken")); assert.throws(() => P.inspectPe(file), /Truncated/)
  fs.writeFileSync(file, "plain"); assert.equal(P.inspectPe(file), null)
  const wrongMachine = makePe(); wrongMachine.writeUInt16LE(0x14c, 132); fs.writeFileSync(file, wrongMachine)
  assert.throws(() => P.inspectPe(file), /machine\/header/)
  const badSection = makePe(); badSection.writeUInt32LE(128, 152 + 240 + 20); fs.writeFileSync(file, badSection)
  assert.throws(() => P.inspectPe(file), /overlaps headers/)
})
test("ASAR verifies empty and exact-block files and refuses hash/content corruption", (t) => {
  const root = temporary(t), asar = makeAsar({ "empty": "", "exact": "1234567890123456" }), file = write(root, "app.asar", asar.bytes)
  assert.equal(P.verifyAsar(file).fileCount, 2)
  const corrupt = Buffer.from(asar.bytes); corrupt[corrupt.length - 1] ^= 1; fs.writeFileSync(file, corrupt)
  assert.throws(() => P.verifyAsar(file), /hash mismatch/)
})
test("ASAR rejects links, path traversal, overlaps, missing hashes and trailing payload", (t) => {
  const root = temporary(t), file = path.join(root, "app.asar")
  const variants = [
    makeAsar({ "a": "one" }, tree => { tree.files.a.link = "../outside" }),
    makeAsar({ "a": "one" }, tree => { tree.files[".."] = tree.files.a; delete tree.files.a }),
    makeAsar({ "a": "one", "b": "one" }, tree => { tree.files.b.offset = "0" }),
    makeAsar({ "a": "one" }, tree => { delete tree.files.a.integrity }),
  ]
  for (const variant of variants) { fs.writeFileSync(file, variant.bytes); assert.throws(() => P.verifyAsar(file), /ASAR|path/) }
  fs.writeFileSync(file, Buffer.concat([makeAsar({ "a": "one" }).bytes, Buffer.from("extra")]))
  assert.throws(() => P.verifyAsar(file), /trailing/)
})
test("Complete unsigned and signed payloads validate static contracts without claiming signature trust", (t) => {
  for (const signed of [false, true]) {
    const f = fixture(t, { signed }), report = P.verifyPayload(f.config, f.root, f.options)
    assert.equal(report.passed, true); assert.equal(report.peFiles.length, 3)
    assert.equal(report.asar.fileCount, 3); assert.equal(report.signatureTrustChecked, false)
    assert.deepEqual(report.fuses.values, [49, 48, 49, 49, 48, 48, 48, 49])
  }
})
test("Payload rejects wrong Engine version/skills and updater identity", (t) => {
  const f = fixture(t)
  assert.throws(() => P.verifyPayload({ ...f.config, engineVersion: "9.9.9" }, f.root, f.options), /version mismatch/)
  assert.throws(() => P.verifyPayload({ ...f.config, updateBaseUrl: "https://wrong.example/" }, f.root, f.options), /URL mismatch/)
  write(f.root, "resources/engine/skill/example/SKILL.md", "changed")
  assert.throws(() => P.verifyPayload(f.config, f.root, f.options), /skill tree hash/)
})
test("Payload rejects x86 application, fake native module and unsigned signed-mode input", (t) => {
  const f = fixture(t)
  write(f.root, "DFCode.exe", makePe({ machine: 0x14c, headerHash: f.asar.headerHash }))
  assert.throws(() => P.verifyPayload(f.config, f.root, f.options), /architecture/)
  write(f.root, "DFCode.exe", makePe({ headerHash: f.asar.headerHash })); write(f.root, "native.node", "fake")
  assert.throws(() => P.verifyPayload(f.config, f.root, f.options), /without PE/)
  fs.unlinkSync(path.join(f.root, "native.node"))
  assert.throws(() => P.verifyPayload(f.config, f.root, { ...f.options, signed: true }), /certificate/)
})
test("Payload checks embedded ASAR header even when the integrity fuse is disabled", (t) => {
  const f = fixture(t)
  write(f.root, "DFCode.exe", makePe({ headerHash: "b".repeat(64) }))
  assert.throws(() => P.verifyPayload(f.config, f.root, f.options), /Embedded ASAR hash mismatch/)
})
test("Payload rejects invalid fuse wire and signed publisher mismatch", (t) => {
  const f = fixture(t)
  write(f.root, "DFCode.exe", makePe({ headerHash: f.asar.headerHash, fuseValues: [0, 48, 49, 49, 48, 48, 48, 49] }))
  assert.throws(() => P.verifyPayload(f.config, f.root, f.options), /fuse value/)
  const signed = fixture(t, { signed: true }); signed.update.publisherName = ["Wrong Publisher"]
  write(signed.root, "resources/app-update.yml", json(signed.update))
  assert.throws(() => P.verifyPayload(signed.config, signed.root, signed.options), /publisher mismatch/)
})
