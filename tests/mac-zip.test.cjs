"use strict"
const test = require("node:test")
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const os = require("node:os")
const { EventEmitter } = require("node:events")
const { Readable } = require("node:stream")
const U = require("../scripts/mac-utils.cjs")

function fixture(t, values) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "mac-zip-test-")), file = path.join(directory, "fixture.zip")
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const buffers = [], entries = []; let offset = 0
  for (const value of values) {
    const localName = Buffer.from(value.localName || value.name), header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0); header.writeUInt16LE(localName.length, 26)
    buffers.push(header, localName)
    entries.push({ fileName: Buffer.from(value.name), relativeOffsetOfLocalHeader: offset, generalPurposeBitFlag: 0, externalFileAttributes: value.target === undefined ? 0 : 0o120777 << 16, uncompressedSize: Buffer.byteLength(value.target || ""), target: value.target })
    offset += 30 + localName.length
  }
  fs.writeFileSync(file, Buffer.concat(buffers))
  const yauzl = { open(_file, options, callback) {
    assert.equal(options.lazyEntries, true); assert.equal(options.validateEntrySizes, true)
    const zip = new EventEmitter(); let index = 0, closed = false
    zip.close = () => { closed = true }
    zip.readEntry = () => queueMicrotask(() => { if (!closed) index < entries.length ? zip.emit("entry", entries[index++]) : zip.emit("end") })
    zip.openReadStream = (entry, next) => queueMicrotask(() => next(null, Readable.from([Buffer.from(entry.target)])))
    callback(null, zip)
  } }
  return { file, yauzl }
}

test("ZIP symlink streaming finishes and validates a normal framework alias", async (t) => {
  const f = fixture(t, [{ name: "DFCode.app/Contents/Frameworks/F.framework/Versions/Current", target: "A" }])
  const entries = await U.inspectZip("unused", f.file, { yauzl: f.yauzl })
  assert.equal(entries.length, 1); assert.equal(entries[0].symlink, true)
})

test("ZIP local header cannot extract to a different path than its central entry", async (t) => {
  const f = fixture(t, [{ name: "DFCode.app/file", localName: "../outside/file" }])
  await assert.rejects(U.inspectZip("unused", f.file, { yauzl: f.yauzl }), /filenames disagree/)
})

test("ZIP symlink chains cannot include an escaping target", async (t) => {
  const f = fixture(t, [{ name: "DFCode.app/one", target: "two" }, { name: "DFCode.app/two", target: "../../outside" }])
  await assert.rejects(U.inspectZip("unused", f.file, { yauzl: f.yauzl }), /Unsafe ZIP symlink/)
})

test("ZIP absolute, traversal, Windows and duplicate filenames are rejected", async (t) => {
  for (const name of ["/absolute", "../outside", "DFCode.app/../../outside", "C:/Windows/file", "DFCode.app\\file"]) assert.throws(() => U.validateZipName(name), /Unsafe ZIP path/)
  const f = fixture(t, [{ name: "DFCode.app/file" }, { name: "DFCode.app/file" }])
  await assert.rejects(U.inspectZip("unused", f.file, { yauzl: f.yauzl }), /Duplicate ZIP path/)
})
