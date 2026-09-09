"use strict"

const assert = require("node:assert/strict")
const { test } = require("node:test")
const { EventEmitter } = require("node:events")
const { Readable } = require("node:stream")
const { createInflateRaw, deflateRawSync } = require("node:zlib")
const { createHash } = require("node:crypto")
const { inspectFlatZip } = require("../scripts/archive.cjs")

class StoredEntryStream extends Readable {
  constructor(content) { super(); this.content = content; this.sent = false; this.destroyed = false }
  _read() {
    if (this.sent) { this.destroyed = true; this.push(null) }
    else { this.sent = true; this.push(this.content) }
  }
  destroy(error) {
    if (this.destroyed) return this
    this.destroyed = true
    if (error) this.emit("error", error)
    return this
  }
}

function fixture(entries, options = {}) {
  let closed = false
  return {
    isClosed: () => closed,
    open(_file, settings, callback) {
      assert.equal(settings.lazyEntries, true)
      assert.equal(settings.validateEntrySizes, true)
      const zip = new EventEmitter()
      let index = 0
      zip.close = () => { if (!closed) { closed = true; zip.emit("close") } }
      zip.readEntry = () => queueMicrotask(() => {
        if (closed) return
        if (options.prematureClose) return zip.close()
        const entry = entries[index++]
        if (!entry) { zip.emit("end"); zip.close(); return }
        zip.emit("entry", { fileName: entry.name, uncompressedSize: entry.declaredSize ?? entry.content.length, externalFileAttributes: entry.mode ?? 0, fixture: entry })
      })
      zip.openReadStream = (entry, done) => {
        const item = entry.fixture
        if (item.openError) return done(new Error("fixture open failed"))
        const stream = item.compressed
          ? Readable.from([deflateRawSync(item.content)]).pipe(createInflateRaw())
          : new StoredEntryStream(item.content)
        done(null, stream)
      }
      callback(null, zip)
    },
  }
}

async function bounded(promise) {
  let timer
  try {
    return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("ZIP reader remained unresolved")), 1000) })])
  } finally { clearTimeout(timer) }
}

test("stored legacy streams and deflated streams both finish with exact hashes and metadata", async () => {
  const samples = [
    { name: "app.zip", content: Buffer.from("unsigned bytes ".repeat(1000)) },
    { name: "release.json", content: Buffer.from('{"version":"0.2.27"}'), compressed: true },
    { name: "latest.yml", content: Buffer.from("version: 0.2.27\n") },
    { name: "empty.bin", content: Buffer.alloc(0) },
  ]
  const reader = fixture(samples)
  const result = await bounded(inspectFlatZip("fixture.zip", "unused", reader))
  assert.equal(reader.isClosed(), true)
  assert.equal(result.length, samples.length)
  for (const [index, item] of result.entries()) {
    const sample = samples[index]
    assert.equal(item.name, sample.name)
    assert.equal(item.size, sample.content.length)
    assert.equal(item.sha256, createHash("sha256").update(sample.content).digest("hex"))
    assert.equal(item.sha512, createHash("sha512").update(sample.content).digest("base64"))
    assert.equal(item.text, /\.(json|yml)$/.test(sample.name) ? sample.content.toString("utf8") : undefined)
  }
})

test("entry size errors, metadata limits and reader failures reject instead of hanging", async () => {
  for (const [sample, message] of [
    [{ name: "app.zip", content: Buffer.from("too much"), declaredSize: 1 }, /size overflow/],
    [{ name: "app.zip", content: Buffer.from("short"), declaredSize: 20 }, /5 !== 20/],
    [{ name: "release.json", content: Buffer.alloc(2 * 1024 ** 2 + 1) }, /Metadata is too large/],
    [{ name: "app.zip", content: Buffer.alloc(1), openError: true }, /fixture open failed/],
  ]) {
    const reader = fixture([sample])
    await assert.rejects(bounded(inspectFlatZip("fixture.zip", "unused", reader)), message)
    assert.equal(reader.isClosed(), true)
  }
})

test("an unexpectedly closed archive fails deterministically", async () => {
  await assert.rejects(bounded(inspectFlatZip("fixture.zip", "unused", fixture([], { prematureClose: true }))), /closed before all entries/)
})

test("flat archive constraints still reject duplicates, nested names and symlinks", async () => {
  for (const [samples, message] of [
    [[{ name: "same.bin" }, { name: "same.bin" }], /Duplicate/],
    [[{ name: "nested/file.bin" }], /flat files/],
    [[{ name: "link", mode: 0xa000 << 16 }], /symlinks/],
  ]) {
    const reader = fixture(samples.map((entry) => ({ content: Buffer.from("fixture"), ...entry })))
    await assert.rejects(bounded(inspectFlatZip("fixture.zip", "unused", reader)), message)
  }
})
