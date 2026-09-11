"use strict"
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { createHash } = require("node:crypto")
const { requireFromStudio } = require("./io.cjs")

async function inspectFlatZip(file, workspace, zipReader) {
  const { Writable } = require("node:stream")
  const { pipeline } = require("node:stream/promises")
  const yauzl = zipReader || requireFromStudio(workspace)("yauzl")
  const zip = await new Promise((resolve, reject) => yauzl.open(file, { lazyEntries: true, autoClose: true, validateEntrySizes: true }, (error, value) => error ? reject(error) : resolve(value)))
  const entries = []
  const names = new Set()
  let inflated = 0
  return new Promise((resolve, reject) => {
    let settled = false
    const fail = (error) => {
      if (settled) return
      settled = true
      zip.close()
      reject(error)
    }
    zip.on("error", fail)
    zip.on("end", () => { if (!settled) { settled = true; resolve(entries) } })
    zip.on("close", () => { if (!settled) fail(new Error("ZIP closed before all entries were read")) })
    zip.on("entry", async (entry) => {
      try {
        const name = entry.fileName
        assert(name && !name.includes("/") && !name.includes("\\") && name !== "." && name !== ".." && !/[\r\n\0]/.test(name), "Full OTA ZIP must contain only flat files")
        assert(!names.has(name), `Duplicate ZIP member: ${name}`)
        assert.notEqual((entry.externalFileAttributes >>> 16) & 0xf000, 0xa000, "Full OTA ZIP cannot contain symlinks")
        inflated += entry.uncompressedSize
        assert(entries.length < 30 && inflated <= 8 * 1024 ** 3, "Full OTA ZIP resource limit exceeded")
        names.add(name)
        const stream = await new Promise((res, rej) => zip.openReadStream(entry, (e, s) => e ? rej(e) : res(s)))
        const h256 = createHash("sha256"), h512 = createHash("sha512")
        const capture = name.endsWith(".json") || name.endsWith(".yml")
        const chunks = []
        let size = 0
        // yauzl 2's stored-entry fd-slicer marks itself destroyed at EOF.
        // pipeline handles this legacy stream without leaving async iteration pending.
        await pipeline(stream, new Writable({
          write(chunk, _encoding, callback) {
            try {
              size += chunk.length
              assert(size <= entry.uncompressedSize, "ZIP member size overflow")
              h256.update(chunk); h512.update(chunk)
              if (capture) { assert(size <= 2 * 1024 ** 2, "Metadata is too large"); chunks.push(chunk) }
              callback()
            } catch (error) { callback(error) }
          },
        }))
        assert.equal(size, entry.uncompressedSize)
        entries.push({ name, size, sha256: h256.digest("hex"), sha512: h512.digest("base64"), ...(capture ? { text: Buffer.concat(chunks).toString("utf8") } : {}) })
        zip.readEntry()
      } catch (error) { fail(error) }
    })
    zip.readEntry()
  })
}

function verifyFullOtaEntries(entries, config, target, signingStatus = "unsigned", yamlParser) {
  const byName = new Map(entries.map((entry) => [entry.name, entry]))
  const manifest = JSON.parse(byName.get("release.json")?.text || "null")
  assert(manifest && manifest.schemaVersion === 3 && manifest.kind === "dfcode-full-app-release", "Unsupported Full OTA manifest")
  assert.equal(manifest.version, config.version)
  assert.equal(manifest.channel, config.channel)
  assert.equal(manifest.source.studioCommit, config.studioCommit)
  assert.equal(manifest.source.engineCommit, config.engineCommit)
  const repositoryIdentity = String(manifest.source.engineRepository || "").replace(/^https:\/\/github\.com\//, "").replace(/\.git$/, "")
  assert.equal(repositoryIdentity, config.engineRepository, "Engine repository mismatch")
  assert.deepEqual(manifest.target, target)
  assert.equal(manifest.signing.status, signingStatus)
  if (signingStatus === "signed" && target.platform === "darwin") {
    assert.equal(manifest.signing.teamId, config.mac.teamId)
    assert.equal(manifest.signing.notarized, true)
  }
  if (signingStatus === "signed" && target.platform === "win32") {
    assert(config.windows?.publisherName, "Signed Windows verification requires the configured publisher")
    assert.equal(manifest.signing.publisherName, config.windows.publisherName, "Windows manifest publisher mismatch")
  }
  const expected = target.platform === "darwin"
    ? [`DFCode-${config.version}-arm64.dmg`, `DFCode-${config.version}-arm64.zip`, `DFCode-${config.version}-arm64.zip.blockmap`, `${config.channel}-mac.yml`]
    : [`DFCode-${config.version}-x64.exe`, `DFCode-${config.version}-x64.exe.blockmap`, `${config.channel}.yml`]
  assert.deepEqual([...byName.keys()].sort(), [...expected, "release.json"].sort())
  assert.deepEqual(manifest.files.map((entry) => entry.path).sort(), [...expected].sort())
  for (const entry of manifest.files) {
    const actual = byName.get(entry.path)
    assert.equal(entry.sha256, actual.sha256, `Manifest hash mismatch: ${entry.path}`)
    assert.equal(entry.size, actual.size)
    const role = entry.path.endsWith(".yml") ? "feed" : entry.path.endsWith(".blockmap") ? "blockmap" : entry.path.endsWith(".zip") ? "archive" : "installer"
    assert.equal(entry.role, role)
  }
  assert.equal(manifest.fileCount, expected.length)
  assert.equal(manifest.totalSize, manifest.files.reduce((sum, entry) => sum + entry.size, 0))
  const releaseHash = createHash("sha256").update(manifest.files.map((entry) => `${entry.path}:${entry.sha256}`).join("\n")).digest("hex")
  assert.equal(manifest.releaseHash, `sha256:${releaseHash}`)
  const yaml = yamlParser || requireFromStudio(config.workspace)("js-yaml")
  const feedName = target.platform === "darwin" ? `${config.channel}-mac.yml` : `${config.channel}.yml`
  assert.equal(manifest.feed.path, feedName)
  const feed = yaml.load(byName.get(feedName).text)
  assert.equal(feed.version, config.version)
  assert.equal(feed.releaseNotes, manifest.releaseNotes)
  assert.equal(feed.releaseNotes, fs.readFileSync(config.otaNotesFile, "utf8").replaceAll("\r\n", "\n").trim())
  const prefix = `${config.version}/${target.platform}/${target.arch}/`
  const installable = expected.filter((name) => /\.(zip|dmg|exe)$/.test(name))
  assert.deepEqual(feed.files.map((entry) => entry.url).sort(), installable.map((name) => prefix + name).sort())
  for (const entry of feed.files) {
    const actual = byName.get(entry.url.slice(prefix.length))
    assert.equal(entry.sha512, actual.sha512)
    assert.equal(entry.size, actual.size)
  }
  const primary = target.platform === "darwin" ? `DFCode-${config.version}-arm64.zip` : `DFCode-${config.version}-x64.exe`
  assert.equal(feed.path, prefix + primary)
  assert.equal(feed.sha512, byName.get(primary).sha512)
  return { source: manifest.source, signing: manifest.signing, manifest, files: entries.map(({ text, ...entry }) => entry) }
}

module.exports = { inspectFlatZip, verifyFullOtaEntries }
