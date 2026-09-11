"use strict"
const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const { createHash } = require("node:crypto")
const IO = require("./io.cjs")

const hash = (data) => createHash("sha256").update(data).digest("hex")
const readJson = (file) => JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, ""))
const SHA = /^[a-f0-9]{64}$/
const FUSE_NAMES = ["RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnvironmentVariable", "EnableNodeCliInspectArguments", "EnableEmbeddedAsarIntegrityValidation", "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot", "GrantFileProtocolExtraPrivileges"]

function noLinks(file) {
  for (let current = path.resolve(file); ; current = path.dirname(current)) {
    if (fs.existsSync(current)) assert(!fs.lstatSync(current).isSymbolicLink(), `Link path is not permitted: ${current}`)
    if (path.dirname(current) === current) break
  }
}

function safeName(raw, directory = false) {
  assert(typeof raw === "string" && raw.length > 0 && raw.length <= 1024, "Unsafe Windows path")
  const name = directory && raw.endsWith("/") ? raw.slice(0, -1) : raw
  assert(!/[\\:<>"|?*\x00-\x1f\x7f]/.test(name) && !name.startsWith("/"), `Unsafe Windows path: ${raw}`)
  const parts = name.split("/")
  for (const part of parts) {
    assert(part && part !== "." && part !== ".." && part.length <= 255 && !/[ .]$/.test(part), `Unsafe Windows path: ${raw}`)
    assert(!/^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)/i.test(part), `Windows device name: ${raw}`)
  }
  return name
}

function nameRegistry() {
  const names = new Map(), explicit = new Set()
  return (name, directory) => {
    safeName(name)
    const parts = name.split("/")
    for (let i = 1; i <= parts.length; i++) {
      const relative = parts.slice(0, i).join("/"), key = relative.normalize("NFC").toUpperCase()
      const kind = i === parts.length && !directory ? "file" : "directory", old = names.get(key)
      assert(!old || (old.name === relative && old.kind === kind), `Windows path collision: ${name}`)
      if (i === parts.length) { assert(!explicit.has(key), `Duplicate path: ${name}`); explicit.add(key) }
      names.set(key, { name: relative, kind })
    }
  }
}

function inventoryTree(root) {
  noLinks(root); assert(fs.statSync(root).isDirectory(), "Inventory root must be a directory")
  const files = [], register = nameRegistry()
  function walk(directory, prefix = "") {
    for (const name of fs.readdirSync(directory).sort()) {
      const file = path.join(directory, name), relative = prefix + name, stat = fs.lstatSync(file)
      assert(!stat.isSymbolicLink() && (stat.isFile() || stat.isDirectory()), `Non-ordinary inventory entry: ${relative}`)
      if (stat.isFile()) assert.equal(stat.nlink, 1, `Hard-linked inventory entry: ${relative}`)
      register(relative, stat.isDirectory())
      if (stat.isDirectory()) walk(file, relative + "/")
      else files.push({ file: relative, size: stat.size, sha256: IO.hashFile(file) })
    }
  }
  walk(root)
  return files.sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : 0)
}

function readAt(fd, size, offset) {
  assert(Number.isSafeInteger(size) && size >= 0 && Number.isSafeInteger(offset) && offset >= 0, "Invalid binary range")
  const buffer = Buffer.alloc(size)
  assert.equal(fs.readSync(fd, buffer, 0, size, offset), size, "Truncated binary structure")
  return buffer
}

function peHeader(file) {
  noLinks(file); const size = fs.statSync(file).size, fd = fs.openSync(file, "r")
  try {
    if (size < 2 || readAt(fd, 2, 0).toString("ascii") !== "MZ") return null
    assert(size >= 64, "Truncated DOS header")
    const peOffset = readAt(fd, 4, 60).readUInt32LE()
    assert(peOffset >= 64 && peOffset < 16 * 1024 ** 2 && peOffset + 24 <= size, "Invalid PE header offset")
    const head = readAt(fd, 24, peOffset)
    assert.equal(head.readUInt32LE(), 0x00004550, "Invalid PE signature")
    const machine = head.readUInt16LE(4), sectionCount = head.readUInt16LE(6), optionalSize = head.readUInt16LE(20), optionalOffset = peOffset + 24
    assert(sectionCount > 0 && sectionCount <= 96 && optionalSize >= 96 && optionalSize <= 4096, "Invalid PE header dimensions")
    const optional = readAt(fd, optionalSize, optionalOffset), magic = optional.readUInt16LE()
    assert(magic === 0x10b || magic === 0x20b, "Unsupported PE optional header")
    assert((machine === 0x8664 && magic === 0x20b) || (machine === 0x14c && magic === 0x10b), "PE machine/header mismatch")
    const directoryOffset = magic === 0x20b ? 112 : 96
    assert(optionalSize >= directoryOffset + 5 * 8, "Missing PE data directories")
    const directoryCount = optional.readUInt32LE(directoryOffset - 4)
    assert(directoryCount >= 5 && directoryCount <= 16 && optionalSize >= directoryOffset + directoryCount * 8, "Invalid PE directory count")
    const securityOffset = optional.readUInt32LE(directoryOffset + 32), securitySize = optional.readUInt32LE(directoryOffset + 36)
    assert((securityOffset === 0) === (securitySize === 0), "Incomplete PE certificate directory")
    if (securitySize) {
      assert(securityOffset % 8 === 0 && securitySize >= 8 && securityOffset + securitySize === size, "PE certificate table must be aligned and terminal")
      let cursor = securityOffset
      while (cursor < size) {
        const certificate = readAt(fd, 8, cursor), length = certificate.readUInt32LE()
        assert(length >= 8 && cursor + length <= size && certificate.readUInt16LE(4) === 0x200 && certificate.readUInt16LE(6) === 2, "Invalid WIN_CERTIFICATE")
        cursor += Math.ceil(length / 8) * 8
      }
      assert.equal(cursor, size, "Invalid certificate alignment")
    }
    const sectionTable = readAt(fd, sectionCount * 40, optionalOffset + optionalSize), sections = [], headersEnd = optionalOffset + optionalSize + sectionCount * 40
    assert(headersEnd <= (securityOffset || size), "PE headers extend into certificate table")
    for (let index = 0; index < sectionCount; index++) {
      const start = index * 40, rawSize = sectionTable.readUInt32LE(start + 16), rawOffset = sectionTable.readUInt32LE(start + 20)
      assert(rawOffset + rawSize <= (securityOffset || size), "PE section extends beyond program data")
      if (rawSize) assert(rawOffset >= headersEnd, "PE section overlaps headers")
      sections.push({ name: sectionTable.subarray(start, start + 8).toString("ascii").replace(/\0.*$/, ""), virtualSize: sectionTable.readUInt32LE(start + 8), rva: sectionTable.readUInt32LE(start + 12), rawSize, rawOffset })
    }
    const rawSections = sections.filter((entry) => entry.rawSize).sort((a, b) => a.rawOffset - b.rawOffset)
    for (let i = 1; i < rawSections.length; i++) assert(rawSections[i].rawOffset >= rawSections[i - 1].rawOffset + rawSections[i - 1].rawSize, "Overlapping PE raw sections")
    const virtualSections = [...sections].sort((a, b) => a.rva - b.rva)
    for (let i = 1; i < virtualSections.length; i++) assert(virtualSections[i].rva >= virtualSections[i - 1].rva + Math.max(virtualSections[i - 1].virtualSize, virtualSections[i - 1].rawSize), "Overlapping PE virtual sections")
    return { machine, machineName: machine === 0x8664 ? "AMD64" : machine === 0x14c ? "I386" : `0x${machine.toString(16)}`, size, signed: securitySize > 0, securityOffset, securitySize, checksumOffset: optionalOffset + 64, securityDirectoryOffset: optionalOffset + directoryOffset + 32, resourceRva: optional.readUInt32LE(directoryOffset + 16), resourceSize: optional.readUInt32LE(directoryOffset + 20), sections }
  } finally { fs.closeSync(fd) }
}

function peContentDigest(file, header = peHeader(file)) {
  assert(header, "Expected a PE file")
  const end = header.securityOffset || header.size, digest = createHash("sha256"), fd = fs.openSync(file, "r")
  try {
    const buffer = Buffer.alloc(1024 * 1024)
    for (let position = 0; position < end;) {
      const length = Math.min(buffer.length, end - position)
      assert.equal(fs.readSync(fd, buffer, 0, length, position), length)
      for (const [offset, size] of [[header.checksumOffset, 4], [header.securityDirectoryOffset, 8]]) {
        const start = Math.max(position, offset), stop = Math.min(position + length, offset + size)
        if (stop > start) buffer.fill(0, start - position, stop - position)
      }
      digest.update(buffer.subarray(0, length)); position += length
    }
    digest.update(Buffer.alloc((8 - end % 8) % 8))
    return digest.digest("hex")
  } finally { fs.closeSync(fd) }
}

function inspectPe(file) { const info = peHeader(file); return info && { ...info, contentSha256: peContentDigest(file, info) } }

function verifyAsar(file) {
  noLinks(file)
  const stat = fs.statSync(file)
  assert(stat.size >= 16 && stat.size <= 512 * 1024 ** 2, "ASAR resource limit exceeded")
  const archive = fs.readFileSync(file), headerSize = archive.readUInt32LE(4), jsonSize = archive.readUInt32LE(12), dataStart = headerSize + 8
  assert.equal(archive.readUInt32LE(0), 4, "Invalid ASAR size pickle")
  assert(headerSize >= 8 && headerSize <= 16 * 1024 ** 2 && headerSize % 4 === 0 && jsonSize > 0 && jsonSize <= headerSize - 8 && dataStart <= archive.length, "Invalid ASAR header length")
  assert.equal(archive.readUInt32LE(8), headerSize - 4, "Invalid ASAR header pickle")
  const header = archive.subarray(16, 16 + jsonSize), tree = JSON.parse(header.toString("utf8")), files = [], intervals = [], unpacked = [], register = nameRegistry()
  let appPackage, checkedDataSize = 0, checkedUnpackedSize = 0
  function visit(node, prefix = "", inheritedUnpacked = false, depth = 0) {
    assert(depth <= 64 && node && typeof node.files === "object" && !Array.isArray(node.files), "Invalid ASAR directory")
    for (const [name, entry] of Object.entries(node.files)) {
      assert(!name.includes("/"), "Invalid ASAR basename")
      const relative = prefix + name; register(relative, Boolean(entry.files))
      assert(!Object.hasOwn(entry, "link"), `ASAR links are not permitted: ${relative}`)
      const outside = inheritedUnpacked || entry.unpacked === true
      if (entry.files) { visit(entry, relative + "/", outside, depth + 1); continue }
      assert(files.length < 100000 && Number.isSafeInteger(entry.size) && entry.size >= 0, "Invalid ASAR file size")
      let bytes
      if (outside) {
        checkedUnpackedSize += entry.size
        assert(checkedUnpackedSize <= 1024 ** 3 && entry.size <= 512 * 1024 ** 2, "Unpacked ASAR resource limit exceeded")
        const target = path.join(file + ".unpacked", relative); noLinks(target)
        assert(fs.statSync(target).isFile() && fs.statSync(target).size === entry.size, `Unpacked ASAR size mismatch: ${relative}`)
        bytes = fs.readFileSync(target); unpacked.push(relative)
      } else {
        assert(typeof entry.offset === "string" && /^(0|[1-9]\d*)$/.test(entry.offset), "Invalid ASAR offset")
        const start = dataStart + Number(entry.offset), end = start + entry.size
        assert(Number.isSafeInteger(end) && start >= dataStart && end <= archive.length, "ASAR entry escapes data")
        checkedDataSize += entry.size
        assert(checkedDataSize <= archive.length - dataStart, "ASAR data overlap exceeds archive size")
        bytes = archive.subarray(start, end)
        if (entry.size) intervals.push([start, end])
      }
      const integrity = entry.integrity
      assert(integrity && integrity.algorithm === "SHA256" && SHA.test(integrity.hash) && Number.isSafeInteger(integrity.blockSize) && integrity.blockSize > 0 && Array.isArray(integrity.blocks), `Missing ASAR integrity: ${relative}`)
      assert(integrity.blocks.length <= 131072 && integrity.blocks.length === Math.floor(bytes.length / integrity.blockSize) + 1, `Invalid ASAR block count: ${relative}`)
      assert.equal(hash(bytes), integrity.hash, `ASAR file hash mismatch: ${relative}`)
      const blocks = []
      for (let offset = 0; offset <= bytes.length; offset += integrity.blockSize) blocks.push(hash(bytes.subarray(offset, offset + integrity.blockSize)))
      assert.deepEqual(blocks, integrity.blocks, `ASAR block hash mismatch: ${relative}`)
      files.push({ file: relative, size: entry.size, sha256: integrity.hash, unpacked: outside })
      if (relative === "package.json") appPackage = JSON.parse(bytes.toString("utf8"))
    }
  }
  visit(tree)
  let cursor = dataStart
  for (const [start, end] of intervals.sort((a, b) => a[0] - b[0])) { assert.equal(start, cursor, "ASAR data overlap or unexplained gap"); cursor = end }
  assert.equal(cursor, archive.length, "ASAR contains unexplained trailing data")
  if (fs.existsSync(file + ".unpacked")) assert.deepEqual(inventoryTree(file + ".unpacked").map((entry) => entry.file).sort(), [...unpacked].sort(), "Unpacked ASAR inventory mismatch")
  else assert.equal(unpacked.length, 0, "Missing unpacked ASAR directory")
  return { sha256: hash(archive), headerSha256: hash(header), files, fileCount: files.length, unpacked, packageJson: appPackage, passed: true }
}

function electronMetadata(file, pe, asar) {
  const fd = fs.openSync(file, "r")
  try {
    const rvaOffset = (rva, size) => {
      const section = pe.sections.find((item) => rva >= item.rva && rva + size <= item.rva + item.rawSize)
      assert(section, "Resource RVA is outside PE sections")
      return section.rawOffset + rva - section.rva
    }
    assert(pe.resourceRva && pe.resourceSize > 0 && pe.resourceSize <= 32 * 1024 ** 2, "Missing or invalid PE resources")
    const base = rvaOffset(pe.resourceRva, pe.resourceSize), resource = readAt(fd, pe.resourceSize, base)
    const range = (offset, length) => { assert(offset >= 0 && offset + length <= resource.length, "PE resource entry escapes table"); return resource.subarray(offset, offset + length) }
    const entries = []
    function visit(offset, names, depth) {
      assert(depth <= 3, "Unexpected PE resource nesting")
      const head = range(offset, 16), count = head.readUInt16LE(12) + head.readUInt16LE(14)
      assert(count <= 4096, "PE resource count limit exceeded")
      for (let index = 0; index < count; index++) {
        const entry = range(offset + 16 + index * 8, 8), nameId = entry.readUInt32LE(), value = entry.readUInt32LE(4)
        let name = nameId
        if (nameId & 0x80000000) { const at = nameId & 0x7fffffff, length = range(at, 2).readUInt16LE(); assert(length <= 256, "PE resource name too long"); name = range(at + 2, length * 2).toString("utf16le") }
        const namesNext = [...names, name]
        if (depth === 0 && name !== "INTEGRITY") continue
        if (depth === 1 && name !== "ELECTRONASAR") continue
        if (value & 0x80000000) visit(value & 0x7fffffff, namesNext, depth + 1)
        else {
          assert.equal(depth, 2, "Unexpected ELECTRONASAR resource depth")
          const data = range(value, 16), size = data.readUInt32LE(4)
          assert(size > 0 && size <= 1024 ** 2, "Invalid ELECTRONASAR resource size")
          entries.push(JSON.parse(readAt(fd, size, rvaOffset(data.readUInt32LE(), size)).toString("utf8")))
        }
      }
    }
    visit(0, [], 0)
    assert.equal(entries.length, 1, "Expected exactly one ELECTRONASAR resource")
    const embedded = Array.isArray(entries[0]) ? entries[0] : [entries[0]]
    assert(embedded.length >= 1 && embedded.length <= 2, "Unexpected ASAR resource inventory")
    const resourceNames = new Set()
    for (const entry of embedded) {
      assert(typeof entry.file === "string", "Invalid ASAR resource path")
      const name = entry.file.replaceAll("\\", "/")
      assert(["resources/app.asar", "resources/default_app.asar"].includes(name) && !resourceNames.has(name), "Unexpected ASAR resource inventory")
      resourceNames.add(name)
      assert.equal(entry.alg, "SHA256"); assert(SHA.test(entry.value), "Invalid embedded ASAR hash")
      if (name === "resources/app.asar") assert.equal(entry.value, asar.headerSha256, "Embedded ASAR hash mismatch")
      else {
        const defaultFile = path.join(path.dirname(file), name)
        if (fs.existsSync(defaultFile)) {
          noLinks(defaultFile)
          const defaultFd = fs.openSync(defaultFile, "r")
          try {
            const head = readAt(defaultFd, 16, 0), size = head.readUInt32LE(12)
            assert(size <= 16 * 1024 ** 2 && size <= head.readUInt32LE(4) - 8, "Invalid default ASAR header")
            assert.equal(hash(readAt(defaultFd, size, 16)), entry.value, "Embedded default ASAR hash mismatch")
          } finally { fs.closeSync(defaultFd) }
        }
      }
    }
    assert(resourceNames.has("resources/app.asar"), "Missing application ASAR integrity resource")
    const sentinel = Buffer.from("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"), matches = [], chunkSize = 1024 ** 2
    let tail = Buffer.alloc(0)
    const programSize = pe.securityOffset || pe.size
    for (let position = 0; position < programSize; position += chunkSize) {
      const bytes = readAt(fd, Math.min(chunkSize, programSize - position), position), buffer = Buffer.concat([tail, bytes])
      for (let offset = buffer.indexOf(sentinel); offset !== -1; offset = buffer.indexOf(sentinel, offset + 1)) {
        const absolute = position - tail.length + offset
        if (!matches.includes(absolute)) matches.push(absolute)
      }
      tail = buffer.subarray(Math.max(0, buffer.length - sentinel.length + 1))
    }
    assert.equal(matches.length, 1, "Expected exactly one Electron fuse sentinel")
    const wire = readAt(fd, 10, matches[0] + sentinel.length)
    assert.equal(wire[0], 1, "Unsupported Electron fuse version"); assert.equal(wire[1], 8, "Unexpected Electron fuse count")
    const values = [...wire.subarray(2)]
    assert(values.every((value) => [48, 49, 114].includes(value)), "Invalid Electron fuse value")
    const fuses = { offset: matches[0], version: 1, length: 8, values, ...Object.fromEntries(FUSE_NAMES.map((name, index) => [name, values[index]])) }
    return { embeddedIntegrity: embedded, fuses }
  } finally { fs.closeSync(fd) }
}

function skillTreeHash(root) {
  inventoryTree(root)
  const digest = createHash("sha256")
  let count = 0
  // Match the pinned Engine contract's recursive localeCompare ordering.
  function visit(directory, prefix = "") {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const relative = prefix + entry.name, file = path.join(directory, entry.name)
      if (entry.isDirectory()) visit(file, relative + "/")
      else { digest.update(relative); digest.update("\0"); digest.update(fs.readFileSync(file)); digest.update("\0"); count++ }
    }
  }
  visit(root)
  assert(count > 0, "Engine skill tree is empty")
  return { sha256: digest.digest("hex"), files: count }
}

function verifyPayload(config, root, options = {}) {
  root = path.resolve(root)
  const signed = options.signed === true, files = inventoryTree(root), peFiles = []
  if (options.expectedFiles) assert.deepEqual(files, options.expectedFiles, "Payload inventory does not match expected files")
  for (const entry of files) {
    const pe = inspectPe(path.join(root, entry.file))
    if (!pe) { assert(!/\.(exe|dll|node)$/i.test(entry.file), `Executable extension without PE header: ${entry.file}`); continue }
    assert.equal(pe.machine, entry.file === "resources/elevate.exe" ? 0x14c : 0x8664, `Unexpected PE architecture: ${entry.file}`)
    if (signed) assert(pe.signed, `Missing PE certificate table: ${entry.file}`)
    peFiles.push({ ...entry, ...pe })
  }
  const main = peFiles.find((entry) => entry.file === "DFCode.exe"), enginePe = peFiles.find((entry) => entry.file === "resources/engine/dfcode.exe")
  assert(main && enginePe, "Main application and Engine PE files are required")
  const engineRoot = path.join(root, "resources/engine"), engine = readJson(path.join(engineRoot, "manifest.json"))
  assert.equal(engine.repository, config.engineRepository, "Engine repository mismatch")
  assert.equal(engine.commit, config.engineCommit, "Engine commit mismatch")
  assert.equal(engine.engineVersion, config.engineVersion, "Engine version mismatch")
  assert.equal(engine.platform, "win32"); assert.equal(engine.arch, "x64"); assert.equal(engine.executable, "dfcode.exe")
  assert.equal(engine.binarySha256, enginePe.sha256, "Engine binary hash mismatch")
  const skill = skillTreeHash(path.join(engineRoot, "skill"))
  assert.equal(engine.skillTreeSha256, skill.sha256, "Engine skill tree hash mismatch")
  assert(files.some((entry) => entry.file.startsWith("resources/engine/skill/") && entry.file.endsWith("/SKILL.md")), "Engine must include a SKILL.md")
  assert.equal(engine.signing?.signed, signed, "Engine signing state mismatch")
  if (signed) {
    assert.equal(engine.signing.mode, "keylocker"); assert.equal(engine.signing.publisherName, config.windows.publisherName)
  } else assert.equal(engine.signing.mode, "none")
  const requireStudio = (options.requireFromStudio || IO.requireFromStudio)(config.workspace), yaml = requireStudio("js-yaml")
  const update = yaml.load(fs.readFileSync(path.join(root, "resources/app-update.yml"), "utf8"))
  assert(update && typeof update === "object" && !Array.isArray(update), "Invalid updater configuration")
  assert.equal(update.provider, "generic"); assert.equal(update.url, config.updateBaseUrl, "Updater URL mismatch")
  assert.equal(update.channel || "latest", config.channel, "Updater channel mismatch")
  assert.equal(update.updaterCacheDirName, "@studiodesktop-updater", "Updater cache identity mismatch")
  if (signed) assert.deepEqual(update.publisherName, [config.windows.publisherName], "Updater publisher mismatch")
  else assert(update.publisherName === undefined || (Array.isArray(update.publisherName) && update.publisherName.length === 0), "Unsigned updater unexpectedly pins a publisher")
  const asar = verifyAsar(path.join(root, "resources/app.asar")), pkg = asar.packageJson
  assert(pkg && pkg.name === "@studio/desktop" && pkg.version === config.version && pkg.main === "./main.mjs" && pkg.type === "module", "Packaged application identity/version mismatch")
  const packaging = options.packagingConfig?.packageJson
  if (packaging) for (const key of ["name", "version", "main", "type"]) assert.equal(pkg[key], packaging[key], `Packaged ${key} differs from packaging input`)
  const metadata = electronMetadata(path.join(root, "DFCode.exe"), main, asar)
  return { root, passed: true, signed, files, peFiles, engine, skill, update, asar, ...metadata, signatureTrustChecked: false }
}

module.exports = { safeName, nameRegistry, noLinks, inventoryTree, inspectPe, peContentDigest, verifyAsar, verifyPayload, skillTreeHash }
