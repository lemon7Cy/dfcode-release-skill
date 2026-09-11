'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { hashFile, requireFromStudio } = require('./io.cjs');
const { noLinks } = require('./windows-package.cjs');
const { verifyFullOtaEntries } = require('./archive.cjs');
const payload = require('./windows-payload.cjs');

const SHA = /^[a-f0-9]{64}$/;
const safeName = payload.safeName;
function metadata(file) {
  noLinks(file); assert(fs.statSync(file).isFile() && fs.statSync(file).size <= 4 * 1024 ** 2, 'Input metadata is missing or too large');
  return JSON.parse(fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, ''));
}
function verifyReceipt(config) {
  const name = `DFCode-${config.version}-win32-x64-signing-input-unsigned.zip`;
  const reportFile = path.join(config.outputDir, 'reports/verify-ci.json');
  const report = metadata(reportFile);
  assert.equal(report.schemaVersion, 1); assert.equal(report.status, 'verified'); assert.equal(report.version, config.version);
  for (const key of ['studioCommit', 'engineCommit', 'engineVersion']) assert.equal(report.source?.[key], config[key], `CI receipt ${key} mismatch`);
  assert.equal(report.build?.repository, config.buildRepository, 'CI receipt build repository mismatch');
  assert(/^[1-9][0-9]*$/.test(String(report.build.runId)), 'CI receipt requires the selected run ID');
  assert(/^[a-f0-9]{40}$/.test(report.build.workflowCommit), 'CI receipt requires the exact workflow commit');
  assert(Array.isArray(report.artifacts), 'CI receipt artifacts are missing');
  const matches = report.artifacts.filter(x => x.name === name);
  assert.equal(matches.length, 1, 'CI receipt must identify one complete Windows signing input');
  const recorded = matches[0];
  assert.equal(recorded.kind, 'signing-input'); assert.deepEqual(recorded.target, { platform: 'win32', arch: 'x64' });
  assert(SHA.test(recorded.sha256) && Number.isSafeInteger(recorded.size) && recorded.size > 0, 'CI artifact digest/size is missing');
  // A receipt can originate on macOS. Only this known local basename selects bytes.
  const file = path.join(config.outputDir, 'unsigned-ci', name);
  noLinks(file); noLinks(`${file}.sha256`);
  assert(fs.statSync(file).isFile() && fs.statSync(file).nlink === 1, 'Signing archive must be an ordinary file');
  assert.equal(fs.statSync(file).size, recorded.size, 'CI artifact size mismatch');
  assert.equal(hashFile(file), recorded.sha256, 'CI artifact digest mismatch');
  assert(fs.statSync(`${file}.sha256`).size < 4096, 'Invalid external checksum file');
  const checksum = fs.readFileSync(`${file}.sha256`, 'utf8').replace(/^\uFEFF/, '').trim();
  assert.equal(checksum, `${recorded.sha256}  ${name}`, 'External archive checksum mismatch');
  return { artifact: { ...recorded, path: file }, reportFile, reportSha256: hashFile(reportFile), build: report.build };
}

async function extractZip(file, destination, reader, limits = {}) {
  const budget = { entries: 100000, totalSize: 8 * 1024 ** 3, fileSize: 2 * 1024 ** 3, ...limits };
  for (const value of Object.values(budget)) assert(Number.isSafeInteger(value) && value > 0, 'Invalid ZIP resource limit');
  noLinks(destination); assert(!fs.existsSync(destination), 'Preserve existing extracted input; select a fresh destination');
  const zip = await new Promise((resolve, reject) => reader.open(file, { lazyEntries: true, autoClose: true, validateEntrySizes: true, strictFileNames: true }, (error, value) => error ? reject(error) : resolve(value)));
  fs.mkdirSync(destination, { recursive: true });
  const names = new Map(); let count = 0, total = 0;
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = error => { if (settled) return; settled = true; zip.close(); reject(error); };
    zip.on('error', fail);
    zip.on('end', () => { if (!settled) { settled = true; resolve({ entries: count, totalSize: total }); } });
    zip.on('close', () => { if (!settled) fail(new Error('ZIP closed before all entries were extracted')); });
    zip.on('entry', async entry => {
      try {
        const directory = entry.fileName.endsWith('/'), name = safeName(entry.fileName, directory);
        const type = (entry.externalFileAttributes >>> 16) & 0xf000;
        assert([0, directory ? 0x4000 : 0x8000].includes(type) && !(entry.externalFileAttributes & 0x400), 'Windows signing input cannot contain links or special files');
        assert(!((entry.generalPurposeBitFlag || 0) & 1), 'Encrypted signing input is unsupported');
        assert([0, 8].includes(entry.compressionMethod ?? 0), 'Unsupported ZIP compression');
        assert(Number.isSafeInteger(entry.uncompressedSize) && entry.uncompressedSize >= 0 && entry.uncompressedSize <= budget.fileSize, 'ZIP file size limit exceeded');
        count++; total += entry.uncompressedSize;
        assert(count <= budget.entries && total <= budget.totalSize, 'ZIP resource limit exceeded');
        const parts = name.split('/');
        for (let i = 1; i <= parts.length; i++) {
          const current = parts.slice(0, i).join('/'), key = current.normalize('NFC').toLowerCase();
          const isDirectory = i < parts.length || directory, old = names.get(key), explicit = i === parts.length;
          if (old) {
            assert(old.name === current && old.directory && isDirectory && !(old.explicit && explicit), `Duplicate or colliding ZIP path: ${current}`);
            if (explicit) old.explicit = true;
          } else names.set(key, { name: current, directory: isDirectory, explicit });
        }
        const target = path.join(destination, ...parts);
        if (directory) { assert.equal(entry.uncompressedSize, 0); fs.mkdirSync(target, { recursive: true }); }
        else {
          fs.mkdirSync(path.dirname(target), { recursive: true });
          const stream = await new Promise((res, rej) => zip.openReadStream(entry, (error, value) => error ? rej(error) : res(value)));
          let written = 0;
          await pipeline(stream, new Transform({ transform(chunk, encoding, callback) {
            written += chunk.length;
            if (written > entry.uncompressedSize) callback(new Error('ZIP member size overflow'));
            else callback(null, chunk);
          } }), fs.createWriteStream(target, { flags: 'wx' }));
          assert.equal(written, entry.uncompressedSize, 'ZIP member truncated');
        }
        if (!settled) zip.readEntry();
      } catch (error) { fail(error); }
    });
    zip.readEntry();
  });
}
function verifyChecksums(root, files) {
  const sumsFile = path.join(root, 'SHA256SUMS.txt');
  assert(fs.statSync(sumsFile).size < 16 * 1024 ** 2, 'Input checksum inventory is too large');
  const lines = fs.readFileSync(sumsFile, 'utf8').replace(/^\uFEFF/, '').trim().split(/\r?\n/);
  const expected = new Map();
  for (const line of lines) {
    const match = /^([a-f0-9]{64})  (.+)$/.exec(line); assert(match, 'Malformed input checksum entry');
    const name = safeName(match[2]); assert(name !== 'SHA256SUMS.txt' && !expected.has(name), 'Duplicate or self-referential checksum entry');
    expected.set(name, match[1]);
  }
  assert.deepEqual(files.filter(x => x.file !== 'SHA256SUMS.txt').map(x => x.file).sort(), [...expected.keys()].sort(), 'Input checksum inventory does not cover the complete archive');
  for (const entry of files) if (entry.file !== 'SHA256SUMS.txt') assert.equal(entry.sha256, expected.get(entry.file), `Input SHA-256 mismatch: ${entry.file}`);
  return { passed: true, files: expected.size };
}
function verifyBuildInfo(config, root, receipt) {
  const info = metadata(path.join(root, 'BUILD-INFO.json'));
  assert.equal(info.schemaVersion, 1);
  for (const key of ['version', 'studioRepository', 'studioCommit', 'engineRepository', 'engineCommit', 'engineVersion']) assert.equal(info[key], config[key], `BUILD-INFO ${key} mismatch`);
  assert.equal(info.platform, 'win32'); assert.equal(info.arch, 'x64'); assert.equal(info.signingStatus, 'unsigned');
  assert.equal(info.updateChannel, config.channel); assert.equal(info.updateBaseUrl, config.updateBaseUrl);
  assert.equal(info.workflowRepository, receipt.build.repository); assert.equal(String(info.runId), String(receipt.build.runId));
  assert.equal(info.workflowCommit, receipt.build.workflowCommit);
  assert.equal(info.runUrl, `https://github.com/${receipt.build.repository}/actions/runs/${receipt.build.runId}`);
  return info;
}
function verifyPeInventory(config, root, files) {
  const name = `DFCode-${config.version}-x64.exe`, installerPath = `unsigned-installers/${name}`;
  const actual = files.filter(x => payload.inspectPe(path.join(root, x.file)));
  const inventory = metadata(path.join(root, 'PE-INVENTORY.json'));
  assert(Array.isArray(inventory)); const mapped = new Map();
  for (const entry of inventory) {
    const file = entry.path === name ? installerPath : safeName(entry.path);
    assert(!mapped.has(file), 'Duplicate PE inventory entry');
    assert.equal(entry.signingMode, 'none'); assert.equal(entry.signed, false);
    mapped.set(file, entry);
  }
  assert.deepEqual(actual.map(x => x.file).sort(), [...mapped.keys()].sort(), 'PE inventory is incomplete');
  for (const entry of actual) {
    const expected = mapped.get(entry.file), pe = payload.inspectPe(path.join(root, entry.file));
    assert.equal(entry.sha256, expected.sha256); assert.equal(entry.size, expected.size);
    const expectedMachine = [installerPath, 'win-unpacked/resources/elevate.exe'].includes(entry.file) ? 0x14c : 0x8664;
    assert.equal(pe.machine, expectedMachine, `Unexpected PE architecture: ${entry.file}`);
  }
  assert(actual.some(x => x.file === installerPath), 'Unsigned NSIS installer is missing');
  assert.equal(hashFile(path.join(root, 'PE-INVENTORY.json')), hashFile(path.join(root, 'unsigned-installers/PE-INVENTORY.json')), 'Installer PE inventory differs');
  return { passed: true, files: actual.length };
}
async function verifyAndExtractInput(config, options = {}) {
  const receipt = verifyReceipt(config), req = options.requireFromStudio || requireFromStudio(config.workspace);
  const root = options.destination; assert(root && path.isAbsolute(root), 'An absolute new extraction destination is required');
  await extractZip(receipt.artifact.path, root, req('yauzl'), options.limits);
  const files = payload.inventoryTree(root), checksums = verifyChecksums(root, files);
  const buildInfo = verifyBuildInfo(config, root, receipt);
  const packagingRoot = path.join(root, 'packaging-config'), packageFile = path.join(packagingRoot, 'desktop-package.json');
  const packageJson = metadata(packageFile), engineLockFile = path.join(packagingRoot, 'engine-lock.json'), engineLock = metadata(engineLockFile);
  assert.equal(packageJson.version, config.version); assert.equal(packageJson.name, '@studio/desktop');
  assert.equal(engineLock.commit, config.engineCommit);
  assert.equal(engineLock.repository.replace(/^https:\/\/github\.com\//, '').replace(/\.git$/, ''), config.engineRepository);
  const signingHook = path.join(packagingRoot, 'windows-signing-hook.mjs'), buildResources = path.join(packagingRoot, 'build');
  const payloadRoot = path.join(root, 'win-unpacked');
  for (const required of [signingHook, path.join(root, `studio-source-${config.studioCommit}.zip`), path.join(buildResources, 'dfcode-icon.ico')]) assert(fs.statSync(required).isFile(), 'Incomplete packaging/source handoff');
  assert.equal(hashFile(path.join(buildResources, 'dfcode-icon.ico')), hashFile(path.join(payloadRoot, 'resources/dfcode-icon.ico')), 'Packaged icon differs from source packaging input');
  const packagingConfig = { root: packagingRoot, packageFile, packageJson, build: packageJson.build, engineLockFile, engineLock, signingHook, buildResources };
  const peInventory = verifyPeInventory(config, root, files);
  const installerName = `DFCode-${config.version}-x64.exe`, unsignedDirectory = path.join(root, 'unsigned-installers');
  const originalManifest = path.join(unsignedDirectory, 'FULL-OTA-RELEASE-win32-x64.json');
  const otaEntries = [installerName, `${installerName}.blockmap`, `${config.channel}.yml`].map(name => {
    const file = path.join(unsignedDirectory, name);
    return { name, size: fs.statSync(file).size, sha256: hashFile(file), sha512: hashFile(file, 'sha512', 'base64'), ...(name.endsWith('.yml') ? { text: fs.readFileSync(file, 'utf8') } : {}) };
  });
  otaEntries.push({ name: 'release.json', text: fs.readFileSync(originalManifest, 'utf8').replace(/^\uFEFF/, '') });
  const originalOta = verifyFullOtaEntries(otaEntries, { ...config, otaNotesFile: path.join(root, `studio-v${config.version}-ota.md`) }, { platform: 'win32', arch: 'x64' }, 'unsigned', req('js-yaml'));
  const verifiedPayload = payload.verifyPayload(config, payloadRoot, { signed: false, packagingConfig });
  assert.equal(hashFile(receipt.artifact.path), receipt.artifact.sha256, 'Input archive changed during extraction');
  return { input: { artifact: receipt.artifact, reportFile: receipt.reportFile, reportSha256: receipt.reportSha256 }, build: receipt.build,
    root, payloadRoot, files, packagingConfig, report: { passed: true, checksums, buildInfo, peInventory, originalOta: { passed: true, releaseHash: originalOta.manifest.releaseHash }, payload: verifiedPayload } };
}

module.exports = { ...payload, safeName, verifyReceipt, extractZip, verifyChecksums, verifyBuildInfo, verifyPeInventory, verifyAndExtractInput };
