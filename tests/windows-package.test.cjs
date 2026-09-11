'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const zlib = require('node:zlib');
const P = require('../scripts/windows-package.cjs');
const { hashFile } = require('../scripts/io.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dfcode-win-package-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
test('NSIS repack preserves installer scope and directory selection from source', t => {
  const root = fixture(t); fs.mkdirSync(path.join(root, 'resources')); fs.writeFileSync(path.join(root, 'resources/dfcode-icon.ico'), 'icon');
  const config = { version: '1.2.3', windows: { publisherName: 'Test Publisher' }, updateBaseUrl: 'https://example.test/ota', channel: 'latest' };
  const pkg = { build: { appId: 'ai.dfcode.studio', productName: 'DFCode', artifactName: 'DFCode-${version}-${arch}.${ext}', win: { requestedExecutionLevel: 'asInvoker', signExecutable: true }, nsis: { oneClick: false, allowToChangeInstallationDirectory: true, perMachine: false, allowElevation: false } } };
  const built = P.createBuilderConfig(config, pkg, root, path.join(root, 'out'), '37.10.3');
  assert.equal(built.nsis.allowElevation, false); assert.equal(built.nsis.perMachine, false); assert.equal(built.nsis.allowToChangeInstallationDirectory, true);
  assert.equal(built.forceCodeSigning, true); assert.equal(built.nsis.packElevateHelper, false); assert.match(built.win.signtoolOptions.sign, /windows-sign-hook/);
  pkg.build.nsis.allowElevation = true; assert.equal(P.createBuilderConfig(config, pkg, root, path.join(root, 'out'), '37.10.3').nsis.allowElevation, true);
  pkg.build.nsis.include = 'unreviewed.nsh'; assert.throws(() => P.createBuilderConfig(config, pkg, root, '', ''), /unsupported NSIS/);
});
test('NSIS archive extraction rejects traversal, aliases and links', () => {
  assert.deepEqual(P.safeSevenzipListing('Path = resources\\app.asar\r\nPath = DFCode.exe\r\n'), ['resources\\app.asar', 'DFCode.exe']);
  for (const bad of ['../outside', 'C:\\outside', 'file:stream', 'NUL.txt', 'file.', 'file ', 'a/../b']) assert.throws(() => P.safeSevenzipListing(`Path = ${bad}\n`));
  assert.throws(() => P.safeSevenzipListing('Path = a\nPath = A\n'), /Duplicate/);
  assert.throws(() => P.safeSevenzipListing('Path = safe\nSymbolic Link = elsewhere\n'), /Links/);
});
test('manifest refresh updates signed hash and preserves source, skills and cache settings', t => {
  const root = fixture(t); fs.mkdirSync(path.join(root, 'resources/engine'), { recursive: true });
  const engine = path.join(root, 'resources/engine/dfcode.exe'); fs.writeFileSync(engine, 'signed executable');
  const config = { engineCommit: 'a'.repeat(40), engineVersion: '3.3.18', updateBaseUrl: 'https://example.test', channel: 'latest', windows: { publisherName: 'Publisher' } };
  const mf = path.join(root, 'resources/engine/manifest.json');
  fs.writeFileSync(mf, JSON.stringify({ commit: config.engineCommit, engineVersion: config.engineVersion, skillTreeSha256: 'b'.repeat(64), binarySha256: 'old', signing: { signed: false } }));
  const uf = path.join(root, 'resources/app-update.yml');
  fs.writeFileSync(uf, JSON.stringify({ provider: 'generic', url: config.updateBaseUrl, channel: 'latest', updaterCacheDirName: 'cache' }));
  P.refreshPayloadMetadata(config, root, { yaml: { load: JSON.parse, dump: JSON.stringify } });
  const manifest = JSON.parse(fs.readFileSync(mf)); assert.equal(manifest.binarySha256, hashFile(engine)); assert.equal(manifest.skillTreeSha256, 'b'.repeat(64));
  assert.deepEqual(manifest.signing, { mode: 'keylocker', signed: true, publisherName: 'Publisher' });
  const updater = JSON.parse(fs.readFileSync(uf)); assert.equal(updater.updaterCacheDirName, 'cache'); assert.deepEqual(updater.publisherName, ['Publisher']);
});
test('independent current notes are validated without rewriting source files', t => {
  const root = fixture(t), file = path.join(root, 'notes.md');
  fs.writeFileSync(file, 'New release\r\nDetails\r\n'); assert.equal(P.notes(file), 'New release\nDetails');
  fs.writeFileSync(file, '本次 CI 产物为 unsigned 签名交接包'); assert.throws(() => P.notes(file), /unsigned/);
  fs.writeFileSync(file, 'x'.repeat(4001)); assert.throws(() => P.notes(file), /4000/);
});
test('blockmap validation compares final file bytes and detects stale maps', async t => {
  const root = fixture(t), exe = path.join(root, 'app.exe'), map = `${exe}.blockmap`; fs.writeFileSync(exe, 'final bytes');
  const deps = { buildBlockMap: async (file, mode, out) => fs.writeFileSync(out, zlib.gzipSync(hashFile(file))) };
  await deps.buildBlockMap(exe, 'gzip', map);
  assert.equal(await P.verifyBlockmap(exe, map, path.join(root, 'regenerated'), deps), true);
  fs.appendFileSync(exe, 'changed'); await assert.rejects(P.verifyBlockmap(exe, map, path.join(root, 'regenerated-2'), deps), /final signed installer/);
});
test('embedded uninstaller verification requires exact signed PE bytes', t => {
  const root = fixture(t), expectedFile = path.join(root, 'uninstaller.exe'), installer = path.join(root, 'installer.exe');
  const expected = Buffer.from('MZfixture signed uninstaller'); fs.writeFileSync(expectedFile, expected);
  const header = Buffer.alloc(512); header.write('MZ'); header.writeUInt32LE(64, 0x3c); header.writeUInt32LE(0x4550, 64); header.writeUInt16LE(1, 70); header.writeUInt16LE(0, 84); header.writeUInt32LE(128, 104); header.writeUInt32LE(384, 108);
  const packed = zlib.deflateRawSync(expected), nsis = Buffer.alloc(32 + packed.length + 4);
  Buffer.from('efbeadde4e756c6c736f6674496e7374', 'hex').copy(nsis, 4); nsis.writeUInt32LE(nsis.length, 24); nsis.writeUInt32LE((packed.length | 0x80000000) >>> 0, 28); packed.copy(nsis, 32);
  fs.writeFileSync(installer, Buffer.concat([header, nsis]));
  const result = P.extractUninstaller(installer, expectedFile, path.join(root, 'extracted.exe')); assert.equal(result.passed, true);
  fs.appendFileSync(expectedFile, 'changed'); assert.throws(() => P.extractUninstaller(installer, expectedFile, path.join(root, 'wrong.exe')), /does not contain/);
});
