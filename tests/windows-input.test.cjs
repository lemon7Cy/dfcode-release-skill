'use strict';
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');
const I = require('../scripts/windows-input.cjs');
const { hashFile } = require('../scripts/io.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dfcode-windows-input-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function reader(samples, earlyClose = false) {
  return { open(_file, settings, callback) {
    assert.equal(settings.strictFileNames, true); assert.equal(settings.lazyEntries, true);
    const zip = new EventEmitter(); let cursor = 0, closed = false;
    zip.close = () => { closed = true; zip.emit('close'); };
    zip.readEntry = () => queueMicrotask(() => {
      if (closed) return;
      if (earlyClose) return zip.close();
      const item = samples[cursor++];
      if (!item) { zip.emit('end'); zip.close(); return; }
      const content = Buffer.from(item.content || '');
      zip.emit('entry', { fileName: item.name, externalFileAttributes: 0, uncompressedSize: content.length, content, ...item });
    });
    zip.openReadStream = (entry, done) => done(null, Readable.from([entry.content]));
    callback(null, zip);
  } };
}
test('Windows input streams nested files and preserves an existing extraction', async t => {
  const root = fixture(t), destination = path.join(root, 'extracted');
  const result = await I.extractZip('fixture.zip', destination, reader([{ name: 'payload/' }, { name: 'payload/data', content: 'sample' }, { name: 'empty' }]));
  assert.equal(result.entries, 3); assert.equal(result.totalSize, 6);
  assert.equal(fs.readFileSync(path.join(destination, 'payload/data'), 'utf8'), 'sample');
  await assert.rejects(I.extractZip('fixture.zip', destination, reader([])), /Preserve existing/);
});
test('Windows archive rejects unsafe, aliased, colliding, encrypted and link entries', async t => {
  const root = fixture(t); let index = 0;
  const cases = [
    [{ name: '../outside' }], [{ name: 'C:/outside' }], [{ name: 'a\\b' }], [{ name: 'file:stream' }],
    [{ name: 'NUL.txt' }], [{ name: 'COM¹' }], [{ name: 'a.' }], [{ name: 'a ' }],
    [{ name: 'a' }, { name: 'A' }], [{ name: 'a' }, { name: 'a/b' }], [{ name: 'A/b' }, { name: 'a/c' }],
    [{ name: 'a', externalFileAttributes: 0xa000 << 16 }], [{ name: 'a', externalFileAttributes: 0x400 }],
    [{ name: 'a', generalPurposeBitFlag: 1 }], [{ name: 'a', compressionMethod: 99 }],
  ];
  for (const samples of cases) await assert.rejects(I.extractZip('fixture.zip', path.join(root, `case-${index++}`), reader(samples)));
  assert.equal(fs.existsSync(path.join(root, 'outside')), false);
});
test('Windows archive enforces streamed sizes, resource budgets and completion', async t => {
  const root = fixture(t);
  await assert.rejects(I.extractZip('fixture.zip', path.join(root, 'overflow'), reader([{ name: 'a', content: 'large', uncompressedSize: 1 }])), /overflow/);
  await assert.rejects(I.extractZip('fixture.zip', path.join(root, 'truncated'), reader([{ name: 'a', content: 'small', uncompressedSize: 10 }])), /truncated/);
  await assert.rejects(I.extractZip('fixture.zip', path.join(root, 'entries'), reader([{ name: 'a' }, { name: 'b' }]), { entries: 1 }), /resource limit/);
  await assert.rejects(I.extractZip('fixture.zip', path.join(root, 'size'), reader([{ name: 'a', content: 'large' }]), { totalSize: 1 }), /resource limit/);
  await assert.rejects(I.extractZip('fixture.zip', path.join(root, 'closed'), reader([], true)), /closed before/);
});
function receiptFixture(t) {
  const root = fixture(t), config = { outputDir: root, version: '1.2.3', studioCommit: 'a'.repeat(40), engineCommit: 'b'.repeat(40), engineVersion: '3.3.18', buildRepository: 'example/build' };
  fs.mkdirSync(path.join(root, 'unsigned-ci')); fs.mkdirSync(path.join(root, 'reports'));
  const name = 'DFCode-1.2.3-win32-x64-signing-input-unsigned.zip', file = path.join(root, 'unsigned-ci', name);
  fs.writeFileSync(file, 'fixture archive');
  const artifact = { name, path: '/Users/old-mac/unsigned-ci/' + name, sha256: hashFile(file), size: fs.statSync(file).size, kind: 'signing-input', target: { platform: 'win32', arch: 'x64' } };
  fs.writeFileSync(file + '.sha256', `${artifact.sha256}  ${name}\n`);
  const report = { schemaVersion: 1, status: 'verified', version: config.version, source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, build: { repository: config.buildRepository, runId: 123, workflowCommit: 'c'.repeat(40) }, artifacts: [artifact] };
  const save = () => fs.writeFileSync(path.join(root, 'reports/verify-ci.json'), JSON.stringify(report)); save();
  return { config, report, save, file };
}
test('Mac receipt resolves only the expected Windows-local input basename', t => {
  const f = receiptFixture(t), result = I.verifyReceipt(f.config);
  assert.equal(result.artifact.path, f.file); assert.equal(result.artifact.sha256, hashFile(f.file));
  assert.notEqual(result.artifact.path, f.report.artifacts[0].path);
});
test('receipt refuses mixed source, duplicate artifacts, changed bytes and sidecars', t => {
  for (const kind of ['source', 'duplicate', 'archive', 'sidecar', 'repository']) {
    const f = receiptFixture(t);
    if (kind === 'source') f.report.source.studioCommit = 'd'.repeat(40);
    if (kind === 'duplicate') f.report.artifacts.push({ ...f.report.artifacts[0] });
    if (kind === 'archive') fs.appendFileSync(f.file, 'changed');
    if (kind === 'sidecar') fs.writeFileSync(f.file + '.sha256', 'bad digest');
    if (kind === 'repository') f.report.build.repository = 'wrong/repository';
    f.save(); assert.throws(() => I.verifyReceipt(f.config));
  }
});
test('internal checksum list covers every original file and rejects changed bytes', t => {
  const root = fixture(t), file = path.join(root, 'payload'); fs.writeFileSync(file, 'original');
  fs.writeFileSync(path.join(root, 'SHA256SUMS.txt'), `${hashFile(file)}  payload\n`);
  assert.equal(I.verifyChecksums(root, I.inventoryTree(root)).files, 1);
  fs.writeFileSync(path.join(root, 'extra'), 'unlisted');
  assert.throws(() => I.verifyChecksums(root, I.inventoryTree(root)), /complete archive/);
  fs.unlinkSync(path.join(root, 'extra')); fs.appendFileSync(file, 'changed');
  assert.throws(() => I.verifyChecksums(root, I.inventoryTree(root)), /SHA-256 mismatch/);
});
test('BUILD-INFO must match the collected workflow, pins and target', t => {
  const root = fixture(t), config = { version: '1.2.3', studioRepository: 'example/studio', studioCommit: 'a'.repeat(40), engineRepository: 'example/engine', engineCommit: 'b'.repeat(40), engineVersion: '3.3.18', channel: 'latest', updateBaseUrl: 'https://example.test/ota' };
  const build = { repository: 'example/build', runId: 123, workflowCommit: 'c'.repeat(40) };
  const info = { ...config, schemaVersion: 1, platform: 'win32', arch: 'x64', signingStatus: 'unsigned', updateChannel: config.channel, workflowRepository: build.repository, runId: '123', workflowCommit: build.workflowCommit, runUrl: 'https://github.com/example/build/actions/runs/123' };
  const file = path.join(root, 'BUILD-INFO.json'); fs.writeFileSync(file, JSON.stringify(info));
  assert.equal(I.verifyBuildInfo(config, root, { build }).workflowCommit, build.workflowCommit);
  info.workflowCommit = 'd'.repeat(40); fs.writeFileSync(file, JSON.stringify(info));
  assert.throws(() => I.verifyBuildInfo(config, root, { build }));
});
