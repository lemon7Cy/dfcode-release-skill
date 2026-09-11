'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { createSigningApi, MICROSOFT_SUBJECT, peHeader, hashFile } = require('../scripts/windows-sign.cjs');
const { createHook } = require('../scripts/windows-sign-hook.cjs');

const CERT = 'A'.repeat(40);
const PUBLISHER = 'Example Signing Company, Ltd';
const SECRET = 'test-credential-value-never-log';

function fakePe(file, { machine = 0x8664, size = 1027 } = {}) {
  const bytes = Buffer.alloc(size);
  bytes.write('MZ'); bytes.writeUInt32LE(0x80, 0x3c); bytes.write('PE\0\0', 0x80);
  bytes.writeUInt16LE(machine, 0x84); bytes.writeUInt16LE(1, 0x86);
  bytes.writeUInt16LE(machine === 0x8664 ? 240 : 224, 0x94);
  bytes.writeUInt16LE(machine === 0x8664 ? 0x20b : 0x10b, 0x98);
  bytes.writeUInt32LE(16, 0x98 + (machine === 0x8664 ? 108 : 92));
  bytes[700] = 0x5a; bytes[size - 1] = 0x62;
  fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, bytes);
}

function signatureKind(file) {
  const header = peHeader(file);
  if (!header.certificateOffset) return 'unsigned';
  return fs.readFileSync(file).subarray(header.certificateOffset + 8, header.certificateOffset + 40)
    .toString('ascii').replace(/\0.*$/, '');
}

function appendSignature(file, kind = 'company') {
  const original = fs.readFileSync(file), header = peHeader(file);
  assert.equal(header.certificateOffset, 0);
  const offset = Math.ceil(original.length / 8) * 8;
  const bytes = Buffer.alloc(offset + 64);
  original.copy(bytes); bytes.writeUInt32LE(offset, header.securityOffset); bytes.writeUInt32LE(64, header.securityOffset + 4);
  bytes.writeUInt32LE(0xabcdef, header.checksumOffset);
  bytes.writeUInt32LE(64, offset); bytes.writeUInt16LE(0x200, offset + 4); bytes.writeUInt16LE(2, offset + 6);
  bytes.write(kind, offset + 8); fs.writeFileSync(file, bytes);
}

function details(kind) {
  if (kind === 'unsigned') return { status: 'NotSigned', signatureType: 'None', signerSubject: null,
    signerThumbprint: null, publisherName: null, timestampSubject: null, timestampThumbprint: null };
  return { status: kind === 'invalid' ? 'HashMismatch' : 'Valid', signatureType: 'Authenticode',
    signerSubject: kind === 'microsoft' ? MICROSOFT_SUBJECT : kind === 'near-microsoft' ? MICROSOFT_SUBJECT + ', OU=Unexpected' : `CN=${PUBLISHER}`,
    signerThumbprint: kind.startsWith('microsoft') || kind === 'near-microsoft' || kind === 'wrong' ? 'B'.repeat(40) : CERT,
    publisherName: kind === 'microsoft' || kind === 'near-microsoft' ? 'Microsoft Corporation' : kind === 'wrong-publisher' ? 'Different Company' : PUBLISHER,
    timestampSubject: kind === 'no-timestamp' ? null : 'CN=Example timestamp',
    timestampThumbprint: kind === 'no-timestamp' ? null : 'C'.repeat(40) };
}

function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dfcode-sign-test-'));
  t.after(() => { fs.rmSync(root, { recursive: true, force: true }); });
  const ownedRoot = path.join(root, 'owned'), tools = path.join(root, 'tools');
  fs.mkdirSync(ownedRoot);
  const windows = { publisherName: PUBLISHER, certificateSha1: CERT.toLowerCase(), keypairAlias: 'key_selected',
    smctlPath: path.join(tools, 'smctl.exe'), signtoolPath: path.join(tools, 'signtool.exe'), powershellPath: path.join(tools, 'pwsh.exe') };
  for (const tool of [windows.smctlPath, windows.signtoolPath, windows.powershellPath]) fakePe(tool, { size: 1024 });
  const state = { calls: [], signingCalls: 0, outcome: 'success', certOverride: {}, signatureOverride: null,
    signToolOverride: {}, saves: [], failSaveState: null };
  const spawnSync = (tool, args, spawnOptions) => {
    state.calls.push({ tool, args, options: spawnOptions });
    const name = path.basename(tool).toLowerCase();
    if (name === 'pwsh.exe') {
      if (args.includes('-CertificateSha1')) return { status: 0, stdout: JSON.stringify({ thumbprint: CERT,
        publisherName: PUBLISHER, subject: `CN=${PUBLISHER}`, codeSigning: true, currentlyValid: true,
        notBefore: '2025-01-01T00:00:00Z', notAfter: '2035-01-01T00:00:00Z', ...state.certOverride }) };
      const file = args[args.indexOf('-TargetFile') + 1];
      if (state.signatureOverride) return state.signatureOverride(file);
      return { status: 0, stdout: JSON.stringify(details(signatureKind(file))) };
    }
    if (name === 'signtool.exe') return { status: 0, stdout: 'Hash of file (sha256): 123\nNumber of signatures successfully Verified: 1\nNumber of warnings: 0\nNumber of errors: 0\n', ...state.signToolOverride };
    assert.equal(name, 'smctl.exe');
    if (args[0] === '--version') return { status: 0, stdout: `SMCTL 1.67.0\n${SECRET}` };
    assert.equal(args[0], 'sign'); state.signingCalls++;
    const file = args[args.indexOf('--input') + 1];
    assert.notEqual(file, path.join(ownedRoot, 'application.exe'));
    assert.equal(state.saves.at(-1).entries[Object.keys(state.saves.at(-1).entries)[0]].state, 'signing');
    if (state.outcome === 'failure') return { status: 1, stdout: SECRET, stderr: SECRET };
    if (state.outcome === 'timeout') return { status: null, error: new Error(SECRET), stdout: SECRET };
    appendSignature(file, state.outcome === 'wrong-cert' ? 'wrong' : 'company');
    if (state.outcome === 'tamper') { const bytes = fs.readFileSync(file); bytes[700] ^= 0xff; fs.writeFileSync(file, bytes); }
    if (state.outcome === 'success-with-failure') return { status: 1, stderr: SECRET };
    return { status: 0, stdout: SECRET };
  };
  const api = createSigningApi({ platform: options.platform || 'win32', arch: options.arch || 'x64', spawnSync,
    env: { ...windows, SM_API_KEY: SECRET }, processAlive: () => false });
  const config = { windows };
  const file = path.join(ownedRoot, 'application.exe'); fakePe(file);
  const journal = { schemaVersion: 1, entries: {} };
  const save = value => {
    const snapshot = JSON.parse(JSON.stringify(value)); state.saves.push(snapshot);
    if (state.failSaveState && Object.values(snapshot.entries).some(entry => entry.state === state.failSaveState)) {
      throw new Error('simulated interrupted journal storage');
    }
  };
  return { root, ownedRoot, windows, config, file, journal, save, state, api,
    sign: () => api.signFile(file, config, { journal, save, ownedRoot }) };
}

test('preflight selects only the configured public certificate and never claims remote readiness', t => {
  const f = fixture(t);
  const checked = f.api.preflightSigning(f.config);
  assert.equal(checked.credentialStatus, 'tools-ready');
  assert.equal(checked.remoteSigningPermissionVerified, false);
  assert.equal(checked.windows.certificateSha1, CERT);
  assert.equal(checked.windows.keypairAlias, 'key_selected');
  assert.equal(checked.windows.timestampUrl, 'http://timestamp.digicert.com');
  assert.equal(checked.smctlVersion, '1.67.0');
  assert.equal(JSON.stringify(checked).includes(SECRET), false);
  assert.equal(f.state.calls.length, 2);
  assert.deepEqual(f.state.calls[0].args, ['--version']);
  assert.equal(f.state.calls[1].args.at(-1), CERT);
  f.state.certOverride = { thumbprint: 'B'.repeat(40) };
  assert.throws(() => f.api.preflightSigning(f.config), /mismatched/);
  f.state.certOverride = { publisherName: 'Different Company' };
  assert.throws(() => f.api.preflightSigning(f.config), /mismatched/);
});

test('host gate precedes filesystem changes and commands', t => {
  for (const host of [{ platform: 'linux' }, { arch: 'arm64' }]) {
    const f = fixture(t, host);
    assert.throws(() => f.sign(), /native Windows x64/);
    assert.throws(() => f.api.preflightSigning(f.config), /native Windows x64/);
    assert.equal(f.state.calls.length, 0);
    assert.deepEqual(fs.readdirSync(f.ownedRoot), ['application.exe']);
  }
});

test('refuses unconfigured identities, credential fields, unsafe URLs, tools, and outside files', t => {
  const f = fixture(t);
  for (const change of [{ certificateSha1: '' }, { keypairAlias: 'key\nother' }, { apiKey: SECRET },
    { timestampUrl: 'https://user:password@example.com' }, { timestampUrl: 'https://example.com/?token=secret' },
    { smctlPath: 'smctl.exe' }]) {
    assert.throws(() => f.api.preflightSigning({ windows: { ...f.windows, ...change } }));
  }
  const outside = path.join(f.root, 'original.exe'); fakePe(outside);
  assert.throws(() => f.api.signFile(outside, f.config, { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /escaped/);
  assert.equal(f.state.signingCalls, 0);
});

test('unsigned bytes are signed only in a detached copy after journal persistence', t => {
  const f = fixture(t), before = hashFile(f.file);
  const result = f.sign();
  assert.equal(result.action, 'signed'); assert.equal(result.identity, 'configured');
  assert.equal(result.originalSha256, before); assert.notEqual(result.sha256, before);
  assert.equal(result.valid, true); assert.equal(f.state.signingCalls, 1);
  const request = f.state.calls.find(call => call.args[0] === 'sign');
  assert.deepEqual(request.args.filter((_, index) => index !== request.args.indexOf('--input') + 1),
    ['sign', '--simple', '--unsigned', '--keypair-alias', 'key_selected', '--input', '--digalg', 'SHA256', '--timestamp', '--ts-server', 'http://timestamp.digicert.com']);
  assert.equal(request.options.shell, false); assert.equal(request.options.windowsHide, true);
  assert.equal(JSON.stringify(f.journal).includes(SECRET), false);
  assert.equal(JSON.stringify(result).includes(SECRET), false);
  assert.deepEqual(f.state.saves.map(item => Object.values(item.entries)[0].state), ['prepared', 'signing', 'verified', 'committed']);
  assert.equal(f.sign().action, 'reused'); assert.equal(f.state.signingCalls, 1);
});

test('trusted configured signatures with timestamps are reused without a new provider call', t => {
  const f = fixture(t); appendSignature(f.file);
  const before = hashFile(f.file), result = f.sign();
  assert.equal(result.action, 'reused'); assert.equal(result.sha256, before);
  assert.equal(f.state.signingCalls, 0);
});

test('read-only journal verification binds audit copies to the original signed target and identity', t => {
  const f = fixture(t), originalSha256 = hashFile(f.file);
  f.sign();
  const audit = path.join(f.ownedRoot, 'audit', 'Uninstall DFCode.exe');
  fs.mkdirSync(path.dirname(audit)); fs.copyFileSync(f.file, audit);
  fs.unlinkSync(f.file); // electron-builder may remove the original hook target.
  const before = JSON.stringify(f.journal), writes = f.state.saves.length;
  const options = { journal: f.journal, ownedRoot: f.ownedRoot, journalTarget: f.file, originalSha256 };
  const checked = f.api.verifyJournaledFile(audit, f.config, options);
  assert.equal(checked.journalState, 'committed'); assert.equal(checked.identity, 'configured');
  assert.equal(checked.journalTarget, f.file); assert.equal(JSON.stringify(f.journal), before);
  assert.equal(f.state.signingCalls, 1); assert.equal(f.state.saves.length, writes);
  assert.throws(() => f.api.verifyJournaledFile(audit, f.config, { ...options, originalSha256: 'f'.repeat(64) }), /original hash differs/);
  assert.throws(() => f.api.verifyJournaledFile(audit, { windows: { ...f.windows, keypairAlias: 'other_key' } }, options), /identity/);
  assert.throws(() => f.api.verifyJournaledFile(audit, f.config, { ...options, journalTarget: audit }), /Journal entry/);
  const changed = fs.readFileSync(audit); changed[700] ^= 0xff; fs.writeFileSync(audit, changed);
  assert.equal(f.api.verifySignature(audit, f.config).valid, true); // Same trusted fixture signer, different bytes.
  assert.throws(() => f.api.verifyJournaledFile(audit, f.config, options), /signed bytes changed/);
  assert.equal(f.state.signingCalls, 1); assert.equal(JSON.stringify(f.journal), before);
});

test('read-only journal recovery accepts verified replacement bytes but never prepares or retries signing', t => {
  const f = fixture(t); f.sign();
  const entry = Object.values(f.journal.entries)[0], options = { journal: f.journal, ownedRoot: f.ownedRoot };
  entry.state = 'verified';
  const before = JSON.stringify(f.journal);
  assert.equal(f.api.verifyJournaledFile(f.file, f.config, options).journalState, 'verified');
  assert.equal(JSON.stringify(f.journal), before);
  for (const state of ['prepared', 'signing', 'uncertain']) {
    entry.state = state;
    assert.throws(() => f.api.verifyJournaledFile(f.file, f.config, options), /completed signed bytes/);
  }
  assert.throws(() => f.api.verifyJournaledFile(f.file, f.config,
    { ...options, journal: { schemaVersion: 1, entries: {} } }), /Journal entry/);
  assert.equal(f.state.signingCalls, 1);
});

test('only exact Microsoft subjects in two narrowly named files are preserved', t => {
  const f = fixture(t);
  for (const name of ['d3dcompiler_47.dll', 'dxil.dll']) {
    const file = path.join(f.ownedRoot, name); fakePe(file); appendSignature(file, 'microsoft');
    const result = f.api.signFile(file, f.config, { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot });
    assert.equal(result.action, 'preserved-microsoft'); assert.equal(result.preservedMicrosoftSignature, true);
  }
  appendSignature(f.file, 'microsoft'); assert.throws(() => f.sign(), /unapproved/);
  const near = path.join(f.ownedRoot, 'near', 'dxil.dll'); fakePe(near); appendSignature(near, 'near-microsoft');
  assert.throws(() => f.api.signFile(near, f.config, { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /unapproved/);
  assert.equal(f.api.verifySignature(path.join(f.ownedRoot, 'dxil.dll'), { windows: { ...f.windows, preserveMicrosoftSignatures: false } }).valid, false);
  assert.equal(f.state.signingCalls, 0);
});

test('wrong certificates, mismatched publisher, invalid signatures and missing timestamps fail closed', t => {
  for (const kind of ['wrong', 'wrong-publisher', 'invalid', 'no-timestamp']) {
    const f = fixture(t); appendSignature(f.file, kind);
    const before = hashFile(f.file);
    assert.throws(() => f.sign(), /unapproved/);
    assert.equal(hashFile(f.file), before); assert.equal(f.state.signingCalls, 0);
  }
});

test('SignTool warnings, unknown summaries, extra signatures and weak digests reject reuse', t => {
  const f = fixture(t); appendSignature(f.file);
  for (const text of ['Number of warnings: 1\nNumber of errors: 0', 'unrecognized locale output',
    'Number of signatures successfully Verified: 2\nNumber of warnings: 0\nNumber of errors: 0\nHash of file (sha256): abc',
    'Number of signatures successfully Verified: 1\nNumber of warnings: 0\nNumber of errors: 0\nHash of file (sha1): abc']) {
    f.state.signToolOverride = { stdout: text };
    assert.throws(() => f.sign(), /unapproved/);
  }
  assert.equal(f.state.signingCalls, 0);
});

test('failed or timed-out provider outcomes never mutate the target or automatically re-sign', t => {
  for (const outcome of ['failure', 'timeout', 'wrong-cert']) {
    const f = fixture(t), before = hashFile(f.file); f.state.outcome = outcome;
    assert.throws(() => f.sign(), error => /no automatic retry/.test(error.message) && !error.message.includes(SECRET));
    assert.equal(hashFile(f.file), before); assert.equal(f.state.signingCalls, 1);
    assert.equal(Object.values(f.journal.entries)[0].state, 'uncertain');
    assert.throws(() => f.sign(), /no automatic retry/);
    assert.equal(f.state.signingCalls, 1); assert.equal(JSON.stringify(f.journal).includes(SECRET), false);
  }
});

test('provider error with an actually valid signed detached copy is recovered without another sign', t => {
  const f = fixture(t); f.state.outcome = 'success-with-failure';
  assert.equal(f.sign().valid, true); assert.equal(f.state.signingCalls, 1);
  assert.equal(f.sign().action, 'reused'); assert.equal(f.state.signingCalls, 1);
});

test('resume verifies and reuses detached signed bytes after interrupted journal persistence', t => {
  const f = fixture(t), before = hashFile(f.file); f.state.failSaveState = 'verified';
  assert.throws(() => f.sign(), /interrupted journal/);
  assert.equal(hashFile(f.file), before); assert.equal(f.state.signingCalls, 1);
  const entry = Object.values(f.journal.entries)[0]; assert.equal(signatureKind(entry.tempPath), 'company');
  // Model a disk journal that was last persisted immediately before provider invocation.
  entry.state = 'signing'; delete entry.signedSha256; delete entry.result; f.state.failSaveState = null;
  assert.equal(f.sign().action, 'reused'); assert.equal(f.state.signingCalls, 1);
  assert.equal(signatureKind(f.file), 'company');
});

test('interruption after atomic replacement resumes from the journaled signed hash', t => {
  const f = fixture(t); f.state.failSaveState = 'committed';
  assert.throws(() => f.sign(), /interrupted journal/);
  const entry = Object.values(f.journal.entries)[0]; entry.state = 'verified'; f.state.failSaveState = null;
  assert.equal(fs.existsSync(entry.tempPath), false);
  assert.equal(f.sign().action, 'reused'); assert.equal(f.state.signingCalls, 1);
});

test('no sign occurs until signing state is durably saved', t => {
  const f = fixture(t); f.state.failSaveState = 'signing';
  assert.throws(() => f.sign(), /interrupted journal/);
  assert.equal(f.state.signingCalls, 0); assert.equal(signatureKind(f.file), 'unsigned');
  const g = fixture(t);
  assert.throws(() => g.api.signFile(g.file, g.config, { journal: g.journal, ownedRoot: g.ownedRoot, save: async () => {} }), /synchronously/);
  assert.equal(g.state.signingCalls, 0);
});

test('tampered provider bytes and later committed-byte mutation are never accepted or re-signed', t => {
  const f = fixture(t), before = hashFile(f.file); f.state.outcome = 'tamper';
  assert.throws(() => f.sign(), /content differs/);
  assert.equal(hashFile(f.file), before); assert.equal(f.state.signingCalls, 1);
  assert.throws(() => f.sign(), /content differs/); assert.equal(f.state.signingCalls, 1);
  const g = fixture(t); g.sign(); const bytes = fs.readFileSync(g.file); bytes[700] ^= 0xff; fs.writeFileSync(g.file, bytes);
  assert.throws(() => g.sign(), /Committed signing target changed/); assert.equal(g.state.signingCalls, 1);
});

test('journal identity and ownership changes cannot silently start a new signing operation', t => {
  const f = fixture(t); f.state.outcome = 'failure'; assert.throws(() => f.sign());
  assert.throws(() => f.api.signFile(f.file, { windows: { ...f.windows, keypairAlias: 'another_key' } },
    { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /Journal entry does not match/);
  assert.equal(f.state.signingCalls, 1);
});

test('live per-file signing locks prevent concurrent provider calls', t => {
  const f = fixture(t);
  const temp = path.join(f.ownedRoot, '.signing-staging'); fs.mkdirSync(temp);
  const key = crypto.createHash('sha256').update(f.file.toLowerCase()).digest('hex');
  const lock = path.join(temp, `${key}.lock.json`); fs.writeFileSync(lock, JSON.stringify({ schemaVersion: 1, key, pid: process.pid }));
  const live = createSigningApi({ platform: 'win32', arch: 'x64', processAlive: () => true });
  assert.throws(() => live.signFile(f.file, f.config, { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /live process/);
  assert.equal(f.state.signingCalls, 0); assert.equal(fs.existsSync(lock), true);
});

test('hardlinks, junction escapes and alternate stream paths are rejected before signing', t => {
  const f = fixture(t), outside = path.join(f.root, 'original.exe'); fakePe(outside);
  const linked = path.join(f.ownedRoot, 'linked.exe'); fs.linkSync(outside, linked);
  assert.throws(() => f.api.signFile(linked, f.config, { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /hard linked/);
  const externalDirectory = path.join(f.root, 'external'); fs.mkdirSync(externalDirectory);
  fakePe(path.join(externalDirectory, 'outside.exe'));
  const junction = path.join(f.ownedRoot, 'junction'); fs.symlinkSync(externalDirectory, junction, 'junction');
  assert.throws(() => f.api.signFile(path.join(junction, 'outside.exe'), f.config,
    { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /links or junctions/);
  assert.throws(() => f.api.signFile(f.file + ':secret.exe', f.config,
    { journal: f.journal, save: f.save, ownedRoot: f.ownedRoot }), /Alternate streams/);
  assert.equal(f.state.signingCalls, 0);
});

test('resume fails closed if an unresolved detached signature disappears', t => {
  const f = fixture(t); f.state.outcome = 'timeout'; assert.throws(() => f.sign(), /no automatic retry/);
  const entry = Object.values(f.journal.entries)[0]; fs.unlinkSync(entry.tempPath);
  assert.throws(() => f.sign(), /detached copy is missing/); assert.equal(f.state.signingCalls, 1);
});

test('builder hook propagates failure and saves only a matching signed uninstaller audit copy', async t => {
  const f = fixture(t);
  const configFile = path.join(f.ownedRoot, 'hook.json'), journalFile = path.join(f.ownedRoot, 'audit/hook-journal.json');
  const uninstallerPath = path.join(f.ownedRoot, 'audit/Uninstall DFCode.exe');
  fs.writeFileSync(configFile, JSON.stringify({ schemaVersion: 1, windows: f.windows, ownedRoot: f.ownedRoot, journalFile, uninstallerPath }));
  const file = path.join(f.ownedRoot, 'DFCode-x64.__uninstaller.exe'); fakePe(file);
  // Hook uses a separate durable journal, so only replace the fixture's persistence assertion.
  const hookApi = { assertHost: () => {}, signFile: (target, config, opts) => {
    assert.equal(target, file); assert.equal(config.windows.keypairAlias, 'key_selected');
    assert.equal(opts.ownedRoot, f.ownedRoot); opts.save(opts.journal);
    appendSignature(target); return { sha256: hashFile(target), valid: true };
  } };
  const hook = createHook(hookApi, { DFCODE_WINDOWS_SIGN_CONFIG: configFile });
  await assert.rejects(() => hook({ path: file, hash: 'sha1' }), /SHA256/);
  const result = await hook({ path: file, hash: 'sha256' });
  assert.equal(hashFile(uninstallerPath), result.sha256); assert.equal(fs.existsSync(journalFile), true);
  const failing = createHook({ assertHost: () => {}, signFile: () => { throw new Error('provider refused'); } },
    { DFCODE_WINDOWS_SIGN_CONFIG: configFile });
  await assert.rejects(() => failing({ path: file, hash: 'sha256' }), /provider refused/);
});
