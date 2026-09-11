'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { createWindowsPlan, run, assertNativeHost, windowsRelease, configBinding } = require('../scripts/windows-release.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dfcode-windows-handoff-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = {
    version: '0.2.99-rc.1', studioRepository: 'example/studio', studioCommit: 'a'.repeat(40),
    engineRepository: 'example/engine', engineCommit: 'b'.repeat(40), engineVersion: '3.3.18',
    buildRepository: 'example/fork', channel: 'latest', updateBaseUrl: 'https://updates.example.com/ota/latest',
    workspace: path.join(root, 'source'), outputDir: path.join(root, 'release'),
    releaseNotesFile: path.join(root, 'new-full-notes.md'), otaNotesFile: path.join(root, 'new-ota-notes.md'),
  };
  let output = ''; let errors = '';
  const options = { loadConfig: () => config, stdout: { write: value => { output += value; } }, stderr: { write: value => { errors += value; } } };
  return { root, config, options, output: () => output, errors: () => errors };
}

test('default prints a Windows plan without creating directories or reading credentials', t => {
  const f = fixture(t);
  assert.equal(run(['--config', 'release.json'], f.options), 0);
  const plan = JSON.parse(f.output());
  assert.equal(plan.status, 'handoff-only');
  assert.deepEqual(plan.target, { platform: 'win32', arch: 'x64' });
  assert.equal(plan.signing.implemented, true);
  assert.equal(plan.handoffWritten, false);
  assert.equal(plan.inputs.otaNotesFile, f.config.otaNotesFile);
  assert.equal(plan.inputs.ciVerificationReport, path.join(f.config.outputDir, 'reports', 'verify-ci.json'));
  assert.equal(fs.existsSync(f.config.outputDir), false);
});

test('execute writes only an ASCII-named version-specific document and is idempotent', t => {
  const f = fixture(t);
  assert.equal(run(['--config', 'release.json', '--execute'], f.options), 0);
  const plan = createWindowsPlan(f.config);
  const body = fs.readFileSync(plan.handoffFile, 'utf8');
  assert.equal(path.basename(plan.handoffFile), 'Windows-0.2.99-rc.1-signing-handoff.md');
  assert.equal(body.includes(f.config.otaNotesFile), true);
  assert.equal(body.includes(plan.inputs.ciVerificationReport), true);
  assert.equal(body.includes(`${f.config.studioRepository}@${f.config.studioCommit}`), true);
  assert.deepEqual(fs.readdirSync(f.config.outputDir), ['delivery']);
  assert.deepEqual(fs.readdirSync(path.dirname(plan.handoffFile)), [path.basename(plan.handoffFile)]);
  assert.equal(run(['--config', 'release.json', '--execute'], f.options), 0);
  assert.equal(fs.readFileSync(plan.handoffFile, 'utf8'), body);
});

test('execute does not overwrite an independently edited handoff', t => {
  const f = fixture(t);
  const plan = createWindowsPlan(f.config);
  fs.mkdirSync(path.dirname(plan.handoffFile), { recursive: true });
  fs.writeFileSync(plan.handoffFile, 'Existing user notes');
  assert.equal(run(['--config', 'release.json', '--execute'], f.options), 1);
  assert.equal(fs.readFileSync(plan.handoffFile, 'utf8'), 'Existing user notes');
});

test('invalid sign arguments fail before config loading or side effects', async t => {
  const f = fixture(t);
  f.options.loadConfig = () => { throw new Error('must not load config'); };
  assert.equal(await run(['--config', 'release.json', '--execute', '--sign', '--typo'], f.options), 1);
  assert.match(f.errors(), /Unknown or incomplete/);
  assert.equal(fs.existsSync(f.config.outputDir), false);
});

test('CLI sign request requires a config and does not use credentials on missing config', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, '../scripts/windows-release.cjs'), '--sign'], { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /config is required/i);
});

test('sign plan is side-effect free even with absent inputs and credential setup', async t => {
  const f = fixture(t);
  assert.equal(await run(['--config', 'release.json', '--sign'], f.options), 0);
  const plan = JSON.parse(f.output());
  assert.equal(plan.status, 'planned'); assert.equal(plan.signing.performed, false);
  assert.equal(fs.existsSync(f.config.outputDir), false);
});

test('host gates reject cross-platform signing before native tools or output', async t => {
  const f = fixture(t);
  for (const [platform, arch] of [['darwin', 'arm64'], ['linux', 'x64'], ['win32', 'arm64'], ['win32', 'ia32']]) assert.throws(() => assertNativeHost(platform, arch), /Windows x64/);
  assertNativeHost('win32', 'x64');
  if (process.platform === 'win32' && process.arch === 'x64') {
    await assert.rejects(windowsRelease(f.config, { execute: true }), /publisherName, certificateSha1 and keypairAlias/);
    assert.equal(fs.existsSync(f.config.outputDir), false);
  }
});

test('Windows checkpoint binding detects notes and signing identity changes', t => {
  const f = fixture(t);
  fs.writeFileSync(f.config.otaNotesFile, 'OTA notes'); fs.writeFileSync(f.config.releaseNotesFile, 'Full notes');
  const first = configBinding(f.config);
  fs.appendFileSync(f.config.otaNotesFile, ' changed'); assert.notEqual(configBinding(f.config), first);
  fs.writeFileSync(f.config.otaNotesFile, 'OTA notes'); assert.equal(configBinding(f.config), first);
  assert.notEqual(configBinding({ ...f.config, windows: { publisherName: 'Other' } }), first);
});

test('CLI consumes the shared flat config without invoking a platform signing path', t => {
  const f = fixture(t);
  const configFile = path.join(f.root, 'release.json');
  fs.writeFileSync(configFile, JSON.stringify(f.config));
  const result = spawnSync(process.execPath, [path.join(__dirname, '../scripts/windows-release.cjs'), '--config', configFile], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const plan = JSON.parse(result.stdout);
  assert.equal(plan.inputs.otaNotesFile, f.config.otaNotesFile);
  assert.equal(plan.publication.performed, false);
  assert.equal(plan.verification.performed, false);
  assert.equal(fs.existsSync(f.config.outputDir), false);
});

test('unsafe versions and unrecognized options fail without writes', t => {
  const f = fixture(t);
  assert.equal(run(['--config', 'release.json', '--publish'], f.options), 1);
  f.config.version = '../../elsewhere';
  assert.equal(run(['--config', 'release.json', '--execute'], f.options), 1);
  assert.equal(fs.existsSync(f.config.outputDir), false);
});
