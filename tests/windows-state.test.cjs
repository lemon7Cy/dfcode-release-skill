'use strict';

// Execute the actual route and durable filesystem checkpoints, replacing only
// external APIs in a test-local VM. Production CLI has no bypass or injection.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');
const io = require('../scripts/io.cjs');
const realPackage = require('../scripts/windows-package.cjs');

function write(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
}
function inventory(root) {
  const files = [];
  const visit = (directory, prefix = '') => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file, relative);
      else files.push({ file: relative, size: fs.statSync(file).size, sha256: io.hashFile(file) });
    }
  };
  visit(root);
  return files.sort((a, b) => a.file.localeCompare(b.file));
}

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dfcode-windows-state-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const config = {
    schemaVersion: 1, version: '0.2.99', studioRepository: 'example/studio', studioCommit: 'a'.repeat(40),
    engineRepository: 'example/engine', engineCommit: 'b'.repeat(40), engineVersion: '3.3.18', buildRepository: 'example/fork',
    channel: 'latest', updateBaseUrl: 'https://updates.example.com/ota/latest',
    outputDir: path.join(root, 'release'), workspace: path.join(root, 'studio'),
    otaNotesFile: path.join(root, 'current-ota.md'), releaseNotesFile: path.join(root, 'current-release.md'),
    windows: { publisherName: 'Example Company', certificateSha1: 'C'.repeat(40), keypairAlias: 'key_selected' },
  };
  write(config.otaNotesFile, 'Current independent OTA notes'); write(config.releaseNotesFile, 'Current full release notes');
  fs.mkdirSync(config.workspace);
  const artifact = path.join(config.outputDir, 'unsigned-ci', `DFCode-${config.version}-win32-x64-signing-input-unsigned.zip`);
  write(artifact, 'immutable unsigned fixture archive');
  const counts = { preflight: 0, input: 0, signProvider: 0, signOrder: [], build: 0, extract: 0, finalize: 0, probe: 0, blockmap: 0 };
  const behavior = { failAfterInnerCommit: false, failBeforeInnerReplacement: false, build: null, metadata: null, tamperFinal: false, engineVersion: config.engineVersion,
    failFinalSignature: false, lockDuringBuild: null, failBeforeMetadata: false, failBeforeBuild: false, failFinalReport: false };
  let currentPaths;
  const signature = file => {
    const bytes = fs.readFileSync(file, 'utf8');
    const microsoft = bytes.startsWith('MICROSOFT:');
    const signed = bytes.startsWith('SIGNED:') || microsoft;
    return { path: file, valid: signed && !(behavior.failFinalSignature && file.includes(`${path.sep}verify-`)),
      identity: microsoft ? 'microsoft' : signed ? 'configured' : 'unsigned', status: signed ? 'Valid' : 'NotSigned',
      sha256: io.hashFile(file), size: fs.statSync(file).size, signerThumbprint: microsoft ? 'D'.repeat(40) : config.windows.certificateSha1,
      timestampThumbprint: signed ? 'E'.repeat(40) : null };
  };
  const inputApi = {
    // Production modules share one realm. Return fixture inventory in the
    // route's realm so checkpoint JSON and fresh inventory keep that contract.
    inventoryTree: root => vm.runInContext('JSON.parse', context)(JSON.stringify(inventory(root))),
    inspectPe: file => /\.(exe|dll|node)$/i.test(file),
    peContentDigest: file => fs.readFileSync(file, 'utf8').replace(/^SIGNED:/, ''),
    verifyAndExtractInput: async (_, { destination }) => {
      counts.input++;
      const payloadRoot = path.join(destination, 'win-unpacked');
      write(path.join(payloadRoot, 'DFCode.exe'), 'main unsigned bytes');
      write(path.join(payloadRoot, 'dxil.dll'), 'MICROSOFT:original trusted library');
      write(path.join(payloadRoot, 'resources/engine/dfcode.exe'), 'engine unsigned bytes');
      write(path.join(payloadRoot, 'resources/app.asar'), 'immutable complete ASAR bytes');
      write(path.join(payloadRoot, 'resources/engine/skill/builtin/example/SKILL.md'), '# immutable builtin skill');
      write(path.join(payloadRoot, 'resources/engine/manifest.json'), JSON.stringify({ commit: config.engineCommit,
        engineVersion: config.engineVersion, binarySha256: io.hashFile(path.join(payloadRoot, 'resources/engine/dfcode.exe')),
        skillTreeSha256: 'f'.repeat(64), signing: { mode: 'none', signed: false } }));
      write(path.join(payloadRoot, 'resources/app-update.yml'), JSON.stringify({ provider: 'generic', url: config.updateBaseUrl,
        channel: config.channel, updaterCacheDirName: 'fixed-cache' }));
      write(path.join(destination, 'BUILD-INFO.json'), JSON.stringify({ version: config.version }));
      return { root: destination, payloadRoot, packagingConfig: { build: {} }, report: { status: 'verified' },
        build: { localFixture: true }, input: { artifact: { path: artifact, sha256: io.hashFile(artifact) } } };
    },
    verifyPayload: (_, payload, options) => {
      assert.equal(options.signed, true);
      const manifest = JSON.parse(fs.readFileSync(path.join(payload, 'resources/engine/manifest.json'), 'utf8'));
      assert.equal(manifest.binarySha256, io.hashFile(path.join(payload, 'resources/engine/dfcode.exe')));
      assert.equal(manifest.commit, config.engineCommit); assert.equal(manifest.signing.signed, true);
      return { passed: true, files: inventory(payload).length };
    },
  };
  const signingApi = {
    preflightSigning: selected => { counts.preflight++; return { windows: { ...selected.windows }, provider: 'keylocker-smctl-simple', credentialStatus: 'tools-ready' }; },
    verifySignature: signature,
    verifyJournaledFile: (file, selected, { journal, ownedRoot, journalTarget = file, originalSha256 }) => {
      const record = journal.entries[path.relative(ownedRoot, journalTarget)];
      assert(record && record.path === journalTarget && record.binding === JSON.stringify(selected.windows), 'Journal target or identity differs');
      assert(['committed', 'verified'].includes(record.state), 'Journal does not establish completed signed bytes');
      if (originalSha256 !== undefined) assert.equal(record.originalSha256, originalSha256);
      const result = signature(file); assert(result.valid, 'Journaled signature is invalid');
      assert.equal(result.sha256, record.sha256, 'Journaled signed bytes changed');
      return result;
    },
    signFile: (file, selected, { journal, save, ownedRoot }) => {
      assert.equal(selected.windows.certificateSha1, config.windows.certificateSha1);
      assert(file.startsWith(ownedRoot + path.sep));
      const key = path.relative(ownedRoot, file), existing = journal.entries[key];
      if (existing) {
        if (existing.state === 'verified' && io.hashFile(file) === existing.originalSha256) {
          fs.writeFileSync(file, 'SIGNED:' + fs.readFileSync(file, 'utf8')); existing.state = 'committed'; save(journal);
        }
        assert.equal(io.hashFile(file), existing.sha256); return { ...signature(file), action: 'reused' };
      }
      const before = signature(file);
      const originalBytes = fs.readFileSync(file, 'utf8');
      if (!before.valid) {
        assert.equal(before.identity, 'unsigned'); counts.signProvider++; counts.signOrder.push(key.replaceAll('\\', '/'));
        fs.writeFileSync(file, 'SIGNED:' + fs.readFileSync(file, 'utf8'));
      }
      const result = signature(file); journal.entries[key] = { path: file, binding: JSON.stringify(selected.windows),
        originalSha256: before.sha256, sha256: result.sha256, state: 'committed' }; save(journal);
      if (behavior.failBeforeInnerReplacement && counts.signProvider === 1) {
        behavior.failBeforeInnerReplacement = false; journal.entries[key].state = 'verified';
        fs.writeFileSync(file, originalBytes); save(journal);
        throw new Error('simulated interruption before atomic signed-copy replacement');
      }
      if (behavior.failAfterInnerCommit && counts.signProvider === 1) {
        behavior.failAfterInnerCommit = false;
        throw new Error('simulated interruption after a committed engine signature');
      }
      return { ...result, action: before.valid ? 'preserved-microsoft' : 'signed' };
    },
  };
  const deps = { yaml: { load: JSON.parse, dump: value => JSON.stringify(value) }, electronBuilder: '26.15.3', appBuilderLib: '26.15.3' };
  const packageApi = {
    ...realPackage,
    dependencies: () => deps,
    validateToolchain: () => ({ electron: '37.10.3', electronBuilder: '26.15.3', sourcePinVerified: true }),
    refreshPayloadMetadata: (...args) => {
      if (behavior.failBeforeMetadata) { behavior.failBeforeMetadata = false; throw new Error('simulated interruption before metadata refresh'); }
      return realPackage.refreshPayloadMetadata(...args);
    },
    comparePayloads: (...args) => {
      const result = realPackage.comparePayloads(...args);
      if (behavior.failBeforeBuild && args[1] === args[2]) {
        behavior.failBeforeBuild = false; throw new Error('simulated interruption after payload checkpoint before NSIS');
      }
      return result;
    },
    buildInstaller: async (_, input, paths) => {
      counts.build++; currentPaths = paths;
      assert(fs.existsSync(path.join(input.payloadRoot, 'resources/app.asar')));
      if (behavior.lockDuringBuild) await behavior.lockDuringBuild();
      const installer = path.join(paths.buildOutput, `DFCode-${config.version}-x64.exe`);
      write(installer, 'SIGNED:final fixture installer');
      if (behavior.build === 'incomplete') throw new Error('simulated ambiguous incomplete NSIS build');
      write(paths.uninstaller, 'SIGNED:final fixture uninstaller');
      const generatedUninstaller = path.join(paths.buildOutput, `${path.basename(installer, 'exe')}__uninstaller.exe`);
      const hookJournal = { schemaVersion: 1, entries: {} };
      for (const [target, actual] of [[installer, installer], [generatedUninstaller, paths.uninstaller]]) {
        hookJournal.entries[path.relative(paths.work, target)] = { path: target, binding: JSON.stringify(config.windows),
          sha256: io.hashFile(actual), state: 'committed' };
      }
      write(paths.hookJournal, JSON.stringify(hookJournal));
      if (behavior.build === 'complete-throw') throw new Error('simulated interruption after valid NSIS output');
      return { installer, uninstaller: paths.uninstaller };
    },
    extractInstaller: async (_, destination) => {
      counts.extract++;
      fs.cpSync(currentPaths.payload, destination, { recursive: true });
      if (behavior.tamperFinal) fs.appendFileSync(path.join(destination, 'resources/app.asar'), 'unexpected change');
      return { passed: true };
    },
    extractUninstaller: (_, expected, destination) => {
      fs.copyFileSync(expected, destination, fs.constants.COPYFILE_EXCL);
      return { passed: true, sha256: io.hashFile(expected) };
    },
    finalizeMetadata: async (selected, installer, destination) => {
      counts.finalize++;
      const name = `DFCode-${config.version}-x64.exe`;
      fs.mkdirSync(destination, { recursive: true }); fs.copyFileSync(installer, path.join(destination, name));
      if (behavior.metadata === 'partial') throw new Error('simulated interruption during final metadata creation');
      const names = [name, name + '.blockmap', 'latest.yml', 'release.json', `DFCode-${config.version}-win32-x64-full-ota-signed.zip`];
      for (const file of names.slice(1)) write(path.join(destination, file), JSON.stringify({ kind: file,
        notes: realPackage.notes(selected.otaNotesFile), installerSha256: io.hashFile(installer) }));
      return { passed: true, installer: path.join(destination, name), zip: path.join(destination, names.at(-1)),
        files: names.map(file => ({ path: path.join(destination, file), size: fs.statSync(path.join(destination, file)).size, sha256: io.hashFile(path.join(destination, file)) })) };
    },
    verifyBlockmap: async (_, blockmap, regenerated) => { counts.blockmap++; fs.copyFileSync(blockmap, regenerated, fs.constants.COPYFILE_EXCL); return true; },
  };
  const routePath = path.resolve(__dirname, '../scripts/windows-release.cjs');
  const actualRequire = createRequire(routePath), module = { exports: {} };
  const injectedRequire = name => {
    if (name === './windows-input.cjs') return inputApi;
    if (name === './windows-package.cjs') return packageApi;
    if (name === './windows-sign.cjs') return signingApi;
    if (name === './io.cjs') return { ...io, writeJson: (file, value) => {
      if (behavior.failFinalReport && path.basename(file) === 'WINDOWS-VERIFICATION.json') {
        behavior.failFinalReport = false; throw new Error('simulated interruption before final report');
      }
      return io.writeJson(file, value);
    }, run: (file, args) => {
      assert(file.endsWith(path.join('resources', 'engine', 'dfcode.exe'))); assert.deepEqual(Array.from(args), ['--version']);
      counts.probe++; return behavior.engineVersion;
    } };
    return actualRequire(name);
  };
  const context = vm.createContext({ require: injectedRequire, module, exports: module.exports,
    __filename: routePath, __dirname: path.dirname(routePath), Buffer, console,
    process: { platform: 'win32', arch: 'x64', pid: process.pid, versions: process.versions } });
  new vm.Script(fs.readFileSync(routePath, 'utf8'), { filename: routePath }).runInContext(context);
  const api = module.exports;
  const paths = api.releasePaths(config);
  currentPaths = paths;
  return { root, config, paths, api, counts, behavior, artifact,
    execute: resume => api.windowsRelease(config, { execute: true, resume: Boolean(resume) }),
    state: () => JSON.parse(fs.readFileSync(paths.state, 'utf8')) };
}

test('native route finalizes five bound delivery assets and resumes without repeating side effects', async t => {
  const f = fixture(t);
  const report = await f.execute();
  assert.equal(report.status, 'finalized'); assert.equal(report.files.length, 5);
  assert.equal(report.signing.verifiedPeCount, 5);
  assert.equal(report.signing.companySignedPeCount, 4); assert.equal(report.signing.preservedMicrosoftPeCount, 1);
  assert.equal(report.acceptance.engineVersionCliVerified, true); assert.equal(report.acceptance.windowsAccepted, false);
  assert.equal(report.publication.admin, false); assert.equal(report.publication.github, false);
  assert.equal(f.counts.signOrder[0], 'signed-payload/resources/engine/dfcode.exe');
  assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.build, 1); assert.equal(f.counts.probe, 1);
  assert.equal(f.state().phase, 'finalized'); assert.equal(fs.existsSync(f.paths.state + '.lock'), false);
  assert.equal(fs.readFileSync(path.join(f.paths.input, 'win-unpacked/DFCode.exe'), 'utf8'), 'main unsigned bytes');
  const notes = JSON.parse(fs.readFileSync(path.join(f.paths.delivery, 'release.json'), 'utf8')).notes;
  assert.equal(notes, 'Current independent OTA notes');
  const prior = JSON.stringify(f.counts);
  assert.equal((await f.execute(true)).status, 'finalized'); assert.equal(JSON.stringify(f.counts), prior);
  await assert.rejects(f.execute(), /use --resume/);
});

test('resume reuses a committed inner signature after an interrupted unfinished stage', async t => {
  const f = fixture(t); f.behavior.failAfterInnerCommit = true;
  await assert.rejects(f.execute(), /committed engine signature/);
  assert.equal(f.counts.signProvider, 1); assert.equal(f.state().stages['inner-pe-signed'], undefined);
  assert.equal(Object.keys(f.state().signingJournal.entries).length, 1);
  assert.equal(fs.existsSync(f.paths.state + '.lock'), false);
  await f.execute(true);
  assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.input, 1); assert.equal(f.counts.build, 1);
});

test('resume permits unchanged unsigned target while recovering its verified detached signature', async t => {
  const f = fixture(t); f.behavior.failBeforeInnerReplacement = true;
  await assert.rejects(f.execute(), /before atomic signed-copy replacement/);
  assert.equal(f.counts.signProvider, 1);
  assert.equal(Object.values(f.state().signingJournal.entries)[0].state, 'verified');
  assert.equal(fs.readFileSync(path.join(f.paths.payload, 'resources/engine/dfcode.exe'), 'utf8'), 'engine unsigned bytes');
  await f.execute(true);
  assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.build, 1); assert.equal(f.state().phase, 'finalized');
});

test('partial signing resume rejects changed non-PE, unsigned PE, journaled PE or file inventory before another paid call', async t => {
  for (const kind of ['non-pe', 'unsigned-pe', 'signed-pe', 'added', 'removed']) {
    const f = fixture(t); f.behavior.failAfterInnerCommit = true;
    await assert.rejects(f.execute(), /committed engine signature/);
    if (kind === 'non-pe') fs.appendFileSync(path.join(f.paths.payload, 'resources/app.asar'), 'changed');
    if (kind === 'unsigned-pe') fs.appendFileSync(path.join(f.paths.payload, 'DFCode.exe'), 'changed');
    if (kind === 'signed-pe') fs.appendFileSync(path.join(f.paths.payload, 'resources/engine/dfcode.exe'), 'other trusted signed bytes');
    if (kind === 'added') write(path.join(f.paths.payload, 'extra.dll'), 'new unsigned PE');
    if (kind === 'removed') fs.unlinkSync(path.join(f.paths.payload, 'dxil.dll'));
    await assert.rejects(f.execute(true), /Staged non-PE|Journal|file set differs/);
    assert.equal(f.counts.signProvider, 1); assert.equal(f.counts.build, 0); assert.equal(f.counts.finalize, 0);
  }
});

test('completed inner-sign stage still rejects replacement signed PE before metadata or NSIS signing', async t => {
  const f = fixture(t); f.behavior.failBeforeMetadata = true;
  await assert.rejects(f.execute(), /before metadata refresh/);
  assert(f.state().stages['inner-pe-signed']); assert.equal(f.state().stages['manifest-refreshed'], undefined);
  fs.appendFileSync(path.join(f.paths.payload, 'DFCode.exe'), 'different but still trusted fixture signature');
  await assert.rejects(f.execute(true), /Journaled signed bytes changed/);
  assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.build, 0);
});

test('post-manifest checkpoint binds the complete payload before any NSIS signing attempt', async t => {
  for (const target of ['DFCode.exe', 'resources/app.asar', 'resources/app-update.yml', 'resources/engine/manifest.json', 'extra.dll']) {
    const f = fixture(t); f.behavior.failBeforeBuild = true;
    await assert.rejects(f.execute(), /after payload checkpoint/);
    assert(Array.isArray(f.state().stages['manifest-refreshed'].result.inventory));
    assert.equal(f.state().buildPending, undefined);
    fs.appendFileSync(path.join(f.paths.payload, target), 'changed staged bytes');
    await assert.rejects(f.execute(true), /Signed payload changed/);
    assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.build, 0); assert.equal(f.counts.finalize, 0);
  }
});

test('an interrupted NSIS result is recovered only when installer and uninstaller are both signed', async t => {
  const f = fixture(t); f.behavior.build = 'complete-throw';
  await assert.rejects(f.execute(), /after valid NSIS output/);
  assert.equal(f.state().buildPending, true); assert.equal(f.state().stages['nsis-signed'], undefined);
  f.behavior.build = null;
  await f.execute(true);
  assert.equal(f.counts.build, 1); assert.equal(f.counts.signProvider, 2); assert.equal(f.state().phase, 'finalized');
});

test('interrupted NSIS recovery rejects other valid signed outputs and missing or unresolved hook evidence', async t => {
  for (const kind of ['installer', 'uninstaller', 'missing-journal', 'wrong-identity', 'unresolved']) {
    const f = fixture(t); f.behavior.build = 'complete-throw';
    await assert.rejects(f.execute(), /after valid NSIS output/);
    if (kind === 'installer') fs.appendFileSync(path.join(f.paths.buildOutput, `DFCode-${f.config.version}-x64.exe`), 'other installation scope');
    if (kind === 'uninstaller') fs.appendFileSync(f.paths.uninstaller, 'other uninstall behavior');
    if (kind === 'missing-journal') fs.unlinkSync(f.paths.hookJournal);
    if (kind === 'wrong-identity' || kind === 'unresolved') {
      const journal = JSON.parse(fs.readFileSync(f.paths.hookJournal, 'utf8'));
      for (const entry of Object.values(journal.entries)) {
        if (kind === 'wrong-identity') entry.binding = 'another signing attempt';
        else entry.state = 'signing';
      }
      fs.writeFileSync(f.paths.hookJournal, JSON.stringify(journal));
    }
    await assert.rejects(f.execute(true), /Journal|journal is required/);
    assert.equal(f.counts.build, 1); assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.extract, 0); assert.equal(f.counts.finalize, 0);
  }
});

test('incomplete NSIS outcomes are preserved and never automatically rebuilt on resume', async t => {
  const f = fixture(t); f.behavior.build = 'incomplete';
  await assert.rejects(f.execute(), /incomplete NSIS build/);
  const installer = path.join(f.paths.buildOutput, `DFCode-${f.config.version}-x64.exe`), before = io.hashFile(installer);
  await assert.rejects(f.execute(true), /incomplete or ambiguous/);
  assert.equal(f.counts.build, 1); assert.equal(io.hashFile(installer), before);
  assert.equal(fs.existsSync(f.paths.state + '.lock'), false);
});

test('partial metadata output blocks retry without overwriting or rebuilding accepted signatures', async t => {
  const f = fixture(t); f.behavior.metadata = 'partial';
  await assert.rejects(f.execute(), /metadata creation/);
  const delivered = path.join(f.paths.delivery, `DFCode-${f.config.version}-x64.exe`), before = io.hashFile(delivered);
  assert(f.state().stages['final-payload-verified']); assert.equal(f.state().stages['metadata-verified'], undefined);
  await assert.rejects(f.execute(true), /Partial metadata delivery/);
  assert.equal(f.counts.finalize, 1); assert.equal(f.counts.build, 1); assert.equal(io.hashFile(delivered), before);
});

test('metadata checkpoint resumes final reporting only for the unchanged five delivered assets', async t => {
  for (const kind of ['unchanged', 'installer', 'blockmap', 'feed', 'manifest', 'zip']) {
    const f = fixture(t); f.behavior.failFinalReport = true;
    await assert.rejects(f.execute(), /before final report/);
    const state = f.state(); assert(state.stages['metadata-verified']);
    const names = { installer: `DFCode-${f.config.version}-x64.exe`, blockmap: `DFCode-${f.config.version}-x64.exe.blockmap`,
      feed: 'latest.yml', manifest: 'release.json', zip: `DFCode-${f.config.version}-win32-x64-full-ota-signed.zip` };
    if (kind === 'unchanged') assert.equal((await f.execute(true)).status, 'finalized');
    else {
      fs.appendFileSync(path.join(f.paths.delivery, names[kind]), 'modified accepted metadata');
      await assert.rejects(f.execute(true)); assert.equal(fs.existsSync(f.paths.final), false);
    }
    assert.equal(f.counts.signProvider, 2); assert.equal(f.counts.build, 1); assert.equal(f.counts.finalize, 1);
  }
});

test('source archive and extracted baseline changes fail resume before additional signing', async t => {
  for (const kind of ['archive', 'payload']) {
    const f = fixture(t); f.behavior.failAfterInnerCommit = true;
    await assert.rejects(f.execute());
    const target = kind === 'archive' ? f.artifact : path.join(f.paths.input, 'win-unpacked/resources/app.asar');
    fs.appendFileSync(target, 'changed input');
    await assert.rejects(f.execute(true), kind === 'archive' ? /Unsigned input changed/ : /extracted input was modified/);
    assert.equal(f.counts.signProvider, 1); assert.equal(f.counts.build, 0);
  }
});

test('notes and identity changes invalidate checkpoint binding before repeated external work', async t => {
  for (const kind of ['notes', 'certificate']) {
    const f = fixture(t); f.behavior.failAfterInnerCommit = true;
    await assert.rejects(f.execute());
    const preflight = f.counts.preflight;
    if (kind === 'notes') fs.appendFileSync(f.config.otaNotesFile, '\nchanged');
    else f.config.windows.certificateSha1 = 'D'.repeat(40);
    await assert.rejects(f.execute(true), /Source\/config\/notes changed/);
    assert.equal(f.counts.preflight, preflight); assert.equal(f.counts.signProvider, 1);
  }
});

test('modified finalized delivery is rejected without rerunning signing or packaging', async t => {
  const f = fixture(t); const report = await f.execute(); const prior = JSON.stringify(f.counts);
  fs.appendFileSync(report.files[0].path, 'tampered');
  await assert.rejects(f.execute(true)); assert.equal(JSON.stringify(f.counts), prior);
});

test('payload extraction mismatches and untrusted final signatures cannot reach metadata delivery', async t => {
  for (const kind of ['bytes', 'signature']) {
    const f = fixture(t);
    if (kind === 'bytes') f.behavior.tamperFinal = true;
    else f.behavior.failFinalSignature = true;
    await assert.rejects(f.execute(), kind === 'bytes' ? /differs from the signed copy/ : /Final package signature verification failed/);
    assert.equal(f.counts.finalize, 0); assert.equal(fs.existsSync(f.paths.delivery), false);
  }
});

test('wrong signed Engine CLI version blocks final delivery', async t => {
  const f = fixture(t); f.behavior.engineVersion = '3.3.19';
  await assert.rejects(f.execute(), /Engine --version differs/);
  assert.equal(f.counts.probe, 1); assert.equal(f.counts.finalize, 0);
});

test('per-release lock blocks concurrent execution and is released after completion', async t => {
  const f = fixture(t);
  let attempts = 0;
  f.behavior.lockDuringBuild = async () => {
    attempts++;
    await assert.rejects(f.execute(true), /Windows signing lock exists/);
    assert.equal(fs.existsSync(f.paths.state + '.lock'), true);
  };
  await f.execute(); assert.equal(attempts, 1); assert.equal(f.counts.build, 1);
  assert.equal(fs.existsSync(f.paths.state + '.lock'), false);
});

test('test-local CLI uses the same execution state machine while unknown flags never reach it', async t => {
  const f = fixture(t); let output = '', errors = '';
  const options = { loadConfig: () => f.config, stdout: { write: value => { output += value; } }, stderr: { write: value => { errors += value; } } };
  assert.equal(await f.api.run(['--sign', '--execute', '--config', 'fixture.json', '--publish'], options), 1);
  assert.equal(f.counts.preflight, 0); assert.match(errors, /Unknown or incomplete/);
  output = ''; errors = '';
  assert.equal(await f.api.run(['--sign', '--execute', '--config', 'fixture.json'], options), 0);
  assert.equal(JSON.parse(output).status, 'finalized'); assert.equal(errors, '');
});
