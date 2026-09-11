#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { hashFile, writeJson, run: command } = require('./io.cjs');

function createWindowsPlan(config) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(config.version || '')) {
    throw new Error('A safe release version is required');
  }
  if (!config.outputDir || !config.otaNotesFile) throw new Error('outputDir and otaNotesFile are required');
  const archive = `DFCode-${config.version}-win32-x64-signing-input-unsigned.zip`;
  return {
    schemaVersion: 1,
    status: 'handoff-only',
    target: { platform: 'win32', arch: 'x64' },
    version: config.version,
    source: {
      studioRepository: config.studioRepository, studioCommit: config.studioCommit,
      engineRepository: config.engineRepository, engineCommit: config.engineCommit, engineVersion: config.engineVersion,
      buildRepository: config.buildRepository,
    },
    inputs: {
      archive: path.join(config.outputDir, 'unsigned-ci', archive),
      archiveChecksum: path.join(config.outputDir, 'unsigned-ci', `${archive}.sha256`),
      ciVerificationReport: path.join(config.outputDir, 'reports', 'verify-ci.json'),
      otaNotesFile: config.otaNotesFile,
      releaseNotesFile: config.releaseNotesFile,
      notesPolicy: 'Use the independent otaNotesFile, never the older notes embedded in the CI ZIP.',
    },
    update: { channel: config.channel, baseUrl: config.updateBaseUrl },
    handoffFile: path.join(config.outputDir, 'delivery', `Windows-${config.version}-signing-handoff.md`),
    signing: { implemented: true, performed: false },
    verification: { performed: false },
    publication: { performed: false },
  };
}

function renderWindowsHandoff(plan) {
  return `# DFCode ${plan.version} Windows Signing Handoff

This file is a plan, not evidence of signing, verification, or publication.
On Windows x64, run windows-release.cjs --config <local-config> --sign --execute.
Signing and packaging are implemented. Installation and real OTA acceptance remain separate, explicitly coordinated tests.

## Pinned Inputs

- Studio: \`${plan.source.studioRepository}@${plan.source.studioCommit}\`
- Engine: \`${plan.source.engineRepository}@${plan.source.engineCommit}\`, version \`${plan.source.engineVersion}\`
- Build repository: \`${plan.source.buildRepository}\`
- Unsigned signing input: \`${plan.inputs.archive}\`
- Input checksum: \`${plan.inputs.archiveChecksum}\`
- CI verification receipt (required when transferring hosts): \`${plan.inputs.ciVerificationReport}\`
- Current independent OTA notes: \`${plan.inputs.otaNotesFile}\`
- Full release notes: \`${plan.inputs.releaseNotesFile}\`
- Update source/channel: \`${plan.update.baseUrl}\` / \`${plan.update.channel}\`

Use the independent OTA notes above. The original CI ZIP and its embedded old notes stay unchanged.
Paths must resolve on the Windows signing machine; do not reuse a macOS configuration unchanged.

## Windows Work Still Required

1. Verify the input ZIP and every SHA256SUMS entry, BUILD-INFO source pins, PE inventory, Engine manifest, and app-update.yml. CI evidence is not local signing evidence.
2. Confirm Windows x64, the matching locked Node/Bun/Electron Builder toolchain, Windows SDK SignTool, PowerShell 7 and DigiCert SMCTL. The native driver uses KeyLocker through SMCTL --simple; a KSP installation is not required. The account must be a designated signer for the target certificate. Keep credentials outside this skill, config, packages, logs, and chat.
3. Work on a copy of win-unpacked. Inventory and sign/verify every inner PE, including the Engine, main EXE, DLLs and native modules, with the intended publisher and trusted timestamp.
4. Refresh resources/engine/manifest.json binarySha256 and signing fields after signing the Engine; preserve source/version and skill hashes. Recheck after packaging.
5. Rebuild NSIS from the signed directory with the project's signing hook enabled for the generated uninstaller and final installer. --prepackaged does not sign inner files; dist:win is not a validated sign-only command. Verify the exact publisherName contract and embedded updater configuration.
6. Generate blockmap and feed from final signed bytes, then build release.json and the matching Full OTA ZIP using the independent notes. The Admin packaging helper does not repair stale feed SHA-512 or regenerate blockmap. Keep signed and unsigned reports separate.
7. On Windows, verify Authenticode publisher, trust and timestamp for inner PE, installed uninstaller and final installer. Test clean installation, Engine ${plan.source.engineVersion}, startup, uninstall, and a real old-to-new OTA upgrade with data retention. Silent behavior is controlled by the initiating client.
8. Deliver ASCII-named signed EXE, matching Full OTA ZIP, SHA-256 checksums, source record and actual verification report. Signing does not authorize an Admin production publish or guarantee immediate SmartScreen reputation.

See the installed skill reference references/windows-handoff.md for configuration, recovery and acceptance details.
No signing credentials have been read or used by this handoff generator.
`;
}

function configBinding(config) {
  return createHash('sha256').update(JSON.stringify({ config, otaNotes: hashFile(config.otaNotesFile), releaseNotes: hashFile(config.releaseNotesFile) })).digest('hex');
}
function assertNativeHost(platform = process.platform, arch = process.arch) {
  assert(platform === 'win32' && arch === 'x64', 'Actual Windows signing requires a Windows x64 host');
}
function releasePaths(config) {
  const root = path.join(config.outputDir, '.work.noindex/windows');
  const work = path.join(root, 'signing');
  return { root, work, input: path.join(root, 'input'), payload: path.join(work, 'signed-payload'),
    builder: path.join(work, 'builder'), buildOutput: path.join(work, 'nsis-output'),
    audit: path.join(work, 'audit'), hookJournal: path.join(work, 'hook-journal.json'),
    uninstaller: path.join(work, 'audit/Uninstall DFCode.exe'), delivery: path.join(config.outputDir, 'delivery/windows'),
    state: path.join(config.outputDir, 'reports/windows-state.json'), final: path.join(config.outputDir, 'reports/windows-final.json') };
}
function verifyFinalReport(config, report) {
  const P = require('./windows-package.cjs');
  assert.equal(report.schemaVersion, 1); assert.equal(report.status, 'finalized');
  assert.equal(report.configBinding, configBinding(config), 'Final Windows report is bound to other config or notes');
  assert.equal(report.version, config.version);
  assert.deepEqual(report.source, { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion });
  assert.equal(report.signing.status, 'signed'); assert.equal(report.signing.publisherName, config.windows.publisherName);
  assert.equal(report.signing.certificateSha1, config.windows.certificateSha1.toUpperCase());
  assert(report.files.length >= 5, 'Incomplete Windows deliverables');
  for (const file of report.files) {
    P.ownedPath(releasePaths(config).delivery, file.path);
    assert.equal(fs.statSync(file.path).size, file.size); assert.equal(hashFile(file.path), file.sha256, 'Verified Windows delivery was modified');
  }
  return report;
}
function acquireLock(file) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  try { fs.writeFileSync(file, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }), { flag: 'wx' }); }
  catch (error) { if (error.code === 'EEXIST') throw new Error(`Windows signing lock exists: ${file}. Check the recorded process before archiving only a proven stale lock.`); throw error; }
  return () => fs.unlinkSync(file);
}
function durableState(file, value) {
  const temporary = `${file}.${process.pid}.pending`;
  const fd = fs.openSync(temporary, 'wx', 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}
function verifyStagedPayload(config, input, paths, state, I, S) {
  const current = I.inventoryTree(paths.payload);
  const refreshed = state.stages['manifest-refreshed'];
  if (refreshed) {
    assert(Array.isArray(refreshed.result.inventory), 'Signed payload checkpoint lacks its immutable inventory');
    assert.deepEqual(current, refreshed.result.inventory, 'Signed payload changed since its verified checkpoint');
    return current;
  }
  const original = I.inventoryTree(input.payloadRoot);
  assert.deepEqual(current.map(x => x.file), original.map(x => x.file), 'Staged payload file set differs from the verified unsigned input');
  for (let index = 0; index < original.length; index++) {
    const before = original[index], now = current[index], file = path.join(paths.payload, before.file);
    if (!I.inspectPe(path.join(input.payloadRoot, before.file))) {
      assert.equal(now.sha256, before.sha256, `Staged non-PE content changed before metadata checkpoint: ${before.file}`);
      continue;
    }
    const record = Object.values(state.signingJournal.entries).find(entry => entry.path === file);
    // A verified detached copy may still await atomic replacement; its target
    // must remain the original bytes and signFile will recover that copy.
    if (state.stages['inner-pe-signed'] || now.sha256 !== before.sha256 || record?.state === 'committed') {
      S.verifyJournaledFile(file, config, { journal: state.signingJournal, ownedRoot: paths.work, originalSha256: before.sha256 });
    }
  }
  return current;
}
async function windowsRelease(config, options = {}) {
  const plan = createWindowsPlan(config);
  if (!options.execute) return { ...plan, status: 'planned', handoffWritten: false, actions: ['verify-input', 'sign-inner-pe', 'refresh-manifest', 'rebuild-sign-nsis', 'verify-final-payload', 'finalize-full-ota'], publication: { performed: false } };
  assertNativeHost();
  assert(config.windows?.publisherName && config.windows?.certificateSha1 && config.windows?.keypairAlias, 'windows.publisherName, certificateSha1 and keypairAlias are required to sign');
  const P = require('./windows-package.cjs'), I = require('./windows-input.cjs'), S = require('./windows-sign.cjs');
  P.notes(config.otaNotesFile);
  const paths = releasePaths(config), binding = configBinding(config);
  for (const file of [config.outputDir, config.workspace, paths.root, paths.state, paths.final, paths.delivery]) P.noLinks(file);
  const unlock = acquireLock(`${paths.state}.lock`);
  try {
    let state;
    if (fs.existsSync(paths.state)) {
      assert(options.resume, 'Windows state already exists; use --resume or a new outputDir');
      state = JSON.parse(fs.readFileSync(paths.state, 'utf8'));
      assert.equal(state.configBinding, binding, 'Source/config/notes changed; use a new outputDir');
      if (state.phase === 'finalized') return verifyFinalReport(config, JSON.parse(fs.readFileSync(paths.final, 'utf8')));
    } else {
      assert(!options.resume, 'No Windows state exists to resume');
      assert(!fs.existsSync(paths.root) && !fs.existsSync(paths.delivery) && !fs.existsSync(paths.final), 'Preserve existing Windows work and use a new outputDir');
      state = { schemaVersion: 1, version: config.version, configBinding: binding, phase: 'created', stages: {}, signingJournal: { schemaVersion: 1, entries: {} }, createdAt: new Date().toISOString() };
    }
    const save = () => durableState(paths.state, state);
    const stage = (name, result) => { state.stages[name] = { completedAt: new Date().toISOString(), result }; state.phase = name; save(); };
    const signingTools = S.preflightSigning(config), activeConfig = { ...config, windows: signingTools.windows };
    const deps = P.dependencies(config);
    save();
    if (!state.input) {
      assert(!fs.existsSync(paths.input), 'An incomplete extraction exists; preserve it and use a new outputDir');
      state.input = await I.verifyAndExtractInput(config, { destination: paths.input });
      state.inputTree = I.inventoryTree(paths.input);
      stage('input-verified', state.input.report);
    }
    const input = state.input;
    assert.equal(hashFile(input.input.artifact.path), input.input.artifact.sha256, 'Unsigned input changed since verification');
    assert.deepEqual(I.inventoryTree(paths.input), state.inputTree, 'Original extracted input was modified');
    const tools = P.validateToolchain(config, input, deps);
    if (!state.payloadCopied) {
      assert(!fs.existsSync(paths.payload), 'Partial payload copy exists; start a new outputDir');
      fs.mkdirSync(paths.audit, { recursive: true });
      fs.cpSync(input.payloadRoot, paths.payload, { recursive: true, errorOnExist: true, force: false });
      state.payloadCopied = true; save();
    }
    // Check the entire copy before any further paid operation. An unfinished
    // signing stage may differ only by bytes already established in its journal.
    const peFiles = verifyStagedPayload(activeConfig, input, paths, state, I, S)
      .filter(entry => I.inspectPe(path.join(paths.payload, entry.file)));
    peFiles.sort((a, b) => (a.file === 'resources/engine/dfcode.exe' ? -1 : b.file === 'resources/engine/dfcode.exe' ? 1 : a.file.localeCompare(b.file)));
    if (!state.stages['inner-pe-signed']) {
      const records = [];
      for (const entry of peFiles) {
        const result = S.signFile(path.join(paths.payload, entry.file), activeConfig, { journal: state.signingJournal, save, ownedRoot: paths.work });
        records.push({ ...result, file: entry.file });
      }
      stage('inner-pe-signed', records);
    }
    if (!state.stages['manifest-refreshed']) {
      const metadata = P.refreshPayloadMetadata(activeConfig, paths.payload, deps);
      stage('manifest-refreshed', { ...metadata, inventory: I.inventoryTree(paths.payload) });
    }
    // Recheck every signature before passing this directory to the builder, including on resume.
    for (const entry of peFiles) S.verifyJournaledFile(path.join(paths.payload, entry.file), activeConfig,
      { journal: state.signingJournal, ownedRoot: paths.work });
    P.comparePayloads(input.payloadRoot, paths.payload, paths.payload, I, activeConfig, deps);
    I.verifyPayload(activeConfig, paths.payload, { signed: true, packagingConfig: input.packagingConfig });
    const installer = path.join(paths.buildOutput, `DFCode-${config.version}-x64.exe`);
    if (!state.stages['nsis-signed']) {
      if (state.buildPending) {
        assert(fs.existsSync(installer) && fs.existsSync(paths.uninstaller), 'NSIS build result is incomplete or ambiguous. Do not automatically rebuild or re-sign; preserve this attempt and inspect the hook journal.');
      } else {
        state.buildPending = true; save();
        await P.buildInstaller(activeConfig, input, paths, tools, deps);
      }
      P.noLinks(paths.hookJournal);
      assert(fs.existsSync(paths.hookJournal), 'NSIS signing journal is required to bind this build result');
      const hookJournal = JSON.parse(fs.readFileSync(paths.hookJournal, 'utf8'));
      const hookOptions = { journal: hookJournal, ownedRoot: paths.work };
      assert.equal(S.verifyJournaledFile(installer, activeConfig, hookOptions).identity, 'configured');
      const generatedUninstaller = path.join(paths.buildOutput, `${path.basename(installer, 'exe')}__uninstaller.exe`);
      assert.equal(S.verifyJournaledFile(paths.uninstaller, activeConfig, { ...hookOptions, journalTarget: generatedUninstaller }).identity, 'configured');
      state.installerSha256 = hashFile(installer); state.uninstallerSha256 = hashFile(paths.uninstaller);
      stage('nsis-signed', { installerSha256: state.installerSha256, uninstallerSha256: state.uninstallerSha256 });
    }
    assert.equal(hashFile(installer), state.installerSha256); assert.equal(hashFile(paths.uninstaller), state.uninstallerSha256);
    if (!state.stages['final-payload-verified']) {
      const audit = fs.mkdtempSync(path.join(paths.audit, 'verify-'));
      const finalPayload = path.join(audit, 'payload'), embeddedUninstaller = path.join(audit, 'Uninstall DFCode.exe');
      await P.extractInstaller(installer, finalPayload, deps);
      const content = P.comparePayloads(input.payloadRoot, paths.payload, finalPayload, I, activeConfig, deps);
      const payload = I.verifyPayload(activeConfig, finalPayload, { signed: true, packagingConfig: input.packagingConfig });
      const uninstaller = P.extractUninstaller(installer, paths.uninstaller, embeddedUninstaller);
      const signatures = [];
      for (const entry of I.inventoryTree(finalPayload).filter(x => I.inspectPe(path.join(finalPayload, x.file)))) signatures.push({ file: entry.file, ...S.verifySignature(path.join(finalPayload, entry.file), activeConfig) });
      signatures.push({ file: path.basename(installer), ...S.verifySignature(installer, activeConfig) }, { file: 'Uninstall DFCode.exe', ...S.verifySignature(embeddedUninstaller, activeConfig) });
      assert(signatures.every(x => x.valid), 'Final package signature verification failed');
      const engineVersion = command(path.join(finalPayload, 'resources/engine/dfcode.exe'), ['--version'], { timeout: 30000, windowsHide: true });
      assert.equal(engineVersion, config.engineVersion, 'Final Engine --version differs from pinned version');
      stage('final-payload-verified', { content, payload, uninstaller, signatures, engineCliVersion: engineVersion, auditDirectory: audit });
    }
    if (!state.stages['metadata-verified']) {
      assert(!fs.existsSync(paths.delivery), 'Partial metadata delivery exists. Preserve this attempt and use a new outputDir; never publish a partial directory');
      const metadata = await P.finalizeMetadata(activeConfig, installer, paths.delivery, deps);
      await P.verifyBlockmap(metadata.installer, `${metadata.installer}.blockmap`, path.join(paths.audit, 'regenerated-final.blockmap'), deps);
      stage('metadata-verified', metadata);
    }
    const signatures = state.stages['final-payload-verified'].result.signatures;
    const report = { schemaVersion: 1, status: 'finalized', configBinding: binding, version: config.version, target: { platform: 'win32', arch: 'x64' },
      source: { studioCommit: config.studioCommit, engineCommit: config.engineCommit, engineVersion: config.engineVersion }, build: input.build,
      input: input.input.artifact, tools,
      signing: { status: 'signed', publisherName: config.windows.publisherName, certificateSha1: config.windows.certificateSha1.toUpperCase(), provider: signingTools.provider,
        verifiedPeCount: signatures.length, companySignedPeCount: signatures.filter(x => x.identity === 'configured').length, preservedMicrosoftPeCount: signatures.filter(x => x.identity === 'microsoft').length },
      stages: state.stages, files: state.stages['metadata-verified'].result.files,
      acceptance: { engineVersionCliVerified: true, cleanInstallation: false, applicationStartup: false, installedUninstaller: false, actualOtaUpgrade: false, userDataRetention: false, windowsAccepted: false },
      publication: { github: false, admin: false }, generatedAt: new Date().toISOString() };
    verifyFinalReport(config, report);
    writeJson(path.join(paths.delivery, 'WINDOWS-VERIFICATION.json'), report);
    fs.writeFileSync(path.join(paths.delivery, 'SHA256SUMS.txt'), report.files.map(f => `${f.sha256}  ${path.basename(f.path)}`).join('\n') + `\n${hashFile(path.join(paths.delivery, 'WINDOWS-VERIFICATION.json'))}  WINDOWS-VERIFICATION.json\n`);
    for (const file of report.files.filter(f => /\.(exe|zip)$/.test(f.path))) fs.writeFileSync(`${file.path}.sha256`, `${file.sha256}  ${path.basename(file.path)}\n`);
    writeJson(paths.final, report); state.phase = 'finalized'; save();
    return report;
  } finally { unlock(); }
}

async function runSign(argv, options) {
  const stdout = options.stdout || process.stdout, stderr = options.stderr || process.stderr;
  try {
    let configFile; const flags = new Set();
    for (let i = 0; i < argv.length; i++) {
      const arg = argv[i];
      if (['--sign', '--execute', '--resume'].includes(arg)) { assert(!flags.has(arg), `Duplicate ${arg}`); flags.add(arg); }
      else if (arg === '--config' && argv[i + 1] && !argv[i + 1].startsWith('--') && !configFile) configFile = argv[++i];
      else throw new Error(`Unknown or incomplete argument: ${arg}`);
    }
    if (flags.has('--execute')) assertNativeHost();
    assert(configFile, '--config is required');
    assert(!flags.has('--resume') || flags.has('--execute'), '--resume requires --execute');
    const config = (options.loadConfig || require('./config.cjs').loadConfig)(configFile);
    const result = await windowsRelease(config, { execute: flags.has('--execute'), resume: flags.has('--resume') });
    stdout.write(JSON.stringify(result, null, 2) + '\n'); return 0;
  } catch (error) { stderr.write(`Windows release failed: ${error.message}\n`); return 1; }
}

function run(argv, options = {}) {
  const stdout = options.stdout || process.stdout;
  const stderr = options.stderr || process.stderr;
  if (argv.includes('--sign')) {
    return runSign(argv, options);
  }
  if (argv.includes('--help')) {
    stdout.write('Usage: node windows-release.cjs --config release.json [--sign] [--execute] [--resume]\nDefault: plan only. --execute: write handoff. --sign --execute: native Windows signing and packaging. --resume reuses verified stages.\n');
    return 0;
  }
  let configFile;
  let execute = false;
  try {
    for (let index = 0; index < argv.length; index += 1) {
      const arg = argv[index];
      if (arg === '--execute') execute = true;
      else if (arg === '--config' && argv[index + 1] && !argv[index + 1].startsWith('--') && !configFile) configFile = argv[++index];
      else throw new Error(`Unknown or incomplete argument: ${arg}`);
    }
    if (!configFile) throw new Error('--config is required');
    const loadConfig = options.loadConfig || require('./config.cjs').loadConfig;
    const plan = createWindowsPlan(loadConfig(configFile));
    if (execute) {
      const body = renderWindowsHandoff(plan);
      fs.mkdirSync(path.dirname(plan.handoffFile), { recursive: true });
      try { fs.writeFileSync(plan.handoffFile, body, { encoding: 'utf8', flag: 'wx' }); }
      catch (error) {
        if (error.code !== 'EEXIST' || fs.readFileSync(plan.handoffFile, 'utf8') !== body) throw error;
      }
    }
    stdout.write(JSON.stringify({ ...plan, handoffWritten: execute }, null, 2) + '\n');
    return 0;
  } catch (error) {
    stderr.write(`Windows handoff failed: ${error.message}\n`);
    return 1;
  }
}

module.exports = { createWindowsPlan, renderWindowsHandoff, configBinding, assertNativeHost, releasePaths, verifyFinalReport, acquireLock, windowsRelease, run };
if (require.main === module) Promise.resolve(run(process.argv.slice(2))).then(code => { process.exitCode = code; }).catch(error => { console.error(error.message); process.exitCode = 1; });
