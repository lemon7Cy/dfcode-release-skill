#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

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
      otaNotesFile: config.otaNotesFile,
      releaseNotesFile: config.releaseNotesFile,
      notesPolicy: 'Use the independent otaNotesFile, never the older notes embedded in the CI ZIP.',
    },
    update: { channel: config.channel, baseUrl: config.updateBaseUrl },
    handoffFile: path.join(config.outputDir, 'delivery', `Windows-${config.version}-signing-handoff.md`),
    signing: { implemented: false, performed: false },
    verification: { performed: false },
    publication: { performed: false },
  };
}

function renderWindowsHandoff(plan) {
  return `# DFCode ${plan.version} Windows Signing Handoff

This file is a plan, not evidence of signing, verification, or publication.
The Windows implementation is pending local Windows x64 development and acceptance.

## Pinned Inputs

- Studio: \`${plan.source.studioRepository}@${plan.source.studioCommit}\`
- Engine: \`${plan.source.engineRepository}@${plan.source.engineCommit}\`, version \`${plan.source.engineVersion}\`
- Build repository: \`${plan.source.buildRepository}\`
- Unsigned signing input: \`${plan.inputs.archive}\`
- Input checksum: \`${plan.inputs.archiveChecksum}\`
- Current independent OTA notes: \`${plan.inputs.otaNotesFile}\`
- Full release notes: \`${plan.inputs.releaseNotesFile}\`
- Update source/channel: \`${plan.update.baseUrl}\` / \`${plan.update.channel}\`

Use the independent OTA notes above. The original CI ZIP and its embedded old notes stay unchanged.
Paths must resolve on the Windows signing machine; do not reuse a macOS configuration unchanged.

## Windows Work Still Required

1. Verify the input ZIP and every SHA256SUMS entry, BUILD-INFO source pins, PE inventory, Engine manifest, and app-update.yml. CI evidence is not local signing evidence.
2. Confirm Windows x64, the matching locked Node/Bun/Electron Builder toolchain, Windows SDK SignTool, and DigiCert KeyLocker KSP. The account must be a designated signer for the target certificate. Keep credentials outside this skill, config, packages, logs, and chat.
3. Work on a copy of win-unpacked. Inventory and sign/verify every inner PE, including the Engine, main EXE, DLLs and native modules, with the intended publisher and trusted timestamp.
4. Refresh resources/engine/manifest.json binarySha256 and signing fields after signing the Engine; preserve source/version and skill hashes. Recheck after packaging.
5. Rebuild NSIS from the signed directory with the project's signing hook enabled for the generated uninstaller and final installer. --prepackaged does not sign inner files; dist:win is not a validated sign-only command. Verify the exact publisherName contract and embedded updater configuration.
6. Generate blockmap and feed from final signed bytes, then build release.json and the matching Full OTA ZIP using the independent notes. The Admin packaging helper does not repair stale feed SHA-512 or regenerate blockmap. Keep signed and unsigned reports separate.
7. On Windows, verify Authenticode publisher, trust and timestamp for inner PE, installed uninstaller and final installer. Test clean installation, Engine ${plan.source.engineVersion}, startup, uninstall, and a real old-to-new OTA upgrade with data retention. Silent behavior is controlled by the initiating client.
8. Deliver ASCII-named signed EXE, matching Full OTA ZIP, SHA-256 checksums, source record and actual verification report. Signing does not authorize an Admin production publish or guarantee immediate SmartScreen reputation.

See the installed skill reference references/windows-handoff.md for the extension acceptance contract.
No signing credentials have been read or used by this handoff generator.
`;
}

function run(argv, options = {}) {
  const stdout = options.stdout || process.stdout;
  const stderr = options.stderr || process.stderr;
  if (argv.includes('--sign')) {
    stderr.write('Windows signing is not implemented. This entrypoint only prepares a handoff; no signing was performed.\n');
    return 2;
  }
  if (argv.includes('--help')) {
    stdout.write('Usage: node windows-release.cjs --config release.json [--execute]\nDefault: print the plan. --execute: write only the handoff document. --sign: unsupported.\n');
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

module.exports = { createWindowsPlan, renderWindowsHandoff, run };
if (require.main === module) process.exitCode = run(process.argv.slice(2));
