'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const { createHash } = require('node:crypto');
const zlib = require('node:zlib');
const { run, hashFile, requireFromStudio, writeJson } = require('./io.cjs');
const { inside, canonical } = require('./config.cjs');
const { inspectFlatZip, verifyFullOtaEntries } = require('./archive.cjs');

function noLinks(file) {
  let cursor = path.resolve(file);
  for (;;) {
    if (fs.existsSync(cursor)) assert(!fs.lstatSync(cursor).isSymbolicLink(), `Symlink/junction in release path: ${cursor}`);
    const parent = path.dirname(cursor);
    if (parent === cursor) return;
    cursor = parent;
  }
}
function ownedPath(root, file) {
  noLinks(root); noLinks(file);
  assert(inside(canonical(root), canonical(file)) && canonical(root) !== canonical(file), 'Path must be below the owned release directory');
  return file;
}
function writeNewJson(file, value) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
}
function notes(file) {
  const text = fs.readFileSync(file, 'utf8').replace(/^\uFEFF/, '').replaceAll('\r\n', '\n').trim();
  assert(text && text.length <= 4000 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(text), 'Current OTA notes must contain 1–4000 characters without control characters');
  assert(!/本次 CI 产物为 unsigned|unsigned signing handoff/i.test(text), 'Remove build-only unsigned notices from the independent signed OTA notes');
  return text;
}
function dependencies(config) {
  const req = requireFromStudio(config.workspace);
  const desktop = createRequire(path.join(config.workspace, 'packages/desktop/package.json'));
  const builder = createRequire(desktop.resolve('electron-builder/package.json'));
  return { req, yaml: req('js-yaml'), builderCli: path.join(path.dirname(builder.resolve('electron-builder/package.json')), 'out/cli/cli.js'),
    electronBuilder: builder('electron-builder/package.json').version, appBuilderLib: req('app-builder-lib/package.json').version,
    buildBlockMap: req('app-builder-lib/out/targets/blockmap/blockmap.js').buildBlockMap,
    getSevenzip: req('app-builder-lib/out/toolsets/7zip.js').getPath7za };
}
function validateToolchain(config, input, deps = dependencies(config), command = run) {
  assert.equal(command('git', ['-C', config.workspace, 'rev-parse', 'HEAD']), config.studioCommit, 'Signing dependencies must come from the pinned Studio checkout');
  const changes = command('git', ['-C', config.workspace, 'status', '--porcelain', '--untracked-files=all', '--', 'bun.lock', 'package.json', 'packages/desktop/package.json', 'scripts/prepare-admin-full-ota-release.mjs']);
  assert.equal(changes, '', 'Pinned packaging helpers or dependency manifests have local changes');
  const info = JSON.parse(fs.readFileSync(path.join(input.root, 'BUILD-INFO.json'), 'utf8').replace(/^\uFEFF/, ''));
  assert.equal(deps.electronBuilder, info.tools.electronBuilder, 'electron-builder differs from CI');
  assert.equal(deps.appBuilderLib, info.tools.electronBuilder, 'app-builder-lib differs from CI');
  // Only this inspected API/NSIS format has a proven sign-only path. Fail on drift.
  assert.equal(deps.appBuilderLib, '26.15.3', 'Inspect updated electron-builder APIs before extending supported versions');
  const electron = fs.readFileSync(path.join(input.payloadRoot, 'version'), 'utf8').trim();
  assert.equal(electron, info.tools.electron, 'Bundled Electron differs from BUILD-INFO');
  assert.equal(Number(process.versions.node.split('.')[0]), Number(info.tools.node.replace(/^v/, '').split('.')[0]), 'Use the CI Node major version');
  const bun = command('bun', ['--version']);
  assert.equal(bun, info.tools.bun, 'Use the pinned CI Bun version');
  const sourcePackage = JSON.parse(fs.readFileSync(path.join(config.workspace, 'packages/desktop/package.json'), 'utf8'));
  assert.deepEqual(sourcePackage.build, input.packagingConfig.build, 'CI packaging configuration differs from the source pin');
  return { node: process.versions.node, bun, electron, electronBuilder: deps.electronBuilder, appBuilderLib: deps.appBuilderLib, sourcePinVerified: true };
}
function createBuilderConfig(config, desktopPackage, payload, output, electron) {
  const build = desktopPackage.build;
  const allowedBuild = new Set(['appId', 'productName', 'artifactName', 'files', 'mac', 'win', 'nsis', 'directories', 'electronDist', 'extraResources']);
  const allowedWin = new Set(['icon', 'target', 'requestedExecutionLevel', 'signExecutable', 'signExts', 'signtoolOptions']);
  for (const key of Object.keys(build)) assert(allowedBuild.has(key), `Review unsupported packaging setting before repackaging: ${key}`);
  for (const key of Object.keys(build.win || {})) assert(allowedWin.has(key), `Review unsupported Windows setting before repackaging: ${key}`);
  assert.equal(build.appId, 'ai.dfcode.studio'); assert.equal(build.productName, 'DFCode');
  assert.equal(build.artifactName, 'DFCode-${version}-${arch}.${ext}');
  const allowedNsis = new Set(['oneClick', 'allowToChangeInstallationDirectory', 'perMachine', 'allowElevation', 'createStartMenuShortcut', 'createDesktopShortcut', 'shortcutName', 'uninstallDisplayName', 'installerIcon', 'uninstallerIcon', 'packElevateHelper']);
  for (const key of Object.keys(build.nsis || {})) assert(allowedNsis.has(key), `Review unsupported NSIS setting before repackaging: ${key}`);
  assert.equal(build.win.signExecutable, true, 'Source must enable executable signing');
  assert(['asInvoker', 'highestAvailable', 'requireAdministrator'].includes(build.win.requestedExecutionLevel));
  const icon = path.join(payload, 'resources/dfcode-icon.ico');
  assert(fs.existsSync(icon), 'Missing packaged application icon');
  return {
    appId: build.appId, productName: build.productName, artifactName: build.artifactName,
    electronVersion: electron, forceCodeSigning: true, npmRebuild: false,
    directories: { output },
    win: { icon, target: [{ target: 'nsis', arch: ['x64'] }], requestedExecutionLevel: build.win.requestedExecutionLevel,
      signExecutable: true, signExts: ['.exe', '.dll', '.node'],
      signtoolOptions: { sign: path.join(__dirname, 'windows-sign-hook.cjs'), signingHashAlgorithms: ['sha256'], publisherName: [config.windows.publisherName] } },
    nsis: { ...build.nsis, installerIcon: icon, uninstallerIcon: icon, packElevateHelper: false },
    publish: { provider: 'generic', url: config.updateBaseUrl, channel: config.channel },
  };
}
function refreshPayloadMetadata(config, payload, deps = dependencies(config)) {
  const manifestFile = path.join(payload, 'resources/engine/manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8').replace(/^\uFEFF/, ''));
  assert.equal(manifest.commit, config.engineCommit); assert.equal(manifest.engineVersion, config.engineVersion);
  manifest.binarySha256 = hashFile(path.join(payload, 'resources/engine/dfcode.exe'));
  manifest.signing = { mode: 'keylocker', signed: true, publisherName: config.windows.publisherName };
  writeJson(manifestFile, manifest);
  const updaterFile = path.join(payload, 'resources/app-update.yml');
  const updater = deps.yaml.load(fs.readFileSync(updaterFile, 'utf8'));
  assert.equal(updater.provider, 'generic'); assert.equal(updater.url, config.updateBaseUrl); assert.equal(updater.channel, config.channel);
  updater.publisherName = [config.windows.publisherName];
  fs.writeFileSync(updaterFile, deps.yaml.dump(updater, { lineWidth: -1 }));
  return { engineSha256: manifest.binarySha256, updater };
}
function comparePayloads(original, signed, final, inputApi, config, deps = dependencies(config)) {
  const baseline = inputApi.inventoryTree(original), prepared = inputApi.inventoryTree(signed), extracted = inputApi.inventoryTree(final);
  assert.deepEqual(extracted, prepared, 'Final NSIS payload differs from the signed copy');
  assert.deepEqual(baseline.map(x => x.file), prepared.map(x => x.file), 'Signing added or removed application files');
  const modifications = [];
  for (let i = 0; i < baseline.length; i++) {
    const a = baseline[i], b = prepared[i];
    if (a.sha256 === b.sha256) continue;
    modifications.push(a.file);
    if (['resources/engine/manifest.json', 'resources/app-update.yml'].includes(a.file)) continue;
    const originalFile = path.join(original, a.file), signedFile = path.join(signed, a.file);
    assert(inputApi.inspectPe(originalFile), `Unexpected non-PE application change: ${a.file}`);
    assert.equal(inputApi.peContentDigest(originalFile), inputApi.peContentDigest(signedFile), `PE content changed beyond Authenticode: ${a.file}`);
  }
  const beforeManifest = JSON.parse(fs.readFileSync(path.join(original, 'resources/engine/manifest.json'), 'utf8').replace(/^\uFEFF/, ''));
  const afterManifest = JSON.parse(fs.readFileSync(path.join(final, 'resources/engine/manifest.json'), 'utf8').replace(/^\uFEFF/, ''));
  for (const key of ['binarySha256', 'signing']) { delete beforeManifest[key]; delete afterManifest[key]; }
  assert.deepEqual(beforeManifest, afterManifest, 'Engine source or skills metadata changed');
  const beforeUpdate = deps.yaml.load(fs.readFileSync(path.join(original, 'resources/app-update.yml'), 'utf8'));
  const afterUpdate = deps.yaml.load(fs.readFileSync(path.join(final, 'resources/app-update.yml'), 'utf8'));
  assert.deepEqual(afterUpdate.publisherName, [config.windows.publisherName]);
  delete beforeUpdate.publisherName; delete afterUpdate.publisherName;
  assert.deepEqual(beforeUpdate, afterUpdate, 'Update source/cache settings changed');
  return { passed: true, files: extracted.length, modifications, applicationSourceUnchanged: true, finalPayloadMatchesSignedCopy: true };
}
function safeSevenzipListing(listing) {
  assert(!/^(?:Symbolic Link|Hard Link) = .+/m.test(listing), 'Links are not allowed in NSIS payload');
  const names = [...listing.matchAll(/^Path = (.+)\r?$/gm)].map(x => x[1].replace(/\r$/, ''));
  assert(names.length > 0 && names.length < 100000, 'Unexpected NSIS archive inventory');
  const seen = new Set();
  for (const name of names) {
    const parts = name.replaceAll('\\', '/').split('/');
    assert(!path.win32.isAbsolute(name) && !/[:\0\r\n]/.test(name) && parts.every(p => p && p !== '.' && p !== '..' && !/[ .]$/.test(p) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(p)), `Unsafe NSIS archive path: ${name}`);
    const folded = parts.join('/').toLowerCase(); assert(!seen.has(folded), `Duplicate NSIS path: ${name}`); seen.add(folded);
  }
  return names;
}
async function extractInstaller(installer, destination, deps, command = run) {
  assert(!fs.existsSync(destination), 'Do not overwrite an existing extracted installer'); noLinks(destination);
  const sevenzip = await deps.getSevenzip();
  safeSevenzipListing(command(sevenzip, ['l', '-slt', '-ba', '-sccUTF-8', installer]));
  fs.mkdirSync(destination, { recursive: true });
  const output = command(sevenzip, ['x', installer, `-o${destination}`, '-y', '-sccUTF-8'], { timeout: 300000 });
  assert(output.includes('Type = 7z'), 'Expected a directly extractable NSIS application archive');
  return { extractor: 'electron-builder pinned 7zip toolset', passed: true };
}
function extractUninstaller(installer, expectedFile, destination) {
  assert(!fs.existsSync(destination), 'Do not overwrite extracted uninstaller');
  const data = fs.readFileSync(installer), expected = fs.readFileSync(expectedFile);
  assert(expected.length < 16 * 1024 * 1024 && expected.subarray(0, 2).toString() === 'MZ');
  assert(data.subarray(0, 2).toString() === 'MZ');
  const pe = data.readUInt32LE(0x3c);
  assert(pe >= 64 && pe + 24 < data.length && data.readUInt32LE(pe) === 0x4550);
  const count = data.readUInt16LE(pe + 6), optional = data.readUInt16LE(pe + 20);
  assert(count > 0 && count <= 96);
  let overlay = 0;
  for (let i = 0; i < count; i++) {
    const offset = pe + 24 + optional + i * 40;
    assert(offset + 40 <= data.length);
    const size = data.readUInt32LE(offset + 16), start = data.readUInt32LE(offset + 20);
    assert(start + size <= data.length); overlay = Math.max(overlay, start + size);
  }
  assert(overlay + 28 < data.length && data.subarray(overlay + 4, overlay + 20).equals(Buffer.from('efbeadde4e756c6c736f6674496e7374', 'hex')), 'Unsupported NSIS overlay');
  const end = overlay + data.readUInt32LE(overlay + 24);
  assert(end <= data.length && end > overlay + 32);
  let position = overlay + 28, block = 0, found = null;
  while (position + 4 < end) {
    const value = data.readUInt32LE(position), compressed = (value & 0x80000000) !== 0, size = value & 0x7fffffff;
    position += 4; assert(position + size <= end, 'Unsupported NSIS data block');
    const packed = data.subarray(position, position + size); position += size; block++;
    if (!compressed && size !== expected.length) continue;
    let decoded;
    try { decoded = compressed ? zlib.inflateRawSync(packed, { maxOutputLength: expected.length + 1 }) : packed; }
    catch (error) { if (error.code === 'ERR_BUFFER_TOO_LARGE') continue; throw error; }
    if (decoded.length === expected.length && decoded.equals(expected)) { assert(found === null, 'Duplicate matching NSIS uninstaller'); found = { block, size: decoded.length, sha256: hashFile(expectedFile) }; }
  }
  assert(found, 'Final NSIS does not contain the signed uninstaller captured by the hook');
  fs.writeFileSync(destination, expected, { flag: 'wx' });
  return { passed: true, ...found };
}
async function buildInstaller(config, input, paths, tools, deps = dependencies(config), command = run) {
  assert(!fs.existsSync(paths.builder), 'Previous NSIS build directory exists; preserve it and start a new attempt');
  fs.mkdirSync(paths.builder, { recursive: true }); fs.mkdirSync(paths.buildOutput);
  const originalPackage = input.packagingConfig.packageJson || input.packagingConfig;
  const packageJson = { name: originalPackage.name, version: config.version, private: true, description: 'DFCode Studio', main: originalPackage.main, author: config.windows.publisherName };
  writeNewJson(path.join(paths.builder, 'package.json'), packageJson);
  writeNewJson(path.join(paths.builder, 'electron-builder.json'), createBuilderConfig(config, input.packagingConfig, paths.payload, paths.buildOutput, tools.electron));
  const hookConfig = path.join(paths.builder, 'sign-config.json');
  writeNewJson(hookConfig, { schemaVersion: 1, windows: config.windows, ownedRoot: paths.work, journalFile: paths.hookJournal, uninstallerPath: paths.uninstaller });
  command(process.execPath, [deps.builderCli, '--win', 'nsis', '--x64', '--prepackaged', paths.payload, '--config', path.join(paths.builder, 'electron-builder.json'), '--publish', 'never'], {
    cwd: paths.builder, env: { ...process.env, DFCODE_WINDOWS_SIGN_CONFIG: hookConfig }, timeout: 30 * 60 * 1000,
  });
  const installer = path.join(paths.buildOutput, `DFCode-${config.version}-x64.exe`);
  assert(fs.existsSync(installer) && fs.existsSync(paths.uninstaller), 'Builder did not produce installer and signed uninstaller evidence');
  return { installer, uninstaller: paths.uninstaller };
}
async function verifyBlockmap(installer, blockmap, regenerated, deps) {
  assert(!fs.existsSync(regenerated), 'Preserve previous blockmap verification output');
  const before = hashFile(installer);
  await deps.buildBlockMap(installer, 'gzip', regenerated);
  assert.equal(hashFile(installer), before, 'Blockmap generation modified the installer');
  assert(zlib.gunzipSync(fs.readFileSync(blockmap)).equals(zlib.gunzipSync(fs.readFileSync(regenerated))), 'Blockmap does not match final signed installer bytes');
  return true;
}
async function finalizeMetadata(config, installer, destination, deps = dependencies(config), command = run) {
  assert(!fs.existsSync(destination), 'Preserve existing native delivery; use resume or a new release output');
  noLinks(destination); fs.mkdirSync(destination, { recursive: true });
  const name = `DFCode-${config.version}-x64.exe`, target = path.join(destination, name), currentNotes = notes(config.otaNotesFile);
  fs.copyFileSync(installer, target, fs.constants.COPYFILE_EXCL);
  await deps.buildBlockMap(target, 'gzip', `${target}.blockmap`);
  const sha512 = hashFile(target, 'sha512', 'base64'), size = fs.statSync(target).size;
  fs.writeFileSync(path.join(destination, `${config.channel}.yml`), deps.yaml.dump({ version: config.version, files: [{ url: name, sha512, size }], path: name, sha512, releaseDate: new Date().toISOString(), releaseNotes: currentNotes }, { lineWidth: -1 }), { flag: 'wx' });
  const stage = path.join(path.dirname(destination), '.windows-metadata');
  assert(!fs.existsSync(stage), 'Preserve previous metadata attempt');
  command(process.execPath, [path.join(config.workspace, 'scripts/prepare-admin-full-ota-release.mjs'), '--artifact-dir', destination, '--output-dir', stage,
    '--channel', config.channel, '--version', config.version, '--platform', 'win32', '--arch', 'x64', '--studio-commit', config.studioCommit,
    '--engine-commit', config.engineCommit, '--engine-repository', `https://github.com/${config.engineRepository}.git`, '--signing-status', 'signed',
    '--publisher-name', config.windows.publisherName, '--release-notes', config.otaNotesFile]);
  fs.copyFileSync(path.join(stage, `${config.channel}.yml`), path.join(destination, `${config.channel}.yml`));
  fs.copyFileSync(path.join(stage, 'release.json'), path.join(destination, 'release.json'), fs.constants.COPYFILE_EXCL);
  assert.equal(hashFile(target), hashFile(installer), 'Metadata helper changed installer bytes');
  const zip = path.join(destination, `DFCode-${config.version}-win32-x64-full-ota-signed.zip`);
  const names = ['release.json', name, `${name}.blockmap`, `${config.channel}.yml`];
  const sevenzip = await deps.getSevenzip();
  command(sevenzip, ['a', '-tzip', '-mx=0', '-sccUTF-8', zip, ...names], { cwd: destination, timeout: 300000 });
  command(sevenzip, ['t', zip], { timeout: 300000 });
  const proof = verifyFullOtaEntries(await inspectFlatZip(zip, config.workspace), config, { platform: 'win32', arch: 'x64' }, 'signed');
  assert.equal(proof.manifest.signing.publisherName, config.windows.publisherName);
  return { installer: target, zip, releaseHash: proof.manifest.releaseHash, files: [...names, path.basename(zip)].map(file => ({ path: path.join(destination, file), size: fs.statSync(path.join(destination, file)).size, sha256: hashFile(path.join(destination, file)) })), passed: true };
}

module.exports = { noLinks, ownedPath, writeNewJson, notes, dependencies, validateToolchain, createBuilderConfig, refreshPayloadMetadata, comparePayloads, safeSevenzipListing, extractInstaller, extractUninstaller, buildInstaller, verifyBlockmap, finalizeMetadata };
