'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const childProcess = require('node:child_process');

const SHA1 = /^[A-Fa-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const MICROSOFT_SUBJECT = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US';
const MICROSOFT_FILES = new Set(['d3dcompiler_47.dll', 'dxil.dll']);
const WINDOWS_KEYS = new Set(['publisherName', 'certificateSha1', 'keypairAlias', 'smctlPath', 'signtoolPath',
  'powershellPath', 'timestampUrl', 'preserveMicrosoftSignatures']);
const STATES = new Set(['prepared', 'signing', 'uncertain', 'verified', 'committed']);
const MAX_PE_SIZE = 4 * 1024 * 1024 * 1024;

function requireValue(condition, message) {
  if (!condition) throw new Error(message);
}

function inside(root, file) {
  const relative = path.relative(root, file);
  return relative !== '' && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function ordinaryPath(file, { directory = false, allowMissing = false } = {}) {
  requireValue(typeof file === 'string' && path.isAbsolute(file) && !/[\r\n\0]/.test(file), 'An absolute local path is required');
  requireValue(!/^[\\/]{2}/.test(file), 'UNC/device paths are not signing paths');
  const absolute = path.resolve(file);
  const relativeParts = path.relative(path.parse(absolute).root, absolute).split(path.sep);
  requireValue(relativeParts.every(part => !part.includes(':') && !/[. ]$/.test(part)),
    'Alternate streams and ambiguous Windows path names are not signing paths');
  let current = absolute;
  while (true) {
    let info;
    try { info = fs.lstatSync(current); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (info) {
      requireValue(!info.isSymbolicLink(), 'Signing paths must not contain links or junctions');
      requireValue(current === absolute || info.isDirectory(), 'Signing path ancestor is not a directory');
    } else {
      requireValue(allowMissing, 'Signing path is unavailable');
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  if (fs.existsSync(absolute)) {
    const info = fs.statSync(absolute);
    requireValue(directory ? info.isDirectory() : info.isFile(), 'Unexpected signing path type');
    if (!directory) requireValue(info.nlink === 1, 'Signing files must not be hard linked');
  } else requireValue(allowMissing, 'Signing path is unavailable');
  return absolute;
}

function hashFile(file) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    let count;
    while ((count = fs.readSync(fd, buffer, 0, buffer.length, null))) hash.update(buffer.subarray(0, count));
  } finally { fs.closeSync(fd); }
  return hash.digest('hex');
}

function peHeader(file) {
  const info = fs.statSync(file);
  requireValue(info.size >= 128 && info.size <= MAX_PE_SIZE, 'Unexpected PE file size');
  const fd = fs.openSync(file, 'r');
  try {
    const dos = Buffer.alloc(64);
    requireValue(fs.readSync(fd, dos, 0, dos.length, 0) === 64 && dos.toString('ascii', 0, 2) === 'MZ', 'Signing target/tool is not PE');
    const offset = dos.readUInt32LE(0x3c);
    requireValue(offset >= 64 && offset + 24 <= info.size && offset < 16 * 1024 * 1024, 'Invalid PE header offset');
    const head = Buffer.alloc(24);
    fs.readSync(fd, head, 0, head.length, offset);
    requireValue(head.toString('ascii', 0, 4) === 'PE\0\0', 'Invalid PE signature');
    const machine = head.readUInt16LE(4);
    const optionalSize = head.readUInt16LE(20);
    requireValue([0x14c, 0x8664].includes(machine) && optionalSize >= 136 && offset + 24 + optionalSize <= info.size, 'Unsupported PE architecture/header');
    const optional = Buffer.alloc(optionalSize);
    fs.readSync(fd, optional, 0, optional.length, offset + 24);
    const magic = optional.readUInt16LE(0);
    requireValue((machine === 0x8664 && magic === 0x20b) || (machine === 0x14c && magic === 0x10b), 'PE machine/header mismatch');
    const directoryStart = magic === 0x20b ? 112 : 96;
    const countOffset = magic === 0x20b ? 108 : 92;
    requireValue(optional.readUInt32LE(countOffset) >= 5 && optionalSize >= directoryStart + 40, 'PE security directory is unavailable');
    const securityRelative = directoryStart + 4 * 8;
    const certificateOffset = optional.readUInt32LE(securityRelative);
    const certificateSize = optional.readUInt32LE(securityRelative + 4);
    requireValue((certificateOffset === 0 && certificateSize === 0) ||
      (certificateOffset >= offset + 24 + optionalSize && certificateSize >= 8 && certificateOffset + certificateSize <= info.size),
    'Malformed PE certificate directory');
    return { machine, size: info.size, checksumOffset: offset + 24 + 64,
      securityOffset: offset + 24 + securityRelative, certificateOffset, certificateSize };
  } finally { fs.closeSync(fd); }
}

function normalizedPrefix(file, size, header) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buffer = Buffer.alloc(1024 * 1024);
    for (let offset = 0; offset < size;) {
      const count = fs.readSync(fd, buffer, 0, Math.min(buffer.length, size - offset), offset);
      requireValue(count > 0, 'Unexpected end of signed PE');
      for (const [start, length] of [[header.checksumOffset, 4], [header.securityOffset, 8]]) {
        const low = Math.max(start, offset), high = Math.min(start + length, offset + count);
        if (low < high) buffer.fill(0, low - offset, high - offset);
      }
      hash.update(buffer.subarray(0, count));
      offset += count;
    }
  } finally { fs.closeSync(fd); }
  return hash.digest('hex');
}

function originalContent(file) {
  const header = peHeader(file);
  requireValue(header.certificateOffset === 0, 'An unsigned target has a nonempty PE signature directory');
  return { ...header, normalizedSha256: normalizedPrefix(file, header.size, header) };
}

function verifyOriginalContent(file, expected) {
  const header = peHeader(file);
  requireValue(header.machine === expected.machine && header.checksumOffset === expected.checksumOffset &&
    header.securityOffset === expected.securityOffset && header.certificateOffset >= expected.size &&
    header.certificateOffset <= expected.size + 7 && header.certificateOffset % 8 === 0 &&
    header.certificateOffset + header.certificateSize === header.size,
  'Signed PE changed more than its checksum and appended Authenticode signature');
  requireValue(normalizedPrefix(file, expected.size, header) === expected.normalizedSha256,
    'Signed PE content differs from the journaled unsigned bytes');
  const paddingSize = header.certificateOffset - expected.size;
  if (paddingSize) {
    const fd = fs.openSync(file, 'r');
    try {
      const padding = Buffer.alloc(paddingSize);
      fs.readSync(fd, padding, 0, paddingSize, expected.size);
      requireValue(padding.every(byte => byte === 0), 'Unexpected bytes before appended PE certificate');
    } finally { fs.closeSync(fd); }
  }
}

function publicText(value, label, { nullable = true } = {}) {
  if (value == null && nullable) return null;
  requireValue(typeof value === 'string' && value.length <= 2048 && !/[\x00-\x1f\x7f]/.test(value), `Invalid public ${label}`);
  return value;
}

function signingBinding(windows) {
  return crypto.createHash('sha256').update(JSON.stringify({ publisherName: windows.publisherName,
    certificateSha1: windows.certificateSha1, keypairAlias: windows.keypairAlias, timestampUrl: windows.timestampUrl,
    preserveMicrosoftSignatures: windows.preserveMicrosoftSignatures })).digest('hex');
}
function journalKey(file) {
  return crypto.createHash('sha256').update(file.toLowerCase()).digest('hex');
}

function createSigningApi(dependencies = {}) {
  const host = { platform: dependencies.platform ?? process.platform, arch: dependencies.arch ?? process.arch };
  const environment = dependencies.env ?? process.env;
  const spawn = dependencies.spawnSync ?? childProcess.spawnSync;
  const alive = dependencies.processAlive ?? (pid => {
    try { process.kill(pid, 0); return true; } catch (error) { return error.code !== 'ESRCH'; }
  });
  function assertHost() {
    requireValue(host.platform === 'win32' && host.arch === 'x64', 'Signing requires native Windows x64');
  }

  function nativeTool(file, basename) {
    const resolved = ordinaryPath(file);
    requireValue(path.basename(resolved).toLowerCase() === basename.toLowerCase(), `Expected native ${basename}`);
    requireValue(peHeader(resolved).machine === 0x8664, `${basename} must be native Windows x64`);
    return resolved;
  }

  function resolveTools(config) {
    assertHost();
    const raw = config?.windows;
    requireValue(raw && typeof raw === 'object' && !Array.isArray(raw), 'windows signing configuration is required');
    for (const name of Object.keys(raw)) requireValue(WINDOWS_KEYS.has(name), 'Only public signing fields belong in windows configuration');
    const publisherName = publicText(raw.publisherName, 'publisherName', { nullable: false });
    requireValue(publisherName.trim() === publisherName && publisherName.length > 0 && publisherName.length <= 256, 'Exact publisherName is required');
    requireValue(SHA1.test(raw.certificateSha1 || ''), 'An explicit certificateSha1 is required');
    requireValue(typeof raw.keypairAlias === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(raw.keypairAlias), 'An explicit safe keypairAlias is required');
    requireValue(raw.preserveMicrosoftSignatures === undefined || typeof raw.preserveMicrosoftSignatures === 'boolean', 'preserveMicrosoftSignatures must be boolean');
    const timestampUrl = raw.timestampUrl ?? 'http://timestamp.digicert.com';
    requireValue(typeof timestampUrl === 'string' && !/[\x00-\x20\x7f]/.test(timestampUrl), 'Invalid timestampUrl');
    let url;
    try { url = new URL(timestampUrl); } catch { throw new Error('Invalid timestampUrl'); }
    requireValue(['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && !url.search && !url.hash, 'timestampUrl must be a credential-free HTTP(S) URL');
    const programFiles = environment.ProgramFiles || 'C:\\Program Files';
    const programFilesX86 = environment['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';
    const smctlPath = raw.smctlPath || path.join(programFiles, 'DigiCert', 'DigiCert One Signing Manager Tools', 'smctl.exe');
    let signtoolPath = raw.signtoolPath;
    if (!signtoolPath) {
      const sdk = path.join(programFilesX86, 'Windows Kits', '10', 'bin');
      ordinaryPath(sdk, { directory: true });
      const versions = fs.readdirSync(sdk).filter(name => /^\d+\.\d+\.\d+\.\d+$/.test(name))
        .sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
      signtoolPath = versions.map(name => path.join(sdk, name, 'x64', 'signtool.exe')).find(file => fs.existsSync(file));
      requireValue(signtoolPath, 'An installed Windows SDK x64 SignTool is required');
    }
    const powershellPath = raw.powershellPath || environment.DFCODE_LOCAL_PWSH || path.join(programFiles, 'PowerShell', '7', 'pwsh.exe');
    return { publisherName, certificateSha1: raw.certificateSha1.toUpperCase(), keypairAlias: raw.keypairAlias,
      timestampUrl, preserveMicrosoftSignatures: raw.preserveMicrosoftSignatures !== false,
      smctlPath: nativeTool(smctlPath, 'smctl.exe'), signtoolPath: nativeTool(signtoolPath, 'signtool.exe'),
      powershellPath: nativeTool(powershellPath, 'pwsh.exe') };
  }

  function invoke(file, args, timeout = 240000) {
    // Output remains in memory only and is never included in thrown errors or
    // journal records. SMCTL diagnostics can contain credential details.
    try {
      const result = spawn(file, args, { encoding: 'utf8', windowsHide: true, shell: false,
        timeout, maxBuffer: 4 * 1024 * 1024, env: environment });
      return { ok: !result.error && result.status === 0, status: Number.isInteger(result.status) ? result.status : null,
        stdout: String(result.stdout || ''), stderr: String(result.stderr || '') };
    } catch { return { ok: false, status: null, stdout: '', stderr: '' }; }
  }

  function publicInspection(windows, args) {
    const result = invoke(windows.powershellPath, ['-NoLogo', '-NoProfile', '-NonInteractive', '-File',
      path.join(__dirname, 'windows-signature.ps1'), ...args], 60000);
    requireValue(result.ok, 'Windows public signature inspection failed');
    try { return JSON.parse(result.stdout.replace(/^\uFEFF/, '')); }
    catch { throw new Error('Windows public signature inspection returned invalid metadata'); }
  }

  function preflightSigning(config) {
    const windows = resolveTools(config);
    const version = invoke(windows.smctlPath, ['--version'], 30000);
    requireValue(version.ok, 'Configured SMCTL could not report its version');
    const certificate = publicInspection(windows, ['-CertificateSha1', windows.certificateSha1]);
    requireValue(certificate.thumbprint === windows.certificateSha1 && certificate.publisherName === windows.publisherName &&
      certificate.codeSigning === true && certificate.currentlyValid === true, 'Configured public code-signing certificate is unavailable or mismatched');
    return { windows, provider: 'keylocker-smctl-simple', credentialStatus: 'tools-ready', remoteSigningPermissionVerified: false,
      smctlVersion: version.stdout.match(/\b\d+\.\d+\.\d+(?:[-+][\w.-]+)?\b/)?.[0] || 'unreported',
      certificate: { thumbprint: windows.certificateSha1, subject: publicText(certificate.subject, 'certificate subject'),
        publisherName: windows.publisherName, notBefore: publicText(certificate.notBefore, 'certificate start'),
        notAfter: publicText(certificate.notAfter, 'certificate expiry'), codeSigning: true } };
  }

  function verifyResolved(file, windows) {
    file = ordinaryPath(file);
    const header = peHeader(file);
    const before = hashFile(file);
    const details = publicInspection(windows, ['-TargetFile', file]);
    const statuses = new Set(['Valid', 'UnknownError', 'NotSigned', 'HashMismatch', 'NotTrusted', 'NotSupportedFileFormat', 'Incompatible']);
    requireValue(statuses.has(details.status), 'Unexpected Authenticode status');
    const value = { path: file, status: details.status,
      signerSubject: publicText(details.signerSubject, 'signer subject'),
      signerThumbprint: details.signerThumbprint == null ? null : String(details.signerThumbprint).toUpperCase(),
      publisherName: publicText(details.publisherName, 'publisher name'),
      timestampSubject: publicText(details.timestampSubject, 'timestamp subject'),
      timestampThumbprint: details.timestampThumbprint == null ? null : String(details.timestampThumbprint).toUpperCase(),
      signatureType: publicText(details.signatureType, 'signature type'), sha256: before, size: header.size,
      identity: 'unexpected', valid: false, signTool: { exitCode: null, warnings: null, errors: null, signatureCount: null, digestAlgorithm: null } };
    for (const thumbprint of [value.signerThumbprint, value.timestampThumbprint]) requireValue(thumbprint === null || SHA1.test(thumbprint), 'Invalid public certificate fingerprint');
    if (details.status === 'NotSigned') {
      if (!value.signerThumbprint && !value.timestampThumbprint && header.certificateOffset === 0) value.identity = 'unsigned';
    } else if (details.status === 'Valid') {
      const result = invoke(windows.signtoolPath, ['verify', '/pa', '/all', '/v', '/tw', file]);
      const combined = result.stdout + '\n' + result.stderr;
      const warnings = combined.match(/Number of warnings:\s*(\d+)/i);
      const errors = combined.match(/Number of errors:\s*(\d+)/i);
      const signatureCount = combined.match(/Number of signatures successfully Verified:\s*(\d+)/i);
      const algorithms = [...combined.matchAll(/Hash of file \(([^)]+)\)/gi)].map(match => match[1].toLowerCase());
      value.signTool = { exitCode: result.status, warnings: warnings ? Number(warnings[1]) : null,
        errors: errors ? Number(errors[1]) : null, signatureCount: signatureCount ? Number(signatureCount[1]) : null,
        digestAlgorithm: algorithms.length === 1 && algorithms[0] === 'sha256' ? 'sha256' : null };
      const trusted = result.ok && value.signTool.warnings === 0 && value.signTool.errors === 0 &&
        value.signTool.signatureCount === 1 && value.signTool.digestAlgorithm === 'sha256' &&
        value.timestampThumbprint && value.signatureType === 'Authenticode' && header.certificateOffset > 0;
      if (trusted && value.signerThumbprint === windows.certificateSha1 && value.publisherName === windows.publisherName) {
        value.identity = 'configured'; value.valid = true;
      } else if (trusted && windows.preserveMicrosoftSignatures && MICROSOFT_FILES.has(path.basename(file).toLowerCase()) &&
                 value.signerSubject === MICROSOFT_SUBJECT && value.publisherName === 'Microsoft Corporation') {
        value.identity = 'microsoft'; value.valid = true;
      }
    }
    requireValue(hashFile(file) === before && fs.statSync(file).size === header.size, 'Signature target changed during verification');
    value.preservedMicrosoftSignature = value.identity === 'microsoft';
    value.signToolWarnings = value.signTool.warnings;
    value.signToolErrors = value.signTool.errors;
    return value;
  }

  function verifySignature(file, config) {
    return verifyResolved(file, resolveTools(config));
  }

  // Read-only recovery proof. It never creates a journal, changes a state, or
  // calls SMCTL. journalTarget binds an audit copy to its original hook target.
  function verifyJournaledFile(file, config, options = {}) {
    assertHost();
    const windows = resolveTools(config);
    const root = ordinaryPath(options.ownedRoot, { directory: true });
    file = ordinaryPath(file);
    const target = ordinaryPath(options.journalTarget || file, { allowMissing: true });
    requireValue(inside(root, file) && inside(root, target), 'Journal verification target escaped its owned staging root');
    const journal = options.journal;
    requireValue(journal && journal.schemaVersion === 1 && journal.entries && typeof journal.entries === 'object' &&
      !Array.isArray(journal.entries), 'A schemaVersion 1 signing journal is required');
    const key = journalKey(target);
    const entry = Object.hasOwn(journal.entries, key) ? journal.entries[key] : null;
    requireValue(entry && entry.path === target && entry.ownedRoot === root &&
      entry.configBinding === signingBinding(windows) && SHA256.test(entry.originalSha256),
    'Journal entry does not match the target and configured signing identity');
    requireValue(entry.state === 'committed' || entry.state === 'verified', 'Journal does not establish completed signed bytes');
    if (options.originalSha256 !== undefined) requireValue(entry.originalSha256 === options.originalSha256,
      'Journal original hash differs from the verified unsigned input');
    const current = verifyResolved(file, windows);
    requireValue(entry.result && current.valid && current.sha256 === entry.result.sha256 &&
      current.identity === entry.result.identity, 'Journaled signed bytes changed; refusing to accept another signature');
    if (entry.state === 'verified') {
      requireValue(current.identity === 'configured' && current.sha256 === entry.signedSha256 && entry.originalContent,
        'Journal does not establish the interrupted replacement bytes');
      verifyOriginalContent(file, entry.originalContent);
    }
    return { ...current, originalSha256: entry.originalSha256, journalTarget: target, journalState: entry.state };
  }

  function signFile(file, config, options = {}) {
    assertHost();
    const windows = resolveTools(config);
    const root = ordinaryPath(options.ownedRoot, { directory: true });
    requireValue(root !== path.parse(root).root, 'A dedicated owned signing root is required');
    file = ordinaryPath(file);
    requireValue(inside(root, file), 'Signing target escaped its owned staging root');
    requireValue(/\.(exe|dll|node)$/i.test(file), 'Only owned PE EXE, DLL and native-module files can be signed');
    const journal = options.journal;
    requireValue(journal && journal.schemaVersion === 1 && journal.entries && typeof journal.entries === 'object' && !Array.isArray(journal.entries), 'A schemaVersion 1 signing journal is required');
    requireValue(typeof options.save === 'function', 'A synchronous durable journal save callback is required');
    const save = () => {
      const result = options.save(journal);
      requireValue(!result || typeof result.then !== 'function', 'Journal save must finish synchronously before signing');
    };
    const binding = signingBinding(windows);
    const key = journalKey(file);
    const temporaryRoot = ordinaryPath(options.tempRoot || path.join(root, '.signing-staging'), { directory: true, allowMissing: true });
    requireValue(inside(root, temporaryRoot), 'Detached signing copies must stay in the owned staging root');
    fs.mkdirSync(temporaryRoot, { recursive: true });
    ordinaryPath(temporaryRoot, { directory: true });
    const lockFile = path.join(temporaryRoot, `${key}.lock.json`);
    if (fs.existsSync(lockFile)) {
      ordinaryPath(lockFile);
      let existing;
      try { existing = JSON.parse(fs.readFileSync(lockFile, 'utf8')); } catch { throw new Error('Signing lock is malformed; manual review is required'); }
      requireValue(existing.schemaVersion === 1 && existing.key === key && Number.isInteger(existing.pid) && existing.pid > 0,
        'Signing lock does not belong to this target');
      requireValue(!alive(existing.pid), 'Another live process owns this signing target');
      fs.unlinkSync(lockFile);
    }
    fs.writeFileSync(lockFile, JSON.stringify({ schemaVersion: 1, pid: process.pid, key }), { flag: 'wx', mode: 0o600 });
    try {
      let entry = Object.hasOwn(journal.entries, key) ? journal.entries[key] : null;
      const recovering = Boolean(entry);
      const current = verifyResolved(file, windows);
      if (entry) {
        requireValue(entry.path === file && entry.ownedRoot === root && entry.configBinding === binding && STATES.has(entry.state) &&
          SHA256.test(entry.originalSha256), 'Journal entry does not match the target and configured signing identity');
        if (entry.state === 'committed') {
          requireValue(entry.result && current.sha256 === entry.result.sha256 && current.valid &&
            current.identity === entry.result.identity, 'Committed signing target changed; refusing to re-sign');
          return { ...current, originalSha256: entry.originalSha256, action: current.identity === 'microsoft' ? 'preserved-microsoft' : 'reused' };
        }
        if (current.valid && entry.signedSha256 === current.sha256 && current.identity === 'configured') {
          verifyOriginalContent(file, entry.originalContent);
          entry.state = 'committed'; entry.result = current; save();
          return { ...current, originalSha256: entry.originalSha256, action: 'reused' };
        }
        requireValue(current.sha256 === entry.originalSha256 && current.identity === 'unsigned', 'Pending signing target bytes or signature changed');
      } else {
        if (current.valid) {
          journal.entries[key] = { path: file, ownedRoot: root, configBinding: binding, state: 'committed',
            originalSha256: current.sha256, result: current };
          save();
          return { ...current, originalSha256: current.sha256, action: current.identity === 'microsoft' ? 'preserved-microsoft' : 'reused' };
        }
        requireValue(current.identity === 'unsigned', 'Unexpected, invalid or unapproved existing signature; refusing to replace it');
        const directory = path.join(temporaryRoot, `${key}-${crypto.randomBytes(12).toString('hex')}`);
        entry = { path: file, ownedRoot: root, configBinding: binding, state: 'prepared', originalSha256: current.sha256,
          originalContent: originalContent(file), tempPath: path.join(directory, path.basename(file)), startedAt: new Date().toISOString() };
        journal.entries[key] = entry;
        save();
      }
      requireValue(typeof entry.tempPath === 'string' && inside(temporaryRoot, path.resolve(entry.tempPath)) &&
        path.basename(entry.tempPath) === path.basename(file) &&
        new RegExp(`^${key}-[a-f0-9]{24}$`).test(path.basename(path.dirname(entry.tempPath))),
      'Detached signing path is outside this operation');
      ordinaryPath(entry.tempPath, { allowMissing: true });
      if (!fs.existsSync(entry.tempPath)) {
        requireValue(entry.state === 'prepared', 'Pending signature outcome is unknown and its detached copy is missing; no automatic retry');
        fs.mkdirSync(path.dirname(entry.tempPath), { recursive: true });
        fs.copyFileSync(file, entry.tempPath, fs.constants.COPYFILE_EXCL);
      }
      let detached = verifyResolved(entry.tempPath, windows);
      if (entry.state === 'prepared') {
        requireValue(detached.identity === 'unsigned' && detached.sha256 === entry.originalSha256,
          'Prepared detached copy differs from the journaled unsigned input');
        entry.state = 'signing'; save();
        const result = invoke(windows.smctlPath, ['sign', '--simple', '--unsigned', '--keypair-alias', windows.keypairAlias,
          '--input', entry.tempPath, '--digalg', 'SHA256', '--timestamp', '--ts-server', windows.timestampUrl]);
        entry.providerExitCode = result.status;
        // Even a failed/timeout response can follow a successful remote sign.
        // Never repeat the provider request without first resolving these bytes.
        try { detached = verifyResolved(entry.tempPath, windows); }
        catch {
          entry.state = 'uncertain'; save();
          throw new Error('Signing outcome is unresolved; detached bytes and journal were preserved, no automatic retry');
        }
      }
      if (!detached.valid || detached.identity !== 'configured') {
        entry.state = 'uncertain'; save();
        throw new Error('Signing outcome is unresolved or has an unexpected signature; no automatic retry');
      }
      verifyOriginalContent(entry.tempPath, entry.originalContent);
      entry.state = 'verified'; entry.signedSha256 = detached.sha256; entry.result = detached; save();
      requireValue(hashFile(file) === entry.originalSha256, 'Owned target changed before signed-copy replacement');
      ordinaryPath(file); ordinaryPath(entry.tempPath);
      fs.renameSync(entry.tempPath, file);
      const final = verifyResolved(file, windows);
      requireValue(final.valid && final.identity === 'configured' && final.sha256 === entry.signedSha256, 'Signed-copy replacement verification failed');
      entry.state = 'committed'; entry.result = final; entry.finishedAt = new Date().toISOString(); save();
      return { ...final, originalSha256: entry.originalSha256, action: recovering ? 'reused' : 'signed' };
    } finally {
      if (fs.existsSync(lockFile)) {
        ordinaryPath(lockFile);
        let held;
        try { held = JSON.parse(fs.readFileSync(lockFile, 'utf8')); } catch { throw new Error('Signing lock changed during the operation'); }
        requireValue(held.key === key && held.pid === process.pid, 'Signing lock ownership changed during the operation');
        fs.unlinkSync(lockFile);
      }
    }
  }

  return { assertHost, preflightSigning, verifySignature, verifyJournaledFile, signFile, resolveTools };
}

const production = createSigningApi();
module.exports = { ...production, createSigningApi, MICROSOFT_SUBJECT, ordinaryPath, inside, hashFile, peHeader,
  originalContent, verifyOriginalContent };
