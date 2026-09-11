'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const signing = require('./windows-sign.cjs');

function createHook(api = signing, environment = process.env) {
  return async function windowsSignHook(configuration) {
    api.assertHost();
    if (configuration?.hash !== 'sha256') throw new Error('Windows builder hook requires SHA256 signing');
    const configFile = signing.ordinaryPath(environment.DFCODE_WINDOWS_SIGN_CONFIG);
    let settings;
    try { settings = JSON.parse(fs.readFileSync(configFile, 'utf8')); }
    catch { throw new Error('Generated public Windows signing configuration is invalid'); }
    const allowed = new Set(['schemaVersion', 'windows', 'ownedRoot', 'journalFile', 'uninstallerPath']);
    if (Object.keys(settings).some(name => !allowed.has(name)) || settings.schemaVersion !== 1) {
      throw new Error('Generated signing configuration must contain only public routing fields');
    }
    const root = signing.ordinaryPath(settings.ownedRoot, { directory: true });
    if (!signing.inside(root, configFile)) throw new Error('Generated signing config must stay in the owned staging root');
    const journalFile = signing.ordinaryPath(settings.journalFile, { allowMissing: true });
    const uninstallerPath = signing.ordinaryPath(settings.uninstallerPath, { allowMissing: true });
    if (!signing.inside(root, journalFile) || !signing.inside(root, uninstallerPath)) {
      throw new Error('Builder signing journal and uninstaller audit must stay inside owned staging');
    }
    const journal = fs.existsSync(journalFile) ? JSON.parse(fs.readFileSync(journalFile, 'utf8')) : { schemaVersion: 1, entries: {} };
    const save = value => {
      fs.mkdirSync(path.dirname(journalFile), { recursive: true });
      signing.ordinaryPath(path.dirname(journalFile), { directory: true });
      const temp = `${journalFile}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`;
      const fd = fs.openSync(temp, 'wx', 0o600);
      try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + '\n'); fs.fsyncSync(fd); }
      finally { fs.closeSync(fd); }
      signing.ordinaryPath(journalFile, { allowMissing: true });
      fs.renameSync(temp, journalFile);
    };
    const result = api.signFile(configuration.path, { windows: settings.windows }, { journal, save, ownedRoot: root });
    if (/__uninstaller\.exe$/i.test(configuration.path)) {
      fs.mkdirSync(path.dirname(uninstallerPath), { recursive: true });
      signing.ordinaryPath(path.dirname(uninstallerPath), { directory: true });
      if (fs.existsSync(uninstallerPath)) {
        if (signing.hashFile(uninstallerPath) !== result.sha256) throw new Error('Saved signed uninstaller differs; refusing to overwrite');
      } else fs.copyFileSync(configuration.path, uninstallerPath, fs.constants.COPYFILE_EXCL);
      if (signing.hashFile(uninstallerPath) !== result.sha256) throw new Error('Signed uninstaller audit copy verification failed');
    }
    return result;
  };
}

const hook = createHook();
module.exports = hook;
module.exports.default = hook;
module.exports.createHook = createHook;
