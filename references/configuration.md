# Configuration and Commands

## Locations and Inputs

The skill is a portable Git repository containing `SKILL.md`, scripts and references. It needs Node.js 22+, Git, GitHub CLI (`gh`) already authenticated, and Bun 1.3.14 matching the workflow. The Mac route additionally needs Xcode Command Line Tools, a valid Developer ID Application identity with its private key, and an existing notarytool keychain profile. Dependencies such as `js-yaml`, `yauzl`, `plist`, `app-builder-lib`, and `@electron/osx-sign` are resolved from the selected Studio checkout after a frozen install, not from old absolute paths.

Create a fresh release directory outside the skill. Examples below use `<skill>` for the installed skill directory and `<release>` for a new release workspace. Replace these with actual paths, including quotes around paths containing spaces. Do not save real per-release configs or build outputs inside the skill repository.

```sh
node <skill>/scripts/release.cjs init \
  --studio-commit FULL_STUDIO_SHA \
  --engine-commit FULL_ENGINE_SHA \
  --directory <release> --execute
```

Add `--version 0.2.27` only when that is the actual chosen version, not because it appears in an example. `init` uses read-only GitHub calls and writes `release.config.json` only with `--execute`. It does not build or dispatch. Without a supplied version, inspect the proposed version before continuing. Author the two notes files next; `init` intentionally does not invent release content.

Config shape (commit tokens must be replaced with actual 40-character lowercase hashes):

```json
{
  "schemaVersion": 1,
  "attempt": 1,
  "version": "0.2.27",
  "studioRepository": "wbz0429/dfcode-studio",
  "studioCommit": "FULL_STUDIO_SHA",
  "engineRepository": "wbz0429/xingyuanshusuan-dfcode",
  "engineCommit": "FULL_ENGINE_SHA",
  "engineVersion": "RESOLVED_ENGINE_VERSION",
  "buildRepository": "lemon7Cy/dfcode-studio",
  "workspace": "studio-workspace",
  "outputDir": "output",
  "releaseNotesFile": "release-notes.md",
  "otaNotesFile": "ota-notes.md",
  "channel": "latest",
  "updateBaseUrl": "https://www.xingyuanshusuan.com/ota/latest",
  "mac": {
    "teamId": "XN5ZRPT7L5",
    "identity": "",
    "notaryProfile": "DFCodeNotary"
  }
}
```

Relative paths resolve against the config file. An empty identity selects a unique matching Developer ID identity on this Mac. Multiple matches require an explicit SHA-1 fingerprint; a fingerprint and Team ID are public identifiers, never substitutes for exporting private keys. The notary profile is a local keychain reference, not a secret embedded in the file. No credential fields are accepted.

## Build and Collect

```sh
node <skill>/scripts/release.cjs plan --config <release>/release.config.json
node <skill>/scripts/release.cjs prepare --config <release>/release.config.json --execute
node <skill>/scripts/release.cjs dispatch --config <release>/release.config.json --execute
node <skill>/scripts/release.cjs wait --config <release>/release.config.json
node <skill>/scripts/release.cjs collect --config <release>/release.config.json --execute
node <skill>/scripts/windows-release.cjs --config <release>/release.config.json --execute
```

`prepare` requires a new checkout, not an existing dirty worktree. It installs frozen dependencies but does not start an application. The workflow is rendered to a dedicated branch with both application checkouts pinned. The build repository must already expose an active `desktop-installers.yml` workflow in its default branch so GitHub can dispatch that file on the new branch. If bootstrapping a new repository is necessary, obtain authorization for that change rather than modifying its default branch as a hidden workaround.

The build repository's `DFCODE_ENGINE_READ_TOKEN` must have read access to both selected private source repositories. GitHub's ordinary job token cannot normally read unrelated private repositories. Check the secret's presence by name, never print its value. Do not reuse a broad personal token or change repository permissions without authorization.

Required CI output includes per-platform `BUILD-INFO`, full unsigned OTA ZIPs, original metadata and complete Windows signing input. `collect` validates both platforms before writing `reports/verify-ci.json`; the Mac driver refuses unverified or altered input.

## Native Signing and Upstream Handoff

```sh
node <skill>/scripts/release.cjs sign --config <release>/release.config.json --execute
# After interruption, inspect state first; Mac notarization supports resume:
node <skill>/scripts/release.cjs sign --config <release>/release.config.json --execute --resume
node <skill>/scripts/release.cjs publish --config <release>/release.config.json --execute
```

The native driver is selected from `process.platform` and `process.arch`. Mac arm64 is implemented; Windows x64 deliberately writes a handoff until its native signer is completed. Other platforms do not attempt cross-platform signing. Mac's native output lives in `outputDir/delivery/mac`; publication verifies its report, then creates explicitly signed-named DMG/Full OTA aliases in the delivery root. Use `publish --execute --unsigned-only` for a build-only/Windows handoff or before native signing. Default publication on Mac requires the final signed report, so it cannot silently omit native deliverables.

Publishing defaults to a draft GitHub Release, not Admin. `--publish-release` is separate and may trigger upstream tag workflows, so inspect them and use it only when the user requested publication.

An existing Release with another source or conflicting asset bytes causes a stop. A fresh version is safer than silently clobbering a published build. The skill does not overwrite main, move tags, change billing, delete Actions artifacts or publish production OTA.

## Installing on Windows

Clone the private skill repository with your authenticated GitHub account into the Windows Codex skills directory, then start/reload the relevant Codex session:

```powershell
gh repo clone lemon7Cy/dfcode-release-skill "$HOME\.codex\skills\dfcode-release"
```

On hosts whose Codex configuration uses a different skills directory, use that configured path. Keep only one discoverable copy. Windows may enrich the same repository's native driver and tests; do not create a separate divergent skill. Build configurations, output files and credentials stay outside the repository.
