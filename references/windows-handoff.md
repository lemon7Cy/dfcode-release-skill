# Windows Signing Handoff

## Scope And Current Status

Windows is intentionally a handoff-only extension point. The Mac implementation does not supply Windows signing support. `scripts/windows-release.cjs` is executable on either host but only prints a plan by default; `--execute` creates an ASCII-named, version-specific Markdown handoff in `outputDir/delivery`. `--sign` returns nonzero before config loading or side effects. Neither success from plan generation nor the existence of this skill proves signing, packaging, installation, or OTA acceptance.

Historical evidence: the 0.2.26 Windows CI signing-input archive was checked locally on macOS without executing PE files. Its 122 internal SHA-256 entries and 12 PE inventory records matched, the Engine hash matched its manifest, source pins matched, and the embedded updater URL/channel were correct. This is evidence for that input archive only. A reusable local Windows KeyLocker sign-and-repackage implementation and Windows acceptance remain to be completed on the user's Windows x64 machine.

## Inputs And Invariants

- Load the shared flat config using `scripts/config.cjs` `loadConfig(configPath)`. Its shared fields are `version`, `studioRepository`, `studioCommit`, `engineRepository`, `engineCommit`, `engineVersion`, `buildRepository`, `channel`, `updateBaseUrl`, `workspace`, `outputDir`, `releaseNotesFile`, `otaNotesFile`, and `mac`. Windows must not invoke the Mac code path or use the `mac` credential profile.
- Expect `outputDir/unsigned-ci/DFCode-<version>-win32-x64-signing-input-unsigned.zip` and its `.zip.sha256`. This archive must contain full `win-unpacked`, not only the unsigned NSIS EXE. Preserve it and verify both the external digest and all internal checksum entries, source pins, PE inventory, Engine manifest and `app-update.yml` each run.
- Use the separate current `otaNotesFile` when building the signed release. It takes precedence over the old notes inside the immutable CI ZIP. Do not silently fall back to embedded notes or put unsigned handoff warnings into the signed client announcement.
- KeyLocker membership is insufficient: the signer must be assigned to the target certificate as a designated signer. Use Windows-native SDK SignTool plus DigiCert Signing Manager Tools/KSP. Credentials, API keys, client certificates and their passwords remain in the user's established secure local setup, never this skill, JSON config, archives, chat or build logs. Do not share full healthcheck output.
- Resolve the exact intended certificate publisher, not a guessed company abbreviation; retain the installed client's publisher/update-feed compatibility. macOS notarization is unrelated to Windows signing. A valid new certificate does not itself guarantee immediate SmartScreen reputation.

## Required Windows Pipeline

1. Preserve unsigned input and stage a separate copy of `win-unpacked`. Verify the version-specific toolchain and frozen workspace dependencies, source pins, actual Engine `--version`, PE AMD64 architecture and updater configuration on Windows. Input archive verification is separate from runtime acceptance.
2. Inventory every inner PE, including the Engine, main EXE, DLLs and native `.node` modules. Sign with the authorized publisher and trusted timestamp, then verify each signature. Do not merely sign the outer installer.
3. After Engine signing, update `resources/engine/manifest.json` `binarySha256` and signing fields. Preserve source commit, version and skill-tree hash. Recheck the binary hash after packaging so a second signature cannot invalidate it.
4. Rebuild NSIS from the already signed unpacked directory, preserving the project's signing hook for the newly generated uninstaller and final installer. `--prepackaged` does not automatically sign inner files. The existing `dist:win` rebuilds the renderer and expects an Engine worktree; it is not a proven sign-only command. Do not disable the hook to get a successful build.
5. Ensure `publisherName` and the embedded update configuration match the intended distribution. Generate EXE blockmap and feed SHA-512/size from the final signed bytes; any later modification or signature requires regeneration. The Admin `prepare-admin-full-ota-release.mjs` helper rewrites feed paths and rebuilds `release.json` SHA-256/size/releaseHash, but does not repair stale feed SHA-512 or regenerate blockmap.
6. Package a separate signed Full OTA ZIP with `release.json`, feed, final EXE and blockmap at its root, using the independent notes. Keep the new PE/signing report separate from the unsigned report. Deliver ASCII filenames and SHA-256 digests; upload or production Admin publishing requires the user's current authorization.

## Install This Private Skill On Windows

Obtain the trusted private skill folder from the existing private distribution, not an arbitrary public repository. Copy the whole `dfcode-release` folder, including its scripts and references, to the Windows Codex skill directory. Do not copy Mac release config or credential files. A sample PowerShell install for a new installation:

```powershell
$source = 'C:\DFCode\private-skills\dfcode-release'
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$skills = Join-Path $codexHome 'skills'
$target = Join-Path $skills 'dfcode-release'
if (-not (Test-Path (Join-Path $source 'SKILL.md'))) { throw 'Trusted skill folder missing' }
if (Test-Path $target) { throw 'Existing skill: review and merge its local Windows work first' }
New-Item $skills -ItemType Directory -Force | Out-Null
Copy-Item $source $target -Recurse
```

Start a new Codex task on Windows and invoke `$dfcode-release`. Prepare a release config with Windows-local paths; then run `node <skill-dir>\scripts\windows-release.cjs --config <release.json>` to inspect the plan. Add `--execute` only to create the handoff document. Do not interpret it as a signing command.

## Future Extension Contract

Replace the stub only after implementing and testing a bounded Windows-native flow. Preserve the shared config and `unsigned-ci`/`delivery` locations; extend config deliberately through its shared validator rather than hiding certificate fields in `mac`. Prefer secure credential references, not secret values. Preserve a default plan-only mode and require explicit execution for signing or repackaging. Reject real Windows signing on non-Windows or non-x64 hosts before mutation.

Expose meaningful stage results: `input-verified`, `inner-pe-signed`, `manifest-refreshed`, `nsis-signed`, `metadata-verified`, and `windows-accepted`. Never return a final `signed`/`published` success after partial failure. Use separate staging and deterministic report locations; stop on signature, source, hash or publisher mismatch instead of silently retrying another certificate or mutating originals. Keep upload/production publication a separately authorized operation.

Acceptance required before declaring the Windows implementation complete:

- Automated tests cover host gating, default no-side-effect mode, wrong/missing certificate, manifest hash refresh, signing-hook failure, final-byte feed/blockmap consistency, and refusal to label unsigned output signed.
- Actual Windows verification uses `signtool verify /pa /all /tw` and `Get-AuthenticodeSignature` for inner PE, final installer and the installed uninstaller; checks the expected publisher and trusted timestamp. A mock or static review cannot substitute.
- Clean installation starts the pinned Studio/Engine, preserves expected updater configuration, performs basic work, exits normally and uninstalls successfully.
- A real old-to-new OTA run verifies download, process cleanup, replacement, relaunch and user-data retention. The initiating old client controls silent installation flags; testing an upgrade into the new version does not alone verify the new client's next-upgrade behavior.
- Reports distinguish local tests, Windows runtime verification, signing, installer acceptance, actual OTA and publication status. Credentials never appear in reports, and no statement implies that this historical 0.2.26 CI check validates a future release.
