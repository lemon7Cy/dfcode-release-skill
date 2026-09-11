# Windows Signing and Handoff

## Commands and Scope

The Windows x64 driver implements local KeyLocker signing, NSIS repackaging and signed Full OTA delivery. It also retains a handoff mode usable on Mac. Choose the command deliberately:

```sh
# Read-only handoff plan on either host:
node <skill>/scripts/windows-release.cjs --config <release>/release.config.json
# Write only the version-specific handoff document on either host:
node <skill>/scripts/windows-release.cjs --config <release>/release.config.json --execute
# Native Windows x64 signing and delivery:
node <skill>/scripts/windows-release.cjs --config <release>/release.config.json --sign --execute
# Resume the same config, notes and inputs after inspecting preserved state:
node <skill>/scripts/windows-release.cjs --config <release>/release.config.json --sign --execute --resume
```

The shared `release.cjs sign --execute [--resume]` command selects the native driver and adds `--sign` on Windows. `--sign` without `--execute` only prints its plan. Defaults never sign, repackage or mutate release files. The handoff document lives at `outputDir/delivery/Windows-<version>-signing-handoff.md`; its existence proves no signing or acceptance result.

Real signing requires Windows x64, Node.js 22+, the CI Node major and Bun version, a clean pinned Studio checkout with frozen dependencies, Windows SDK x64 SignTool, PowerShell 7 x64 and DigiCert Signing Manager Tools. The inspected packaging API is `electron-builder`/`app-builder-lib` **26.15.3**. The driver checks tool versions and selected source packaging settings; a different builder API or unknown packaging setting requires review before support is extended. Embedded uninstaller extraction handles the inspected 26.15.3 non-solid NSIS format.

This implementation does not perform installation, application startup or a real OTA upgrade. An authorized real signing run executes the final extracted Engine only with `--version` as a package check. It does not launch the Studio UI or an Engine server. Installation scope comes from the selected source packaging configuration; no all-users installation fix was made.

## Inputs and Local Signing Configuration

- Load the shared flat config with `scripts/config.cjs`. See [configuration](configuration.md) for the optional `windows` object. Actual signing requires `publisherName`, `certificateSha1` and `keypairAlias`; optional fields select native tools, timestamp URL and preservation of approved Microsoft signatures. Windows never invokes the Mac signer or its credential profile.
- Expect `outputDir/unsigned-ci/DFCode-<version>-win32-x64-signing-input-unsigned.zip` and `.zip.sha256`, plus the collection receipt at `outputDir/reports/verify-ci.json`. Preserve the complete archive, including `win-unpacked`, unsigned NSIS installer, metadata and source records. An unsigned installer alone is insufficient. Verify the receipt and external digest, all internal SHA-256 entries, source pins, complete PE inventory, Engine manifest/skills and embedded updater configuration.
- For a Mac-to-Windows handoff, transfer the verified unsigned inputs **and** `reports/verify-ci.json`. Create a fresh Windows-local config/output and a checkout at the same Studio commit with frozen dependencies. The receipt's historical absolute paths do not select local input paths. This supports local signing/delivery; copying Mac `state/ci.json` and rewriting paths is not a supported way to resume CI or publish from Windows.
- For a same-machine CI-to-publication run, configure the public `windows` fields before `prepare`. Keep config and both notes files frozen during prepare/dispatch/collect. Local signing uses the independent current `otaNotesFile`, not embedded CI notes; the OTA summary must have 1–4000 characters, no prohibited control characters and no stale unsigned-handoff notice. Signing state binds the full config and hashes of both notes files. Changed signing notes require fresh config/output and new evidence; do not reuse old signing state or attempt to evade existing CI fingerprints.
- The signer uses SMCTL **`sign --simple`**, with SHA-256 and a trusted timestamp. KSP is not mandatory for this route. The established local KeyLocker credentials remain local; JSON config contains only public identifiers and tool settings. Never place API keys, client-certificate passwords or private-key material in this skill, config, archives, chat or logs. Do not share complete SMCTL/healthcheck output.
- The account must be a designated signer for the chosen certificate. Local preflight checks tool availability and the exact public certificate, publisher and validity; it does not prove remote signing permission. Use the exact publisher compatible with the installed updater. A valid new signature does not guarantee immediate SmartScreen reputation.

## Native Pipeline and Evidence

1. Verify the immutable input archive and extract it under `outputDir/.work.noindex/windows/input`. Stage a separate `signing/signed-payload` copy. Check PE AMD64 architecture, version/source records, skills tree, Engine hash and update URL/channel. Preserve original unsigned input and inventory for comparison.
2. Sign Engine first, then inventory/sign/verify every inner EXE, DLL and native `.node` PE with the configured certificate and timestamp. Preserve approved valid Microsoft signatures for `d3dcompiler_47.dll` and `dxil.dll` when enabled. Unexpected, invalid or unapproved existing signatures stop the operation.
3. Use journaled detached copies for paid signing operations. Verify that changes are confined to Authenticode signature data and PE checksum before replacing an owned staging file. After inner signing, refresh `resources/engine/manifest.json` `binarySha256` and signing fields and set the updater's exact `publisherName`; preserve source/version/skills and other updater fields.
4. Rebuild NSIS from the signed payload with the skill's explicit signing hook for the generated uninstaller and final installer. Preserve supported source NSIS installation settings. `--prepackaged` alone does not sign inner files; the source `dist:win` rebuild command is not the sign-only route.
5. Extract the final NSIS payload and embedded uninstaller. Compare the payload byte-for-byte with the signed copy, and compare unsigned-to-signed content allowing only verified signatures and the documented manifest/updater changes. Verify the expected publisher, certificate, trust, SHA-256 signature and timestamp using `Get-AuthenticodeSignature` and `signtool verify /pa /all /v /tw`. Check final Engine `--version` and recheck its manifest hash.
6. Regenerate EXE blockmap and feed SHA-512/size from final signed bytes, then schema-v3 `release.json` and the signed Full OTA ZIP using independent notes. The Admin helper rewrites feed paths and release hashes; it cannot repair a stale blockmap or feed SHA-512. Verify ZIP root entries, hashes, publisher and final installer bytes before completing delivery.

Stages are `input-verified`, `inner-pe-signed`, `manifest-refreshed`, `nsis-signed`, `final-payload-verified`, `metadata-verified`, then `finalized`. A failure cannot produce a final signed delivery report. Staging, journal and failure evidence remain available; Windows cleanup does not automatically delete them.

## Delivery and Acceptance

Native artifacts live in `outputDir/delivery/windows`:

- `DFCode-<version>-x64.exe` and its checksum.
- `DFCode-<version>-win32-x64-full-ota-signed.zip` and its checksum; ZIP root contains `release.json`, channel feed, final EXE and blockmap.
- Final feed/blockmap/manifest, `SHA256SUMS.txt` and `WINDOWS-VERIFICATION.json`.

The authoritative report is `outputDir/reports/windows-final.json`, with source/input/config binding, current delivery hashes, signing identity, stage results and explicit acceptance flags. `status: finalized` means signing and static package delivery validation completed. It does **not** mean clean installation, application startup, installed-uninstaller testing, actual OTA or user-data retention passed; those flags remain false. The Engine `--version` check is reported separately.

For a run with matching local CI state, `release.cjs publish --execute` verifies the report, current config/notes, source, publisher, certificate and file/ZIP hashes before preparing GitHub assets. It uses the signed installer alias `DFCode-<version>-x64-signed.exe` in the delivery root; the Full OTA ZIP retains its native filename. GitHub publishing defaults to a draft and requires the user's requested scope. Signing does not authorize Admin upload or production publication.

Before declaring Windows runtime/OTA acceptance, coordinate an authorized clean installation, pinned Studio/Engine startup, basic operation, exit and uninstall, then a real old-to-new OTA upgrade with relaunch and user-data retention. Verify the installed uninstaller separately. The initiating old client controls silent installation flags; an upgrade into the new version does not prove that new client's next-upgrade behavior. Record these results independently of unit tests and signing evidence.

## Recovery and Installation of the Skill

Read [recovery](recovery.md) before resuming. `--resume` requires unchanged config, notes and input and rechecks retained evidence; unresolved provider responses or incomplete NSIS hook outcomes must not cause automatic signing retries. Preserve the pending journal and detached files for inspection. A changed output directory is not permission to repeat an unresolved paid operation.

Install from the trusted private distribution into the configured Windows Codex skills directory; keep one discoverable copy and merge existing local work before replacement. Do not copy Mac release configs or credentials. For a new installation from an already obtained trusted folder:

```powershell
$skillSource = 'C:\DFCode\private-skills\dfcode-release'
$skillHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$skillDirectory = Join-Path $skillHome 'skills'
$skillTarget = Join-Path $skillDirectory 'dfcode-release'
if (-not (Test-Path -LiteralPath (Join-Path $skillSource 'SKILL.md'))) { throw 'Trusted skill folder missing' }
if (Test-Path -LiteralPath $skillTarget) { throw 'Existing skill: review and merge its local Windows work first' }
New-Item $skillDirectory -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath $skillSource -Destination $skillTarget -Recurse
```

Start a new Codex task and invoke `$dfcode-release`, using a release config with Windows-local paths. Historical replay and implementation limits are recorded in [validation](validation.md); historical 0.2.26 evidence does not validate a future release.