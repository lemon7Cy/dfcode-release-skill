# Local macOS Signing

## Entrypoints

Use `release.cjs sign --config CONFIG --execute` after collect; it selects Mac only on macOS arm64. For detailed preflight and recovery, call the driver directly:

```sh
node <skill>/scripts/mac-release.cjs --config CONFIG
node <skill>/scripts/mac-release.cjs --config CONFIG --execute
node <skill>/scripts/mac-release.cjs --config CONFIG --execute --resume
```

The first command is read-only. It verifies local CI evidence, hashes, workspace identity, signing identity selection and tool availability. It does not submit, mount, write or open an application. All path/version/repository/pin values come from configuration. Resolve a single valid Developer ID Application certificate for `mac.teamId`; if ambiguous, set its public SHA-1 fingerprint in `mac.identity`.

## Executed Chain

1. Bind `reports/verify-ci.json` to the downloaded unsigned Full OTA ZIP under `unsigned-ci`. Verify its source pins and member hashes, then expand it only under `.work.noindex/mac`.
2. Validate App version/ID/architecture, Electron version against frozen dependencies, builtin skills tree, complete CI ad-hoc signatures and embedded update URL/channel. Engine manifest normalization is allowed only with the explicit verified CI binding and is recorded separately.
3. Sign Engine with hardened runtime and JIT entitlements, update its manifest hash, and sign the App/Helpers/frameworks. Use the proven single-function ignore workaround and empty library entitlements. Verify all nested signatures and that the Engine hash remains unchanged. Probe only Engine `--version` with isolated configuration; do not start App/Engine serve.
4. Create a notarization ZIP, persist submission intent and the returned Apple ID. Wait for `Accepted`, then staple/validate the App. A pending result returns a clear resumable status; do not start a second submission. Resume at sensible intervals, stopping for rejection, authentication failure or an unexplained persistent service error.
5. Create a DMG containing the stapled App plus an exact `/Applications` symlink, then sign, notarize and staple the DMG. Recreate the App ZIP after its ticket is attached.
6. Compare source/App ZIP/DMG contents via no-follow file-tree hashes, using only a private read-only DMG mount with `-nobrowse -noautoopen`. Unmount before cleanup, including error paths. Check signature and staple independently from Gatekeeper policy.
7. Generate blockmap, feed hashes/sizes and Admin schema-v3 manifest from final bytes, create the complete Full OTA ZIP, and verify their consistency. Nothing is sent to production Admin.
8. Final files live under `delivery/mac`; `reports/mac-final.json` binds their paths/hashes and accepted notarization IDs. Publication uses that report to place clearly named signed DMG/Full OTA aliases in the delivery root. Only this run's generated temporary expanded apps are unregistered/Trashed after open-file checks.

## Resume and Boundaries

State is at `reports/mac-state.json`. Existing state requires `--resume`; accepted IDs are reused, and changed input bytes/config are rejected. The process lock prevents concurrent local signing. If the process died after upload intent but before receiving an ID, inspect Apple history and match that exact archive first. The explicit recovery flags are:

```sh
node <skill>/scripts/mac-release.cjs --config CONFIG --execute --resume --recover-app-id APPLE_SUBMISSION_ID
node <skill>/scripts/mac-release.cjs --config CONFIG --execute --resume --recover-dmg-id APPLE_SUBMISSION_ID
```

Never choose an unrelated ID merely to unblock state. A failed signing attempt is preserved and replaced with a fresh extraction of the verified source before signing again. An interrupted final delivery must not be treated as successful; preserve partial output separately and resume only after inspecting its state.

No default runtime/UI or mock-updater tests are run. Past testing unexpectedly exposed a fake `0.2.1` update prompt to the user; do not recreate that experience. Signature, notarization and file validation are not proof of an old-client OTA upgrade. The final report must state runtime/live OTA untested unless separately authorized and actually performed.

If Gatekeeper is disabled or reports an override, keep that state unchanged and report limited local policy evidence. Do not weaken security, import another identity or expose `.p8`/passwords as a workaround. Credentials stay in the user's keychain, outside this skill and GitHub CI.
